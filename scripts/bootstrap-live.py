#!/usr/bin/env python3
"""Browser-authorized disposable infrastructure qualification; no copied secrets."""
import argparse
import hashlib
import hmac
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
PIN = '4.148.0'
SCOPES = ['account:read', 'user:read', 'workers:write', 'workers_scripts:write']

class Failure(Exception):
    pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Failure('HTTP redirect refused')


def child_environment(directory):
    # No inherited tokens, auth endpoints, debug flags, NODE_OPTIONS, or config.
    allowed = ['PATH', 'SYSTEMROOT', 'TMPDIR', 'LANG', 'LC_ALL']
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    env.update(HOME=str(directory), XDG_CONFIG_HOME=str(directory),
               WRANGLER_SEND_METRICS='false', CLOUDFLARE_AUTH_USE_KEYRING='false',
               NO_COLOR='1', TERM='dumb')
    return env


def select_account(accounts, requested=None):
    available = [a for a in accounts if isinstance(a, dict) and
                 isinstance(a.get('id'), str) and len(a['id']) == 32 and
                 all(c in '0123456789abcdef' for c in a['id'])]
    if requested:
        if requested not in [a['id'] for a in available]:
            raise Failure('Selected account is not in the authorized account list')
        return requested
    if len(available) == 1:
        return available[0]['id']
    for index, account in enumerate(available, 1):
        print(str(index)+': '+account['id'])
    if not available:
        raise Failure('No authorized Cloudflare account')
    try:
        index = int(input('Select fixture account number: '))
        if index < 1 or index > len(available): raise ValueError()
        return available[index-1]['id']
    except (ValueError, EOFError):
        raise Failure('An explicit account selection is required') from None


class Session:
    def __init__(self, directory):
        self.directory = directory
        self.env = child_environment(directory)
        (directory/'.wrangler').mkdir(mode=0o700)
        self.node = shutil.which('node')
        self.cli = ROOT/'adapter/node_modules/wrangler/bin/wrangler.js'
        package = ROOT/'adapter/node_modules/wrangler/package.json'
        if not self.node or not package.is_file() or json.loads(package.read_text())['version'] != PIN:
            raise Failure('Install the pinned adapter dependencies with npm ci first')
        self.token = None
        self.http = urllib.request.build_opener(NoRedirect())

    def wrangler(self, args, interactive=False):
        command = [self.node, str(self.cli), *args]
        if interactive:
            result = subprocess.run(command, cwd=self.directory, env=self.env, timeout=300)
        else:
            result = subprocess.run(command, cwd=self.directory, env=self.env,
                                    capture_output=True, text=True, timeout=240)
        if result.returncode:
            raise Failure('Wrangler operation failed; child output withheld')
        return None if interactive else result.stdout

    def authorize(self):
        self.wrangler(['login', '--scopes', *SCOPES], interactive=True)
        auth = json.loads(self.wrangler(['auth', 'token', '--json']))
        if auth.get('type') != 'oauth' or not auth.get('token'):
            raise Failure('Browser OAuth authorization required')
        self.token = auth['token']

    def api(self, method, path, body=None, absent_ok=False):
        request = urllib.request.Request('https://api.cloudflare.com/client/v4/'+path,
            method=method, data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization':'Bearer '+self.token, 'Content-Type':'application/json'})
        try:
            with self.http.open(request, timeout=60) as response:
                result = json.load(response)
        except urllib.error.HTTPError as error:
            if absent_ok and error.code == 404: return None
            raise Failure('Cloudflare request failed (HTTP '+str(error.code)+'); response withheld') from None
        if result.get('success') is not True:
            raise Failure('Cloudflare request unsuccessful; response withheld')
        return result.get('result')

    def close(self):
        # Pinned Wrangler logout does not check the revocation HTTP status.
        # Revoke both token classes ourselves and require a successful response.
        stored = self.directory/'.wrangler/config/default.toml'
        refresh = None
        if stored.is_file():
            raw=stored.read_text()
            match=re.search(r"^refresh_token\s*=\s*(['\"])([^'\"\n]+)\1\s*$",raw,re.MULTILINE)
            if match: refresh=match.group(2)
        if self.token and not refresh:
            raise Failure('OAuth refresh-token revocation cannot be confirmed')
        # Revoke refresh first so an access-token rejection cannot leave a reusable
        # refresh credential active. Both responses must pass before deleting state.
        for hint, token in [('refresh_token', refresh), ('access_token', self.token)]:
            if not token: continue
            body=urllib.parse.urlencode({'client_id':'54d11594-84e4-41aa-b438-e81b8fa78ee7',
                'token_type_hint':hint,'token':token})
            code="""let body='';for await(const chunk of process.stdin)body+=chunk;
try {const r=await fetch('https://dash.cloudflare.com/oauth2/revoke',{
method:'POST',redirect:'error',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
process.stdout.write(String(r.status));}catch{process.exitCode=1;}"""
            result=subprocess.run([self.node,'--input-type=module','-e',code],input=body,
                capture_output=True,text=True,env=self.env,cwd=self.directory,timeout=60)
            if result.returncode or result.stdout.strip()!='200':
                status=result.stdout.strip()
                raise Failure(hint+' revocation failed'+(' (HTTP '+status+')' if status.isdigit() else '; transport failed'))
        self.token = None
        if stored.exists(): stored.unlink()


def write_receipt(path, receipt):
    # Parent must exist; exclusive initial creation is performed before OAuth.
    with path.open('w') as stream:
        json.dump(receipt, stream, indent=2)
        stream.write('\n')

def wait_for_ingress(ingress, receipt, save, pause=time.sleep):
    # An invalid signature must be rejected before any durable/object writes.
    # Retry only route-not-found during deployment propagation, never a signed write.
    for attempt in range(1, 13):
        receipt['ingressReadinessAttempts'] = attempt; save()
        try: ingress('0'*64)
        except urllib.error.HTTPError as error:
            if error.code == 401: return
            if error.code != 404: raise Failure('Ingress readiness failed (HTTP '+str(error.code)+')') from None
        else: raise Failure('Invalid signature accepted during readiness')
        if attempt < 12: pause(2)
    raise Failure('Ingress route unavailable after bounded deployment propagation check')



def first_receipt(ingress, signature, receipt, save, pause=time.sleep):
    # Retry only the explicit pre-handler DO routing failure. All storage and
    # ambiguous delivery errors remain failures and are not automatically retried.
    for attempt in range(1, 13):
        receipt['durableObjectReadinessAttempts'] = attempt; save()
        try: return ingress(signature)
        except urllib.error.HTTPError as error:
            if error.code != 503 or error.headers.get('x-fixture-readiness') != 'durable-object-route':
                raise
        if attempt < 12: pause(2)
    raise Failure('Durable Object route unavailable after bounded deployment propagation check')


def qualify(session, account, binary, receipt, save):
    bucket = worker = 'fk-fixture-'+uuid.uuid4().hex[:16]
    receipt.update(accountID=account, bucket=bucket, worker=worker,
                   verification={'nativeS3': {'status':'blocked',
                       'reason':'Wrangler OAuth has no token-management scope; no S3 credentials minted'},
                       'archive':'not-performed'})
    save()
    base = 'accounts/'+account+'/'
    # Preflight proves we do not knowingly replace a preexisting resource.
    if session.api('GET', base+'r2/buckets/'+bucket, absent_ok=True) is not None:
        raise Failure('Fixture bucket already exists')
    if session.api('GET', base+'workers/scripts/'+worker+'/settings', absent_ok=True) is not None:
        raise Failure('Fixture Worker already exists')
    config = session.directory/'config.json'
    profile = {'accountID':account,'bucket':bucket,
        'group':{'project':'disposable-fixture','environment':'test','purpose':'controller-receipts','contentType':'binary'},
        'managementCredential':{'provider':'environment','reference':'FK_BOOTSTRAP_OAUTH'},
        'workerCredential':{'provider':'environment','reference':'FK_BOOTSTRAP_OAUTH'},
        'allowedWorkerBucketNames':[bucket], 'allowedWorkerSecretReferences':['FK_WEBHOOK_SECRET'],
        'allowedOperations':['storage.bucket.create','storage.retention.inspect','storage.retention.apply','worker.plan','worker.apply']}
    config.write_text(json.dumps({'schemaVersion':1,'profiles':{'fixture':profile},'vaults':[]}))
    env = session.env.copy()
    env.update(FK_BOOTSTRAP_OAUTH=session.token, FK_WEBHOOK_SECRET=secrets.token_hex(32),
               FK_NODE=session.node, FK_WORKER_ADAPTER=str(ROOT/'adapter/worker.mjs'))
    session.env['CLOUDFLARE_ACCOUNT_ID'] = account
    def run(operation, parameters):
        request = session.directory/'request.json'
        request.write_text(json.dumps({'schemaVersion':1,'requestID':uuid.uuid4().hex,
                                      'profile':'fixture','operation':operation,'parameters':parameters}))
        result = subprocess.run([str(binary),'run','--request',str(request),'--config',str(config)],
            env=env, capture_output=True, text=True, timeout=240)
        if result.returncode:
            detail={'operation':operation,'exitCode':result.returncode}
            try:
                error=json.loads(result.stdout).get('error',{})
                for key in ['code','stage']:
                    value=error.get(key)
                    if isinstance(value,str) and re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',value): detail[key]=value
                if isinstance(error.get('httpStatus'),int): detail['httpStatus']=error['httpStatus']
            except (ValueError,AttributeError): pass
            receipt['nativeFailure']=detail; save()
            raise Failure('Native operation failed: '+operation+'; raw child output withheld')
        parsed = json.loads(result.stdout)
        if parsed['status'] != 'succeeded': raise Failure('Native operation unsuccessful: '+operation)
        return parsed['output']
    bucket_attempted = worker_attempted = False
    try:
        bucket_attempted = True
        receipt['phase'] = 'bucket-create-attempted'; save()
        run('storage.bucket.create', {'bucket':bucket,'approveCreate':True})
        baseline = run('storage.retention.inspect', {'bucket':bucket})
        run('storage.retention.apply', {'bucket':bucket,'expectedDigest':baseline['digest'],
            'rules':{'rules':[{'id':'fixture-lock','enabled':True,'prefix':'fixture/',
                             'condition':{'type':'Indefinite'}}]},'acknowledgeAdministratorRemoval':True})
        payload = b'disposable fixture content'
        source = session.directory/'payload'; source.write_bytes(payload)
        session.wrangler(['r2','object','put',bucket+'/fixture/payload','--file',str(source),'--remote'])
        restored = session.directory/'restored'
        session.wrangler(['r2','object','get',bucket+'/fixture/payload','--file',str(restored),'--remote'])
        if restored.read_bytes() != payload: raise Failure('R2 full-content comparison failed')
        params = {'sourceDirectory':str(ROOT/'fixtures/worker'),'mode':'deploy',
            'configuration':{'name':worker,'main':'index.mjs','compatibility_date':'2026-10-04','workers_dev':True,
            'durable_objects':{'bindings':[{'name':'COORDINATOR','class_name':'FixtureCoordinator'}]},
            'migrations':[{'tag':'v1','new_sqlite_classes':['FixtureCoordinator']}],
            'r2_buckets':[{'binding':'RECEIPTS','bucket_name':bucket}]},
            'secretReferences':{'WEBHOOK_SECRET':{'provider':'environment','reference':'FK_WEBHOOK_SECRET'}}}
        plan = run('worker.plan', params)
        params.update(approvedPlan=plan['plan'], approvedPlanDigest=plan['planDigest'])
        worker_attempted = True
        receipt['phase'] = 'worker-apply-attempted'; save()
        run('worker.apply', params)
        receipt['phase']='worker-applied'; save()
        subdomain = session.api('GET',base+'workers/subdomain')['subdomain']
        endpoint = 'https://'+worker+'.'+subdomain+'.workers.dev/fixture'
        body = b'disposable live request'
        digest = hashlib.sha256(body).hexdigest()
        signature = hmac.new(env['FK_WEBHOOK_SECRET'].encode(),body,hashlib.sha256).hexdigest()
        def ingress(signature):
            # Keep request credentials out of argv and use the proven Node transport.
            code="""let raw='';for await(const c of process.stdin)raw+=c;
const input=JSON.parse(raw);
try {const r=await fetch(input.endpoint,{method:'POST',redirect:'error',
headers:{'x-fixture-signature':input.signature},body:input.body,
signal:AbortSignal.timeout(60000)});
const text=await r.text();if(text.length>65536)throw Error('limit');
process.stdout.write(JSON.stringify({status:r.status,readiness:r.headers.get('x-fixture-readiness'),body:r.status===200?JSON.parse(text):null}));
}catch{process.exitCode=1;}"""
            result=subprocess.run([session.node,'--input-type=module','-e',code],
                input=json.dumps({'endpoint':endpoint,'signature':signature,'body':body.decode('ascii')}),
                env=session.env,cwd=session.directory,capture_output=True,text=True,timeout=65)
            if result.returncode: raise Failure('Live ingress transport failed; response withheld')
            response=json.loads(result.stdout)
            if response['status']!=200:
                raise urllib.error.HTTPError(endpoint,response['status'],'Ingress rejected',{'x-fixture-readiness':response.get('readiness')},None)
            return response['body']
        receipt['phase']='live-ingress'; save()
        wait_for_ingress(ingress,receipt,save)
        first = first_receipt(ingress,signature,receipt,save)
        repeat = ingress(signature)
        if first['state'] != 'created' or first['digest'] != digest or repeat['state'] != 'existing' or repeat['digest'] != digest or first['promotion'] != 'disabled':
            raise Failure('Ingress verification failed')
        try: ingress('0'*64)
        except urllib.error.HTTPError as error:
            if error.code != 401: raise Failure('Invalid signature check failed') from None
        else: raise Failure('Invalid signature accepted')
        session.wrangler(['r2','object','get',bucket+'/fixture/'+digest,'--file',str(restored),'--remote'])
        if restored.read_bytes() != body: raise Failure('Receipt content comparison failed')
        receipt['verification'].update(oauthR2='full-content-comparison',
            nativeBucketRetention='create-and-lock-readback',nativeWorker='plan-apply-and-live-ingress',
            duplicateDelivery='existing-object',invalidSignature='rejected-401')
        receipt['phase'] = 'verified'; save()
    finally:
        cleanup(session,account,receipt,save,bucket_attempted,worker_attempted)


def cleanup(session,account,receipt,save,bucket_attempted=True,worker_attempted=True):
    bucket,worker=receipt.get('bucket'),receipt.get('worker')
    if (not isinstance(bucket,str) or bucket!=worker or not bucket.startswith('fk-fixture-') or
        len(bucket)!=27 or any(c not in '0123456789abcdef' for c in bucket[11:])):
        raise Failure('Cleanup requires matching generated fixture names')
    base='accounts/'+account+'/'
    session.env['CLOUDFLARE_ACCOUNT_ID']=account
    errors=[]
    # Attempt cleanup even after a lost mutation response. Names were absent at preflight.
    if worker_attempted:
        try: session.api('DELETE',base+'workers/scripts/'+worker+'?force=true',absent_ok=True)
        except Exception: errors.append('Worker '+worker)
    if bucket_attempted:
        try:
            if session.api('GET',base+'r2/buckets/'+bucket,absent_ok=True) is not None:
                session.api('PUT',base+'r2/buckets/'+bucket+'/lock',{'rules':[]})
                for key in ['fixture/payload','fixture/'+hashlib.sha256(b'disposable live request').hexdigest()]:
                    session.wrangler(['r2','object','delete',bucket+'/'+key,'--remote'])
                session.api('DELETE',base+'r2/buckets/'+bucket)
        except Exception: errors.append('R2 bucket '+bucket)
    receipt['cleanup'] = {'status':'incomplete' if errors else 'worker-and-bucket-removed',
                          'resources':errors,'durableObjectNamespaces':'not-independently-verified'}
    save()
    if errors: raise Failure('Cleanup incomplete; see receipt resource names')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cleanup',type=Path,help='Retry exact fixture removal using an existing receipt')
    parser.add_argument('--account', help='Nonsecret account ID; otherwise select authorized account')
    parser.add_argument('--binary', type=Path, default=ROOT/'.build/debug/fk')
    parser.add_argument('--receipt', type=Path, default=Path('bootstrap-live.receipt.json'))
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not args.cleanup and (not binary.is_file() or not os.access(binary,os.X_OK)): parser.error('Build fk first')
    output=(args.cleanup or args.receipt).resolve()
    if args.cleanup:
        receipt=json.loads(output.read_text())
        account=receipt.get('accountID')
        if (receipt.get('schemaVersion')!=1 or receipt.get('authorization')!='isolated-browser-oauth' or
            not isinstance(account,str) or len(account)!=32 or any(c not in '0123456789abcdef' for c in account)):
            parser.error('Not a bootstrap receipt')
    else:
        fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        os.close(fd)
        receipt={'schemaVersion':1,'status':'running','authorization':'isolated-browser-oauth'}
    save=lambda:write_receipt(output,receipt)
    save()
    old_umask = os.umask(0o077)
    session = None
    try:
        with tempfile.TemporaryDirectory(prefix='fk-bootstrap-') as temp:
            session = Session(Path(temp))
            try:
                session.authorize()
                accounts=[]
                page=1
                while True:
                    batch=session.api('GET','accounts?per_page=50&page='+str(page))
                    accounts.extend(batch)
                    if len(batch)<50: break
                    page+=1
                    if page>100: raise Failure('Authorized account list exceeds limit')
                account=select_account(accounts,receipt.get('accountID') if args.cleanup else args.account)
                if args.cleanup:
                    cleanup(session,account,receipt,save)
                    receipt['status']='cleanup-completed'
                else:
                    qualify(session,account,binary,receipt,save)
                    receipt['status']='passed-with-limits'
            except BaseException as error:
                receipt['failure']=str(error) if isinstance(error,Failure) else ('HTTP '+str(error.code)+' at '+receipt.get('phase','authorization') if isinstance(error,urllib.error.HTTPError) else type(error).__name__+' at '+receipt.get('phase','authorization')+'; external details withheld')
                receipt['status']='interrupted' if isinstance(error,KeyboardInterrupt) else 'failed'
                raise
            finally:
                try:
                    session.close()
                    receipt['authorizationCleanup'] = 'access-and-refresh-revocation-http-200-and-local-state-removed'
                    receipt['accessTokenInvalidation']='not-independently-verified'
                except Exception as error:
                    receipt['authorizationCleanup']='revocation-unconfirmed'
                    receipt['authorizationFailure']={'category':type(error).__name__}
                    if isinstance(error,urllib.error.HTTPError): receipt['authorizationFailure']['httpStatus']=error.code
                    if isinstance(error,Failure): receipt['authorizationFailure']['reason']=str(error)
                    if 'failure' not in receipt:
                        raise Failure('OAuth revocation failed; see authorizationFailure') from None
    except KeyboardInterrupt:
        receipt['status'] = 'interrupted'
    except Exception as error:
        receipt['status'] = 'failed'
        receipt['failure'] = str(error) if isinstance(error,Failure) else ('HTTP '+str(error.code)+' at '+receipt.get('phase','authorization') if isinstance(error,urllib.error.HTTPError) else type(error).__name__+' at '+receipt.get('phase','authorization')+'; external details withheld')
        # Exception strings, server payloads and child output never enter receipts.
    finally:
        os.umask(old_umask)
        save()
    print(json.dumps({'status':receipt['status'],'receipt':str(output),
                      'nativeS3':'blocked','details':'See nonsecret receipt for verification and cleanup'}))
    return 0 if receipt['status'] in ['passed-with-limits','cleanup-completed'] else 1

if __name__ == '__main__':
    raise SystemExit(main())
