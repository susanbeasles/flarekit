#!/usr/bin/env python3
import argparse, json, os, pathlib, re, secrets, shutil, subprocess, tempfile, time, tomllib
parser=argparse.ArgumentParser(description='Qualify native private Worker bindings against disposable Cloudflare fixtures using the existing macOS Wrangler OAuth session.')
parser.add_argument('--account',required=True)
parser.add_argument('--receipt',type=pathlib.Path,required=True)
args=parser.parse_args()
if not re.fullmatch(r'[a-f0-9]{32}',args.account): parser.error('Invalid account ID')
ROOT=pathlib.Path(__file__).resolve().parents[1]
ACCOUNT=args.account
RECEIPT=args.receipt
# Never overwrite an existing qualification receipt.
with RECEIPT.open('x'): pass
RECEIPT.chmod(0o600)
NODE=shutil.which('node')
API="""let raw='';for await(const c of process.stdin)raw+=c;const i=JSON.parse(raw);try{const r=await fetch('https://api.cloudflare.com/client/v4/accounts/'+i.account+i.path,{method:i.method,redirect:'error',headers:{Authorization:'Bearer '+i.token},signal:AbortSignal.timeout(30000)});const v=await r.json();process.stdout.write(JSON.stringify({status:r.status,success:v.success,result:v.result}));}catch{process.exitCode=1;}"""
INGRESS="""let raw='';for await(const c of process.stdin)raw+=c;const i=JSON.parse(raw);try{const r=await fetch(i.url,{redirect:'error',headers:{Authorization:'Bearer '+i.token},signal:AbortSignal.timeout(15000)});process.stdout.write(JSON.stringify({status:r.status,body:r.status===200?await r.json():null}));}catch{process.exitCode=1;}"""
receipt={'schemaVersion':1,'accountID':ACCOUNT,'verification':{},'cleanup':{},'status':'working'}
def save():
    RECEIPT.write_text(json.dumps(receipt,indent=2)+'\n'); RECEIPT.chmod(0o600)
def node(code,payload):
    r=subprocess.run([NODE,'--input-type=module','-e',code],input=json.dumps(payload),capture_output=True,text=True,timeout=40)
    if r.returncode: raise RuntimeError('Node transport failed; response withheld')
    return json.loads(r.stdout)
def api(method,path,missing=False):
    r=node(API,{'account':ACCOUNT,'token':oauth,'method':method,'path':path})
    if missing and r['status']==404: return None
    if r['status']>=300 or r.get('success') is not True: raise RuntimeError('Cloudflare API failed HTTP '+str(r['status'])+'; response withheld')
    return r.get('result')
def run(stage,operation,parameters):
    request=stage/'request.json'; request.write_text(json.dumps({'schemaVersion':1,'requestID':secrets.token_hex(16),'operation':operation,'profile':'fixture','parameters':parameters}));request.chmod(0o600)
    r=subprocess.run([str(ROOT/'.build/debug/fk'),'run','--request',str(request),'--config',str(stage/'config.json')],capture_output=True,text=True,env=env,timeout=240)
    if r.returncode: raise RuntimeError('Native '+operation+' failed; response withheld')
    value=json.loads(r.stdout)
    if value.get('status')!='succeeded': raise RuntimeError('Native '+operation+' rejected; response withheld')
    return value['output']
oauth=tomllib.loads((pathlib.Path.home()/'Library/Preferences/.wrangler/config/default.toml').read_text()).get('oauth_token')
if not oauth: raise RuntimeError('Current authorized Wrangler OAuth token unavailable')
suffix=secrets.token_hex(6); provider='fk-bindings-'+suffix+'-provider'; consumer='fk-bindings-'+suffix+'-consumer'
receipt.update(provider=provider,consumer=consumer);save()
created=[]
try:
    with tempfile.TemporaryDirectory(prefix='fk-bindings-native-') as directory:
        stage=pathlib.Path(directory)
        fixture_token=secrets.token_urlsafe(32)
        env=os.environ.copy();env.update(FK_BINDING_OAUTH=oauth,FK_BINDING_TOKEN=fixture_token,FK_NODE=NODE,FK_WORKER_ADAPTER=str(ROOT/'adapter/worker.mjs'))
        profile={'accountID':ACCOUNT,'group':{'project':'disposable-fixture','environment':'test','purpose':'private-bindings','contentType':'binary'},'allowedOperations':['worker.plan','worker.apply','worker.inspect'],'workerCredential':{'provider':'environment','reference':'FK_BINDING_OAUTH'},'allowedWorkerServiceNames':[provider],'allowedWorkerDurableObjectScriptNames':[provider],'allowedWorkerSecretReferences':['FK_BINDING_TOKEN']}
        (stage/'config.json').write_text(json.dumps({'schemaVersion':1,'profiles':{'fixture':profile},'vaults':[]}));(stage/'config.json').chmod(0o600)
        for name in [provider,consumer]:
            if api('GET','/workers/scripts/'+name+'/settings',missing=True) is not None: raise RuntimeError('Fixture name collision; no existing resource adopted')
        provider_dir=stage/'provider';provider_dir.mkdir()
        (provider_dir/'worker.mjs').write_text("import {WorkerEntrypoint,DurableObject} from 'cloudflare:workers';\nexport class FixtureService extends WorkerEntrypoint { ping(nonce){return nonce;} }\nexport class FixtureDO extends DurableObject { async fetch(r){return Response.json({nonce:await r.text()});} }\nexport default {fetch(){return new Response('Forbidden',{status:403});}};\n")
        consumer_dir=stage/'consumer';consumer_dir.mkdir()
        (consumer_dir/'worker.mjs').write_text("export default {async fetch(r,env){if(r.headers.get('Authorization')!=='Bearer '+env.FIXTURE_TOKEN)return new Response('Forbidden',{status:403});const nonce=new URL(r.url).searchParams.get('nonce');if(!/^[a-f0-9]{32}$/.test(nonce??''))return new Response('Invalid',{status:400});const service=await env.PRIVATE.ping(nonce);const response=await env.STATE.get(env.STATE.idFromName('qualification')).fetch(new Request('https://fixture.invalid',{method:'POST',body:nonce}));const object=await response.json();return Response.json({service,object:object.nonce});}};\n")
        configs=[(provider,provider_dir,{'name':provider,'main':'worker.mjs','compatibility_date':'2026-08-08','workers_dev':False,'durable_objects':{'bindings':[{'name':'SELF','class_name':'FixtureDO'}]},'migrations':[{'tag':'fixture-v1','new_sqlite_classes':['FixtureDO']}]},{}),(consumer,consumer_dir,{'name':consumer,'main':'worker.mjs','compatibility_date':'2026-08-08','workers_dev':True,'durable_objects':{'bindings':[{'name':'STATE','class_name':'FixtureDO','script_name':provider}]},'services':[{'binding':'PRIVATE','service':provider,'entrypoint':'FixtureService'}]},{'FIXTURE_TOKEN':{'provider':'environment','reference':'FK_BINDING_TOKEN'}})]
        for name,source,config,secret_refs in configs:
            parameters={'sourceDirectory':str(source),'configuration':config,'mode':'deploy','secretReferences':secret_refs}
            receipt['phase']='plan-'+name;save()
            plan=run(stage,'worker.plan',parameters)
            parameters.update(approvedPlan=plan['plan'],approvedPlanDigest=plan['planDigest'])
            created.append(name)
            receipt['phase']='apply-'+name;save()
            applied=run(stage,'worker.apply',parameters)
            receipt['verification'][name]={'verification':applied['verification'],'resources':applied['resources'],'endpoints':applied['endpoints']};save()
        endpoint=receipt['verification'][consumer]['endpoints'][0]
        nonce=secrets.token_hex(16); verified=False
        for attempt in range(12):
            try:
                response=node(INGRESS,{'url':endpoint+'/?nonce='+nonce,'token':fixture_token})
                if response['status']==200 and response['body']=={'service':nonce,'object':nonce}: verified=True;break
            except RuntimeError: pass
            time.sleep(2)
        if not verified: raise RuntimeError('Live named service/DO execution could not be verified')
        denied=node(INGRESS,{'url':endpoint+'/?nonce='+nonce,'token':'invalid'})
        if denied['status']!=403: raise RuntimeError('Fixture ingress credential rejection failed')
        receipt['verification']['liveExecution']='named-service-and-external-sqlite-DO-nonce-match'
        receipt['verification']['invalidCredential']='rejected-403';receipt['status']='verified';save()
except Exception as error:
    receipt['status']='failed';receipt['failure']=str(error);save()
finally:
    errors=[]
    for name in reversed(created):
        try:
            if not name.startswith('fk-bindings-'+suffix+'-'): raise RuntimeError('Cleanup name boundary failed')
            api('DELETE','/workers/scripts/'+name+'?force=true',missing=True)
            if api('GET','/workers/scripts/'+name+'/settings',missing=True) is not None: raise RuntimeError('Deleted fixture still exists')
        except Exception as error: errors.append({'resource':name,'failure':str(error)})
    receipt['cleanup']={'status':'incomplete' if errors else 'fixture-workers-removed','errors':errors};save()
print(json.dumps({'status':receipt['status'],'phase':receipt.get('phase'),'failure':receipt.get('failure'),'liveExecution':receipt['verification'].get('liveExecution'),'cleanup':receipt['cleanup'],'receipt':str(RECEIPT)}))
raise SystemExit(0 if receipt['status']=='verified' and not receipt['cleanup']['errors'] else 1)
