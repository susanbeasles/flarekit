#!/usr/bin/env python3
"""Opt-in disposable Cloudflare verification. No production resources or domains."""
import hashlib, json, os, pathlib, subprocess, tempfile, urllib.request, uuid

assert os.environ.get('FK_LIVE_DISPOSABLE') == 'yes', 'Explicit FK_LIVE_DISPOSABLE=yes required'
account = os.environ['FK_LIVE_ACCOUNT_ID']
assert len(account) == 32 and all(c in '0123456789abcdef' for c in account)
for name in ['FK_R2_MANAGEMENT_TOKEN', 'FK_R2_ACCESS_KEY_ID', 'FK_R2_SECRET_ACCESS_KEY', 'FK_WORKER_TOKEN']:
    assert os.environ.get(name), 'Missing named disposable credential: ' + name
root = pathlib.Path(__file__).resolve().parents[1]
binary = pathlib.Path(os.environ.get('FK_BINARY', root / '.build/release/fk')).resolve()
suffix = uuid.uuid4().hex[:16]; bucket = 'fk-fixture-' + suffix; worker = 'fk-fixture-' + suffix
environment = os.environ.copy()
environment['FK_NODE'] = os.environ.get('FK_NODE', subprocess.check_output(['which', 'node'], text=True).strip())
environment['FK_WORKER_ADAPTER'] = str(root / 'adapter/worker.mjs')
environment['FK_WEBHOOK_SECRET'] = uuid.uuid4().hex

def api(method, path, body=None, worker_token=False):
    token=environment['FK_WORKER_TOKEN' if worker_token else 'FK_R2_MANAGEMENT_TOKEN']
    request=urllib.request.Request('https://api.cloudflare.com/client/v4/accounts/'+account+'/'+path,
        data=None if body is None else json.dumps(body).encode(), method=method,
        headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=60) as response: return json.load(response)

with tempfile.TemporaryDirectory(prefix='fk-live-') as temp:
    temp=pathlib.Path(temp)
    profile={'accountID':account,'bucket':bucket,'group':{'project':'disposable-fixture','environment':'test','purpose':'controller-receipts','contentType':'binary'},
        'managementCredential':{'provider':'environment','reference':'FK_R2_MANAGEMENT_TOKEN'},
        'workerCredential':{'provider':'environment','reference':'FK_WORKER_TOKEN'},
        'accessKeyID':{'provider':'environment','reference':'FK_R2_ACCESS_KEY_ID'},'secretAccessKey':{'provider':'environment','reference':'FK_R2_SECRET_ACCESS_KEY'},
        'allowedWorkerBucketNames':[bucket],'allowedWorkerSecretReferences':['FK_WEBHOOK_SECRET'],
        'allowedOperations':['storage.bucket.create','storage.retention.inspect','storage.retention.apply','storage.object.upload','storage.object.download','storage.object.inspect','worker.plan','worker.apply']}
    config=temp/'config.json';config.write_text(json.dumps({'schemaVersion':1,'profiles':{'fixture':profile},'vaults':[]}))
    def run(operation, parameters):
        request=temp/'request.json';request.write_text(json.dumps({'schemaVersion':1,'requestID':uuid.uuid4().hex,'profile':'fixture','operation':operation,'parameters':parameters}))
        result=subprocess.run([str(binary),'run','--request',str(request),'--config',str(config)],env=environment,capture_output=True,text=True,timeout=240)
        if result.returncode: raise RuntimeError('FlareKit fixture operation failed: '+operation+'; redacted JSON: '+result.stdout)
        return json.loads(result.stdout)['output']
    created_bucket=False; attempted_worker=False
    try:
        run('storage.bucket.create',{'bucket':bucket,'approveCreate':True});created_bucket=True
        rules={'rules':[{'id':'fixture-lock','enabled':True,'prefix':'fixture/','condition':{'type':'Indefinite'}}]}
        baseline=run('storage.retention.inspect',{'bucket':bucket})
        run('storage.retention.apply',{'bucket':bucket,'expectedDigest':baseline['digest'],'rules':rules,'acknowledgeAdministratorRemoval':True})
        source=temp/'payload';source.write_bytes(b'disposable fixture content');digest=hashlib.sha256(source.read_bytes()).hexdigest()
        run('storage.object.upload',{'key':'fixture/payload','file':str(source),'verification':'full'})
        run('storage.object.download',{'key':'fixture/payload','destination':str(temp/'restored'),'expectedSHA256':digest})
        params={'sourceDirectory':str(root/'fixtures/worker'),'mode':'deploy','configuration':{'name':worker,'main':'index.mjs','compatibility_date':'2026-10-04','workers_dev':True,
            'durable_objects':{'bindings':[{'name':'COORDINATOR','class_name':'FixtureCoordinator'}]},'migrations':[{'tag':'v1','new_sqlite_classes':['FixtureCoordinator']}],
            'r2_buckets':[{'binding':'RECEIPTS','bucket_name':bucket}]},'secretReferences':{'WEBHOOK_SECRET':{'provider':'environment','reference':'FK_WEBHOOK_SECRET'}}}
        plan=run('worker.plan',params);params['approvedPlan']=plan['plan'];params['approvedPlanDigest']=plan['planDigest']
        attempted_worker=True
        receipt=run('worker.apply',params)
        subdomain=api('GET','workers/subdomain',worker_token=True)['result']['subdomain']
        endpoint='https://'+worker+'.'+subdomain+'.workers.dev/fixture'
        import hmac
        body=b'disposable live request';signature=hmac.new(environment['FK_WEBHOOK_SECRET'].encode(),body,hashlib.sha256).hexdigest()
        req=urllib.request.Request(endpoint,data=body,headers={'x-fixture-signature':signature})
        with urllib.request.urlopen(req,timeout=60) as response: assertion=json.load(response)
        assert assertion['promotion']=='disabled'
        object_receipt=run('storage.object.inspect',{'key':'fixture/'+assertion['digest']})
        evidence={'worker':worker,'bucket':bucket,'endpoint':endpoint,'deployment':receipt,'receiptObject':object_receipt,'tests':'private R2 + lock readback + checksum restore + Worker secret/SQLite DO/R2 ingress'}
        output=pathlib.Path(os.environ.get('FK_LIVE_RECEIPT', 'disposable-live-receipt.json'))
        output.write_text(json.dumps(evidence,indent=2)+'\n')
        print('PASS: disposable live fixture; receipt saved to '+str(output))
    finally:
        # Only the fresh random fixture resources from this invocation may be removed.
        # Cleanup errors remain visible; never hide retained billable resources.
        if attempted_worker:
            try: api('DELETE','workers/scripts/'+worker+'?force=true',worker_token=True)
            except Exception: print('CLEANUP REQUIRED: disposable Worker '+worker)
        if created_bucket:
            try:
                api('PUT','r2/buckets/'+bucket+'/lock',{'rules':[]})
                for key in ['fixture/payload', 'fixture/'+hashlib.sha256(b'disposable live request').hexdigest()]:
                    try: api('DELETE','r2/buckets/'+bucket+'/objects/'+urllib.parse.quote(key,safe=''))
                    except Exception: pass
                api('DELETE','r2/buckets/'+bucket)
            except Exception: print('CLEANUP REQUIRED: disposable R2 bucket '+bucket)
