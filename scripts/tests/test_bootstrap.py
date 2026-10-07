import importlib.util
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bootstrap',ROOT/'scripts/bootstrap-live.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
REAL_RUN = subprocess.run

class BootstrapTests(unittest.TestCase):
    def testReadinessOnlyRetries404AndUsesInvalidSignature(self):
        import urllib.error
        calls=[]; pauses=[]; receipt={}
        def ingress(signature):
            calls.append(signature)
            raise urllib.error.HTTPError('https://fixture.example',404 if len(calls)<3 else 401,'',{},None)
        bootstrap.wait_for_ingress(ingress,receipt,lambda:None,pause=pauses.append)
        self.assertEqual(calls,['0'*64]*3)
        self.assertEqual(pauses,[2,2])
        self.assertEqual(receipt['ingressReadinessAttempts'],3)

    def testReadinessDoesNotRetryServerFailureOrAcceptInvalidSignature(self):
        import urllib.error
        def ingress(signature): raise urllib.error.HTTPError('https://fixture.example',500,'',{},None)
        with self.assertRaises(bootstrap.Failure):
            bootstrap.wait_for_ingress(ingress,{},lambda:None,pause=lambda _:self.fail('must not retry'))
        with self.assertRaises(bootstrap.Failure):
            bootstrap.wait_for_ingress(lambda _: {},{},lambda:None,pause=lambda _:self.fail('must not retry'))

    def testInheritedCredentialsAndEndpointOverridesAreExcluded(self):
        with patch.dict(os.environ, {'CLOUDFLARE_API_TOKEN':'secret','NODE_OPTIONS':'--inspect',
             'WRANGLER_CLIENT_ID':'substituted','WRANGLER_AUTH_DOMAIN':'evil.example','FK_WORKER_TOKEN':'secret'}):
            env = bootstrap.child_environment(Path('/private/session'))
        for key in ['CLOUDFLARE_API_TOKEN','NODE_OPTIONS','WRANGLER_CLIENT_ID',
                    'WRANGLER_AUTH_DOMAIN','FK_WORKER_TOKEN']:
            self.assertNotIn(key,env)
        self.assertEqual(env['XDG_CONFIG_HOME'],'/private/session')
        self.assertEqual(env['CLOUDFLARE_AUTH_USE_KEYRING'],'false')

    def testAccountMustBeAuthorized(self):
        accounts=[{'id':'a'*32},{'id':'b'*32}]
        self.assertEqual(bootstrap.select_account(accounts,'b'*32),'b'*32)
        with self.assertRaises(bootstrap.Failure): bootstrap.select_account(accounts,'c'*32)
        with patch('builtins.input',return_value='0'), patch('builtins.print'):
            with self.assertRaises(bootstrap.Failure): bootstrap.select_account(accounts)

    def testRedirectsRefused(self):
        with self.assertRaises(bootstrap.Failure):
            bootstrap.NoRedirect().redirect_request(None,None,302,'',{},'https://evil.example')

    def fixture(self, temp, corrupt=False, cleanup_failure=False):
        directory=Path(temp)
        binary=directory/'fk'
        binary.write_text('#!'+sys.executable+'\n'+'''import json, pathlib, sys
r=json.loads(pathlib.Path(sys.argv[sys.argv.index('--request')+1]).read_text())
output={'plan':{'fixture':True},'planDigest':'a'*64} if r['operation']=='worker.plan' else {'digest':'a'*64}
print(json.dumps({'status':'succeeded','output':output}))
''')
        binary.chmod(0o700)
        class FakeSession:
            def __init__(self):
                self.directory=directory; self.node='/fixture/node'; self.env={}; self.token='synthetic-secret'
                self.calls=[]; self.bucket_exists=False; self.objects={}
            def api(self,method,path,body=None,absent_ok=False):
                self.calls.append((method,path))
                if path.endswith('/workers/subdomain'): return {'subdomain':'fixture'}
                if '/r2/buckets/' in path and method=='GET':
                    if not self.bucket_exists:
                        self.bucket_exists=True; return None
                    return {}
                if method=='DELETE' and cleanup_failure: raise bootstrap.Failure('secret error')
                return None
            def wrangler(self,args,interactive=False):
                self.calls.append(('wrangler',args))
                if args[:3]==['r2','object','put']:
                    self.objects[args[3]]=Path(args[args.index('--file')+1]).read_bytes()
                if args[:3]==['r2','object','get']:
                    data=self.objects.get(args[3],b'disposable live request')
                    Path(args[args.index('--file')+1]).write_bytes(b'corrupt' if corrupt else data)
            ingress_count=0
            def run(self,args,**kwargs):
                if args[0] != self.node: return REAL_RUN(args,**kwargs)
                import hashlib
                request=json.loads(kwargs['input'])
                if request['signature']=='0'*64:
                    return subprocess.CompletedProcess(args,0,json.dumps({'status':401,'body':None}), '')
                self.ingress_count+=1
                body={'digest':hashlib.sha256(b'disposable live request').hexdigest(),
                    'state':'created' if self.ingress_count==1 else 'existing','promotion':'disabled'}
                return subprocess.CompletedProcess(args,0,json.dumps({'status':200,'body':body}), '')
        return FakeSession(),binary

    def qualify(self,session,binary,receipt,save):
        with patch.object(bootstrap.subprocess,'run',side_effect=session.run):
            return bootstrap.qualify(session,'a'*32,binary,receipt,save)

    def testFullQualificationReportsNativeS3BlockedAndCleans(self):
        with tempfile.TemporaryDirectory() as temp:
            session,binary=self.fixture(temp)
            receipt={}
            self.qualify(session,binary,receipt,lambda:None)
            self.assertEqual(receipt['verification']['nativeS3']['status'],'blocked')
            self.assertEqual(receipt['verification']['oauthR2'],'full-content-comparison')
            self.assertEqual(receipt['cleanup']['status'],'worker-and-bucket-removed')
            self.assertNotIn('synthetic-secret',json.dumps(receipt))
            deletes=[path for method,path in session.calls if method=='DELETE']
            self.assertEqual(len(deletes),2)
            self.assertTrue(all(receipt['bucket'] in path for path in deletes))

    def testContentFailureStillCleansAndNeverReportsVerified(self):
        with tempfile.TemporaryDirectory() as temp:
            session,binary=self.fixture(temp,corrupt=True)
            receipt={}
            with self.assertRaises(bootstrap.Failure):
                self.qualify(session,binary,receipt,lambda:None)
            self.assertNotIn('oauthR2',receipt['verification'])
            self.assertEqual(receipt['cleanup']['status'],'worker-and-bucket-removed')

    def testCleanupFailureIsVisibleAndFails(self):
        with tempfile.TemporaryDirectory() as temp:
            session,binary=self.fixture(temp,cleanup_failure=True)
            receipt={}
            with self.assertRaises(bootstrap.Failure):
                self.qualify(session,binary,receipt,lambda:None)
            self.assertEqual(receipt['cleanup']['status'],'incomplete')
            self.assertTrue(receipt['cleanup']['resources'])
            self.assertNotIn('secret error',json.dumps(receipt))

    def testCleanupRejectsNonFixtureNamesBeforeNetworking(self):
        class Session:
            env={}
            def api(self,*args,**kwargs): raise AssertionError('Network must not run')
        with self.assertRaises(bootstrap.Failure):
            bootstrap.cleanup(Session(),'a'*32,{'bucket':'archive','worker':'archive'},lambda:None)

    def testLostCreateResponseTriggersOnlyFixtureCleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            session,binary=self.fixture(temp)
            binary.write_text('#!'+sys.executable+'\nimport sys\nsys.exit(7)\n')
            receipt={}
            with self.assertRaises(bootstrap.Failure):
                self.qualify(session,binary,receipt,lambda:None)
            self.assertEqual(receipt['phase'],'bucket-create-attempted')
            deletes=[p for method,p in session.calls if method=='DELETE']
            self.assertEqual(len(deletes),1)
            self.assertIn(receipt['bucket'],deletes[0])
            self.assertEqual(receipt['cleanup']['status'],'worker-and-bucket-removed')

    def testRevocationChecksBothTokensAndRemovesLocalState(self):
        with tempfile.TemporaryDirectory() as temp:
            session=object.__new__(bootstrap.Session)
            session.directory=Path(temp)
            session.token='synthetic-access'
            stored=session.directory/'.wrangler/config/default.toml'
            stored.parent.mkdir(parents=True)
            stored.write_text("refresh_token = 'synthetic-refresh'\n")
            session.node='/fixture/node'; session.env={}
            requests=[]
            def revoke(args,**kwargs):
                requests.append(kwargs['input'])
                self.assertNotIn('synthetic-', ' '.join(args))
                self.assertIn("https://dash.cloudflare.com/oauth2/revoke",args[-1])
                return subprocess.CompletedProcess(args,0,'200','')
            with patch.object(bootstrap.subprocess,'run',side_effect=revoke): session.close()
            self.assertEqual(len(requests),2)
            self.assertFalse(stored.exists())
            self.assertIsNone(session.token)
            self.assertIn('token_type_hint=refresh_token',requests[0])
            self.assertIn('token_type_hint=access_token',requests[1])

    def testRevocationFailureCannotClaimSuccess(self):
        with tempfile.TemporaryDirectory() as temp:
            session=object.__new__(bootstrap.Session)
            session.directory=Path(temp)
            session.token='synthetic-access'
            stored=session.directory/'.wrangler/config/default.toml'
            stored.parent.mkdir(parents=True)
            stored.write_text('refresh_token = "synthetic-refresh"\n')
            session.node='/fixture/node'; session.env={}
            with patch.object(bootstrap.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'500','')):
                with self.assertRaises(bootstrap.Failure): session.close()
            self.assertTrue(stored.exists())
            self.assertEqual(session.token,'synthetic-access')

    def testAccessRevocationFailureStillRevokesRefreshAndRetainsState(self):
        with tempfile.TemporaryDirectory() as temp:
            session=object.__new__(bootstrap.Session)
            session.directory=Path(temp);session.node='/fixture/node';session.env={}
            session.token='synthetic-access'
            stored=session.directory/'.wrangler/config/default.toml'
            stored.parent.mkdir(parents=True)
            stored.write_text('refresh_token = "synthetic-refresh"\n')
            requests=[]
            def revoke(args,**kwargs):
                requests.append(kwargs['input'])
                return subprocess.CompletedProcess(args,0,'200' if len(requests)==1 else '400','')
            with patch.object(bootstrap.subprocess,'run',side_effect=revoke):
                with self.assertRaises(bootstrap.Failure): session.close()
            self.assertEqual(len(requests),2)
            self.assertIn('token_type_hint=refresh_token',requests[0])
            self.assertTrue(stored.exists())
            self.assertEqual(session.token,'synthetic-access')

    def testRevocationFailurePreservesPrimaryFailure(self):
        with tempfile.TemporaryDirectory() as temp:
            binary=Path(temp)/'fk';binary.write_text('fixture');binary.chmod(0o700)
            output=Path(temp)/'run.receipt.json'
            class FakeSession:
                def __init__(self,*args): pass
                def authorize(self): pass
                def api(self,*args): return [{'id':'a'*32}]
                def close(self): raise bootstrap.Failure('refresh token unavailable')
            with patch.object(bootstrap,'Session',FakeSession), patch.object(bootstrap,'qualify',side_effect=bootstrap.Failure('Worker apply failed')), patch.object(sys,'argv',['bootstrap','--binary',str(binary),'--receipt',str(output)]), patch('builtins.print'):
                self.assertEqual(bootstrap.main(),1)
            receipt=json.loads(output.read_text())
            self.assertEqual(receipt['failure'],'Worker apply failed')
            self.assertEqual(receipt['authorizationFailure']['reason'],'refresh token unavailable')

if __name__=='__main__': unittest.main()
