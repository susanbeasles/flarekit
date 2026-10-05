#!/usr/bin/env python3
"""Credential-free native CLI + pinned Worker adapter smoke test."""
import hashlib, json, os, pathlib, subprocess, tempfile

root = pathlib.Path(__file__).resolve().parents[1]
binary = pathlib.Path(os.environ.get('FK_BINARY', root / '.build/debug/fk')).resolve()
environment = os.environ.copy()
environment['FK_NODE'] = os.environ.get('FK_NODE', subprocess.check_output(['which', 'node'], text=True).strip())
environment['FK_WORKER_ADAPTER'] = str(root / 'adapter/worker.mjs')
environment['FIXTURE_TOKEN'] = 'disposable-fixture-not-a-real-token'
environment['FIXTURE_WEBHOOK'] = 'fixture-pipe-secret-must-never-appear-in-output'

with tempfile.TemporaryDirectory(prefix='fk-smoke-') as temp:
    temp = pathlib.Path(temp)
    config = {'schemaVersion': 1, 'profiles': {'fixture': {
        'accountID': 'a' * 32, 'group': {'project': 'fixture', 'environment': 'disposable', 'purpose': 'controller-receipts', 'contentType': 'json'},
        'workerCredential': {'provider': 'environment', 'reference': 'FIXTURE_TOKEN'},
        'allowedWorkerBucketNames': ['fk-disposable-receipts'], 'allowedWorkerSecretReferences': ['FIXTURE_WEBHOOK'],
        'allowedOperations': ['worker.plan', 'worker.apply']}}, 'vaults': []}
    config_path = temp / 'config.json'; config_path.write_text(json.dumps(config))
    params = {'sourceDirectory': str(root / 'fixtures/worker'), 'mode': 'dry-run',
              'secretReferences': {'WEBHOOK_SECRET': {'provider': 'environment', 'reference': 'FIXTURE_WEBHOOK'}},
              'configuration': {'name': 'fk-disposable-fixture', 'main': 'index.mjs', 'compatibility_date': '2026-10-04', 'workers_dev': False,
                                'durable_objects': {'bindings': [{'name': 'COORDINATOR', 'class_name': 'FixtureCoordinator'}]},
                                'migrations': [{'tag': 'v1', 'new_sqlite_classes': ['FixtureCoordinator']}],
                                'r2_buckets': [{'binding': 'RECEIPTS', 'bucket_name': 'fk-disposable-receipts'}]}}
    def execute(operation, parameters):
        request = {'schemaVersion': 1, 'requestID': 'fixture-smoke', 'operation': operation, 'profile': 'fixture', 'parameters': parameters}
        path = temp / 'request.json'; path.write_text(json.dumps(request))
        process = subprocess.run([str(binary), 'run', '--request', str(path), '--config', str(config_path)], env=environment, capture_output=True, text=True, timeout=220)
        assert 'disposable-fixture-not-a-real-token' not in process.stdout + process.stderr
        assert environment['FIXTURE_WEBHOOK'] not in process.stdout + process.stderr
        assert process.returncode == 0, process.stdout + process.stderr
        return json.loads(process.stdout)['output']
    plan = execute('worker.plan', params)
    params['approvedPlan'] = plan['plan']; params['approvedPlanDigest'] = plan['planDigest']
    result = execute('worker.apply', params)
    assert result['verification'] == 'local-dry-run'
    assert result['adapter']['wranglerVersion'] == '4.120.0'
    print('PASS: native plan/apply → pinned Wrangler dry-run, SQLite DO + R2 fixture, structured result and token redaction')
