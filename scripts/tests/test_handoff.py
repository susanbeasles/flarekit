import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fk-handoff-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = self.root / 'fk'
        self.binary.write_text('''#!''' + sys.executable + '''
import json, pathlib, sys
request = json.loads(pathlib.Path(sys.argv[sys.argv.index('--request')+1]).read_text())
assert request['operation'] == 'worker.plan', 'application must never execute'
mode = request['parameters']['mode']
if request['parameters'].get('fixtureFailure'):
    print('synthetic-secret-never-print')
    sys.exit(7)
print(json.dumps({'status':'succeeded','operation':'worker.plan','output':{
  'plan':{'activates':mode=='deploy','mode':mode},'planDigest':'a'*64}}))
''')
        self.binary.chmod(0o700)
        self.config = self.root / 'config.json'
        self.config.write_text('{}')
        self.parameters = self.root / 'parameters.json'
        self.parameters.write_text(json.dumps({'mode': 'deploy', 'configuration': {'name': 'caller-worker'}}))
        self.output = self.root / 'review'

    def run_prepare(self):
        return subprocess.run([sys.executable, str(ROOT/'scripts/prepare-worker'),
            '--binary', str(self.binary), '--parameters', str(self.parameters),
            '--config', str(self.config), '--profile', 'deployment',
            '--source', str(self.root), '--output', str(self.output)], capture_output=True, text=True)

    def testPreparesExactReviewedRequestWithoutApplying(self):
        result = self.run_prepare()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertFalse(report['applicationAttempted'])
        self.assertTrue(report['activates'])
        receipt = json.loads((self.output/'plan.json').read_text())
        apply = json.loads((self.output/'apply-request.json').read_text())
        self.assertEqual(apply['operation'], 'worker.apply')
        self.assertEqual(apply['parameters']['approvedPlan'], receipt['output']['plan'])
        self.assertEqual(apply['parameters']['approvedPlanDigest'], receipt['output']['planDigest'])
        self.assertEqual(apply['parameters']['sourceDirectory'], str(self.root.resolve()))
        self.assertEqual((self.output/'apply-request.json').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)

    def testExistingReviewIsNeverOverwritten(self):
        self.output.mkdir()
        sentinel = self.output / 'plan.json'
        sentinel.write_text('previous-review')
        self.assertNotEqual(self.run_prepare().returncode, 0)
        self.assertEqual(sentinel.read_text(), 'previous-review')

    def testFailedPlanCannotProduceApplyAndDoesNotPrintChildOutput(self):
        self.parameters.write_text(json.dumps({'mode': 'deploy', 'fixtureFailure': True}))
        result = self.run_prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('synthetic-secret-never-print', result.stdout + result.stderr)
        self.assertFalse((self.output/'apply-request.json').exists())

    def testActivationModeMustBeExplicit(self):
        self.parameters.write_text('{}')
        self.assertNotEqual(self.run_prepare().returncode, 0)
        self.assertFalse(self.output.exists())

    def testCheckRejectsInvalidJobCountBeforeRunningTools(self):
        result = subprocess.run([sys.executable, str(ROOT/'scripts/check.py'), '--jobs', '0'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('--jobs must be positive', result.stderr)

    @unittest.skipIf(sys.platform == 'darwin', 'macOS permits Keychain qualification')
    def testCheckCannotPretendToValidateMacKeychainOnLinux(self):
        result = subprocess.run([sys.executable, str(ROOT/'scripts/check.py'), '--keychain'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('--keychain requires macOS', result.stderr)

if __name__ == '__main__':
    unittest.main()
