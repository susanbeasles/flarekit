#!/usr/bin/env python3
"""Repeatable local qualification; never provisions cloud resources."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bootstrap', action='store_true', help='Install locked adapter dependencies and pinned age locally')
    parser.add_argument('--keychain', action='store_true', help='On macOS, exercise a temporary Keychain item and delete it')
    parser.add_argument('--jobs', type=int, default=1)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    if args.keychain and sys.platform != 'darwin':
        parser.error('--keychain requires macOS')
    for tool in ['swift', 'node', 'npm', 'git']:
        if not shutil.which(tool):
            parser.error('Missing prerequisite: ' + tool)
    node_major = int(subprocess.check_output(['node', '-p', 'process.versions.node.split(".")[0]'], text=True).strip())
    if node_major < 22:
        parser.error('Node 22+ required')
    environment = os.environ.copy()
    # Real credentials are unnecessary for these checks, including dry-run.
    for key in list(environment):
        if key.startswith(('FK_', 'CLOUDFLARE_')):
            environment.pop(key)
    def run(command, cwd=ROOT):
        subprocess.run(command, cwd=cwd, env=environment, check=True)
    if args.bootstrap:
        run(['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund'], ROOT / 'adapter')
        if not (ROOT / 'tools/age').exists():
            run(['sh', 'scripts/fetch-age'])
    for tool in ['age', 'age-keygen']:
        path = ROOT / 'tools/age' / tool
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.error('Pinned age tools missing; run ./scripts/check --bootstrap')
    if not (ROOT / 'adapter/node_modules/wrangler/package.json').is_file():
        parser.error('Locked adapter dependencies missing; run ./scripts/check --bootstrap')
    environment['FK_TEST_AGE'] = str(ROOT / 'tools/age/age')
    environment['FK_TEST_AGE_KEYGEN'] = str(ROOT / 'tools/age/age-keygen')
    environment['FK_TEST_KEYCHAIN'] = '1' if args.keychain else '0'
    run(['swift', 'build', '--jobs', str(args.jobs), '--disable-automatic-resolution'])
    run(['swift', 'test', '--jobs', str(args.jobs), '--disable-automatic-resolution'])
    binary_dir = subprocess.check_output(['swift', 'build', '--show-bin-path', '--disable-automatic-resolution'], cwd=ROOT, env=environment, text=True).strip()
    environment['FK_BINARY'] = str(Path(binary_dir) / 'fk')
    run([sys.executable, 'scripts/smoke.py'])
    run([sys.executable, '-m', 'unittest', 'discover', '-s', 'scripts/tests', '-v'])
    parameters = ROOT / 'examples/empty.json'
    run([environment['FK_BINARY'], 'configuration', 'validate', '--parameters', str(parameters), '--config', str(ROOT / 'examples/config.json'), '--json'])
    print(json.dumps({'status': 'passed', 'platform': sys.platform, 'keychainCheck': 'performed' if args.keychain else 'not-requested', 'cloudVerification': 'not-performed', 'workerVerification': 'local-dry-run'}))

if __name__ == '__main__':
    main()
