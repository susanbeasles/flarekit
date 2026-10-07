import pathlib
import shutil
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]

class ReceiptFixtureTests(unittest.TestCase):
    def test_locked_duplicate_race_corruption_and_storage_failure(self):
        node = shutil.which('node')
        self.assertIsNotNone(node, 'Node is required for the Worker fixture checks')
        code = r'''
import assert from 'node:assert/strict';
import {FixtureCoordinator} from './fixtures/worker/index.mjs';
const bytes=new TextEncoder().encode('receipt');
const request=()=>new Request('https://internal/receipt',{method:'POST',body:bytes});
const object=data=>({size:data.length,arrayBuffer:async()=>data.slice().buffer});
let stored=null, puts=0;
const storage={put:async()=>{}};
const bucket={get:async()=>stored&&object(stored),put:async(key,value)=>{
  puts++; if(stored)throw Error('object locked'); stored=new Uint8Array(value);return {};
}};
let coordinator=new FixtureCoordinator({storage},{RECEIPTS:bucket});
assert.equal((await (await coordinator.fetch(request())).json()).state,'created');
assert.equal((await (await coordinator.fetch(request())).json()).state,'existing');
assert.equal(puts,1,'duplicate must not overwrite a locked receipt');
stored=new TextEncoder().encode('corrupt');
await assert.rejects(coordinator.fetch(request()),/content mismatch/);
let reads=0;
const race={get:async()=>++reads===1?null:object(bytes),put:async()=>{throw Error('object locked');}};
coordinator=new FixtureCoordinator({storage},{RECEIPTS:race});
assert.equal((await (await coordinator.fetch(request())).json()).state,'existing');
coordinator=new FixtureCoordinator({storage},{RECEIPTS:{get:async()=>null,put:async()=>{throw Error('storage unavailable');}}});
await assert.rejects(coordinator.fetch(request()),/storage unavailable/);
coordinator=new FixtureCoordinator({storage},{RECEIPTS:{get:async()=>null,put:async()=>null}});
await assert.rejects(coordinator.fetch(request()),/missing after conditional write/);
'''
        result = subprocess.run([node, '--input-type=module', '-e', code], cwd=ROOT,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
