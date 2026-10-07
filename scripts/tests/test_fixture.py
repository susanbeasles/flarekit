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
import worker,{FixtureCoordinator} from './fixtures/worker/index.mjs';
const bytes=new TextEncoder().encode('receipt');
const request=()=>new Request('https://internal/receipt',{method:'POST',body:bytes});
const key=await crypto.subtle.importKey('raw',new TextEncoder().encode('fixture-key'),{name:'HMAC',hash:'SHA-256'},false,['sign']);
const sig=Array.from(new Uint8Array(await crypto.subtle.sign('HMAC',key,bytes)),x=>x.toString(16).padStart(2,'0')).join('');
const signed=()=>new Request('https://fixture.example/fixture',{method:'POST',body:bytes,headers:{'x-fixture-signature':sig}});
const env=message=>({WEBHOOK_SECRET:'fixture-key',COORDINATOR:{idFromName:x=>x,get:()=>({fetch:async()=>{throw Error(message);}})}});
const waiting=await worker.fetch(signed(),env('Worker not found.'));
assert.equal(waiting.status,503);
assert.equal(waiting.headers.get('x-fixture-readiness'),'durable-object-route');
await assert.rejects(worker.fetch(signed(),env('unexpected storage error')),/unexpected storage error/);
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
