export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/fixture') return new Response('Not found', {status:404});
    if (!env.WEBHOOK_SECRET) return new Response('Not configured', {status:503});
    const body = new Uint8Array(await request.arrayBuffer());
    if (body.length > 4096) return new Response('Too large', {status:413});
    const header = request.headers.get('x-fixture-signature');
    if (!/^[a-f0-9]{64}$/.test(header ?? '')) return new Response('Unauthorized', {status:401});
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.WEBHOOK_SECRET), {name:'HMAC',hash:'SHA-256'},false,['verify']);
    const signature = Uint8Array.from(header.match(/../g),x=>parseInt(x,16));
    if (!await crypto.subtle.verify('HMAC',key,signature,body)) return new Response('Unauthorized',{status:401});
    try {
      return await env.COORDINATOR.get(env.COORDINATOR.idFromName('fixture')).fetch('https://internal/receipt',{method:'POST',body});
    } catch(error) {
      // Newly deployed DO routes can lag behind the public Worker route.
      // Expose only this pre-handler failure as a bounded readiness condition.
      if (error.message !== 'Worker not found.') throw error;
      return new Response('Durable Object route not ready', {
        status:503, headers:{'x-fixture-readiness':'durable-object-route'}
      });
    }
  }
};
export class FixtureCoordinator {
  constructor(ctx, env) { this.ctx=ctx; this.env=env; }
  async fetch(request) {
    const bytes=await request.arrayBuffer();
    const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),x=>x.toString(16).padStart(2,'0')).join('');
    await this.ctx.storage.put('lastDigest',digest);
    const key='fixture/'+digest;
    const existingMatches=async()=>{
      const existing=await this.env.RECEIPTS.get(key);
      if (!existing) return false;
      if (existing.size!==bytes.byteLength) throw new Error('Receipt content mismatch');
      const stored=new Uint8Array(await existing.arrayBuffer());
      const expected=new Uint8Array(bytes);
      if (stored.length!==expected.length || stored.some((value,index)=>value!==expected[index]))
        throw new Error('Receipt content mismatch');
      return true;
    };
    // Locked objects reject overwrites before evaluating the conditional PUT.
    // Verify the immutable content instead of attempting a duplicate write.
    let state='existing';
    if (!await existingMatches()) {
      let object;
      try {
        object=await this.env.RECEIPTS.put(key,bytes,{onlyIf:{etagDoesNotMatch:'*'}});
      } catch(error) {
        // Another delivery can create and lock the object after our read.
        // Only an exact stored-content match establishes successful delivery.
        if (!await existingMatches()) throw error;
      }
      if (object) state='created';
      else if (!await existingMatches()) throw new Error('Receipt missing after conditional write');
    }
    return Response.json({digest,state,promotion:'disabled'});
  }
}
