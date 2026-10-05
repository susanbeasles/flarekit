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
    return env.COORDINATOR.get(env.COORDINATOR.idFromName('fixture')).fetch('https://internal/receipt',{method:'POST',body});
  }
};
export class FixtureCoordinator {
  constructor(ctx, env) { this.ctx=ctx; this.env=env; }
  async fetch(request) {
    const bytes=await request.arrayBuffer();
    const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),x=>x.toString(16).padStart(2,'0')).join('');
    await this.ctx.storage.put('lastDigest',digest);
    const object=await this.env.RECEIPTS.put('fixture/'+digest,bytes,{onlyIf:{etagDoesNotMatch:'*'}});
    return Response.json({digest,state:object?'created':'existing',promotion:'disabled'});
  }
}
