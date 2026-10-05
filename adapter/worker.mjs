// Nonsecret control file, token through environment, secret payload through inherited
// POSIX stdin pipe. Never print Wrangler's human output or API errors.
import {spawn} from 'node:child_process';
import {mkdtemp, mkdir, writeFile, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {dirname, join} from 'node:path';
import {fileURLToPath} from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
const PIN = '4.120.0';
let workspace;
try {
  if (process.argv.length !== 3) throw new Error('control-file');
  const control = await readFile(process.argv[2]);
  if (control.length > 2 * 1024 * 1024) throw new Error('input-limit');
  const input = JSON.parse(control.toString());
  if (input.schemaVersion !== 1 || !['deploy','upload','promote','secret-stage','dry-run'].includes(input.action)) throw new Error('protocol');
  const pkg = JSON.parse(await readFile(join(here,'node_modules/wrangler/package.json')));
  if (pkg.version !== PIN || Number(process.versions.node.split('.')[0]) < 22) throw new Error('runtime-pin');
  workspace = await mkdtemp(join(tmpdir(),'fk-worker-')); await mkdir(join(workspace,'home'),{mode:0o700});
  const config = join(workspace,'wrangler.json');
  await writeFile(config,JSON.stringify(input.configuration),{mode:0o600});
  const output = join(workspace,'output.ndjson');
  let args;
  if (input.action === 'promote') {
    if (!/^[a-f0-9-]{36}$/i.test(input.versionID ?? '')) throw new Error('version-id');
    args = ['versions','deploy',input.versionID+'@100%','--yes'];
  } else if (input.action === 'secret-stage') {
    args = ['versions','secret','bulk'];
  } else {
    args = input.action === 'upload' ? ['versions','upload'] : ['deploy'];
    args.push('--no-bundle');
    if (input.action !== 'upload') args.push('--autoconfig=false');
    if (input.action === 'dry-run') args.push('--dry-run','--outdir',join(workspace,'compiled'));
    if (input.hasSecrets) args.push('--secrets-file','/dev/stdin');
  }
  args.push('--config',config);
  const env = {PATH:dirname(process.execPath),HOME:join(workspace,'home'),XDG_CONFIG_HOME:join(workspace,'home'),
    CLOUDFLARE_API_TOKEN:process.env.FK_DEPLOYMENT_TOKEN ?? '',CLOUDFLARE_ACCOUNT_ID:input.configuration.account_id,
    WRANGLER_SEND_METRICS:'false',WRANGLER_OUTPUT_FILE_PATH:output,CI:'true',NO_COLOR:'1',TERM:'dumb'};
  const child = spawn(process.execPath,[join(here,'node_modules/wrangler/bin/wrangler.js'),...args],{cwd:workspace,env,stdio:['inherit','pipe','pipe']});
  // Discard stdout/stderr: these can expose vars, paths, source and secret errors.
  child.stdout.resume(); child.stderr.resume();
  const timer = setTimeout(()=>child.kill('SIGTERM'),180_000);
  const exit = await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',(code,signal)=>resolve({code,signal}));});
  clearTimeout(timer);
  if (exit.code !== 0) throw new Error('wrangler-failed');
  let records = [];
  try {
    const raw = await readFile(output,'utf8');
    records = raw.trim().split('\n').filter(Boolean).map(line=>JSON.parse(line)).map(x=>Object.fromEntries(
      ['type','version','worker_name','worker_tag','version_id','deployment_id'].filter(k=>typeof x[k] === 'string' || typeof x[k] === 'number').map(k=>[k,x[k]])
    ));
  } catch { if (!['dry-run','secret-stage'].includes(input.action)) throw new Error('missing-structured-output'); }
  process.stdout.write(JSON.stringify({schemaVersion:1,status:'succeeded',wranglerVersion:PIN,records}));
} catch {
  process.stdout.write(JSON.stringify({schemaVersion:1,status:'failed',code:'worker-adapter',message:'Worker adapter failed; source, secrets and subprocess output omitted. Read back remote state before retrying.'}));
  process.exitCode = 7;
} finally { if (workspace) await rm(workspace,{recursive:true,force:true}); }
