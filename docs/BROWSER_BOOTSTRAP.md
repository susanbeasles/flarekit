# Browser-authorized disposable qualification

Run from the repository root after the native local check passes:

```bash
python3 scripts/bootstrap-live.py
```

The command opens Cloudflare's browser OAuth authorization page. Approve access and select the account if multiple accounts are available. No token creation, copying, secret entry, or credential upload is required. R2 must already be enabled on the selected account; the bootstrap does not activate paid products or register a workers.dev account subdomain.

The pinned Wrangler 4.148.0 login uses PKCE and requests `account:read`, `user:read`, `workers:write`, and `workers_scripts:write`; Wrangler also requests `offline_access`. These scopes are broader than the generated fixtures. Browser consent is the authorization boundary; the executable restricts its mutations and cleanup to newly generated fixture names. This is not server-enforced bucket-only OAuth authorization.

The bootstrap uses a private temporary session directory with a restrictive umask and ignores existing Cloudflare tokens, auth endpoint overrides, Wrangler profiles, and Node injection settings. Wrangler's temporary token file is local and mode 0600; it is not an archive artifact. It does not modify the user's existing Wrangler session or Keychain. Deployment authorization passes through the existing native environment-credential interface into the isolated adapter. The deployed Worker receives only a generated webhook secret and its receipt-bucket binding. It receives no provisioning token or archive key.

## Coverage

| Capability | Verification |
| --- | --- |
| Native bucket creation | Cloudflare response and existing native readback |
| Native retention configuration | Existing digest guard and lock readback |
| OAuth R2 object upload/download | Entire fixture content comparison through pinned Wrangler's remote object API |
| Native Worker plan/apply | Exact approved plan and digest, existing pinned adapter |
| Worker secret, SQLite DO, R2 binding | Signed live ingress and full receipt content comparison |
| Duplicate ingress | Second delivery returns `existing` |
| Invalid signature | HTTP 401 |
| Native S3 client | Blocked; not tested by OAuth object operations |
| Archive encryption, deduplication, replicas, restore | Not performed |
| Cleanup | Exact fixture Worker and bucket removal responses; failures fail the command |
| Durable Object namespace cleanup | Not independently verified |

`passed-with-limits` means the listed infrastructure checks passed; it does not qualify the native S3 client or archive. This command does not run recurring archive scans.

Wrangler's pinned OAuth scope list has no token-management scope. R2 S3 access requires an R2 API token or temporary credentials derived from an existing parent R2 token. The bootstrap does not claim that its OAuth token is an S3 credential, request manual secrets, or create an unsupported token-management grant. Provisioning remains usable independently of native S3 credential enrollment and archive format review.

## Observed live qualification

On October 7, 2026, the native bootstrap infrastructure path passed against disposable personal Cloudflare resources using the existing Wrangler OAuth session: bucket creation and retention readback, complete object upload/download, Worker plan/apply, HMAC ingress through SQLite DO and R2, duplicate delivery, invalid-signature rejection, and receipt content comparison. The fixture Worker and bucket were removed. Evidence: `/private/tmp/flarekit-bootstrap-debug.receipt.json`.

The bootstrap probes invalid-signature rejection before submitting a signed receipt. A new DO route can still return `Worker not found` after the public route is ready. The fixture exposes only that exact pre-handler routing failure as HTTP 503 with a readiness marker; the bootstrap retries that marker for at most 12 attempts. Storage errors and other ambiguous responses fail without automatic retry.

The first live attempt exposed R2 error 10069 on duplicate writes to a locked receipt. The Worker now reads and compares the entire stored content before returning `existing`; a concurrent creation is accepted only after that same comparison. Missing, corrupt, and unavailable storage remain failures. This qualification preserved the existing OAuth session; separate earlier isolated sessions received HTTP 200 for both revocation requests. No native S3, archive-cloud flow, or independent DO namespace cleanup is claimed.

## Receipts and recovery

The nonsecret, mode 0600 `bootstrap-live.receipt.json` records names before mutation, verification performed, cleanup, and authorization revocation. Existing receipts are never overwritten by a new qualification run. Specify a new filename for another run:

```bash
python3 scripts/bootstrap-live.py --receipt another-run.receipt.json
```

Retry cleanup after a failed or interrupted run with a fresh browser authorization:

```bash
python3 scripts/bootstrap-live.py --cleanup bootstrap-live.receipt.json
```

Cleanup accepts only matching `fk-fixture-<16 lowercase hex digits>` Worker/bucket names. It operates in the receipt's authorized account, removes fixture retention rules, deletes the two known fixture object keys, and removes the fixture resources. Do not modify a receipt to target an unrelated resource. The first run checks both names are absent before provisioning; a lost mutation response still triggers cleanup. Unexpected extra objects cause bucket deletion to fail visibly instead of broad deletion.

Authorization shutdown sends both access-token and refresh-token revocation requests to Cloudflare's pinned OAuth endpoint and requires HTTP 200, then removes local credential state. The refresh request runs first so an access-token rejection cannot prevent its revocation. Local state is retained by `close()` if either response fails; the enclosing temporary directory is still removed on normal process exit, so the failure receipt and dashboard recovery remain necessary. This is revocation-response evidence, not an independent proof of every token's invalidation. A revocation failure makes the command fail and is recorded. Abrupt process termination can prevent cleanup/revocation; retry resource cleanup and revoke the interrupted OAuth authorization in Cloudflare's dashboard.

## Sources

- [Wrangler browser login and auth token interface](https://developers.cloudflare.com/workers/wrangler/commands/general/)
- [R2 token policies and S3 credential derivation](https://developers.cloudflare.com/r2/api/tokens/)
- [R2 temporary credentials require an existing parent](https://developers.cloudflare.com/r2/api/s3/temporary-credentials/)

## Local checks

```bash
python3 -m unittest discover -s scripts/tests -p test_bootstrap.py -v
```

These tests mock Cloudflare, Wrangler, and the native binary. They check account authorization, credential/environment isolation, redirect rejection, full content comparisons, cleanup on failure, fixture-name containment, and revocation handling. They do not claim live cloud qualification.

The deployment adapter is pinned to Wrangler 4.148.0. Its Miniflare dependency pins vulnerable Sharp 0.35.4, so the lockfile applies a scoped Sharp 0.35.5 override for [GHSA-wq5f-xc86-pv6w](https://github.com/advisories/GHSA-wq5f-xc86-pv6w). The updated adapter audit reports zero findings.
