# FlareKit

`fk` is a native Swift personal cloud toolkit. Cloudflare is the first provider. R2 remains primary; B2 and Google Drive are planned full recovery replicas, represented in V1 contracts without primary eviction.

This is a tested development implementation, not a production-qualified release. No hosted service, production domain, or repoctl controller is provisioned.

## What works

| Capability | Implemented validation |
| --- | --- |
| Swift operation core and JSON CLI | Native Linux build and tests |
| macOS Keychain enrollment | Implemented; macOS validation pending |
| R2 private bucket and lock management | REST implementation; live validation pending |
| Streaming R2 upload/download, list pages, inspect, SHA-256 verify | Mock transport tests; live validation pending |
| Multipart upload/resume and explicit abort | Mock interruption/resume test; requires verified covering Indefinite lock |
| Generic Worker plan/apply, version upload, activation, promote and secret staging | Pinned Wrangler dry-run; disposable live plan/apply, bindings and signed ingress qualified |
| Git local capture and fresh restore | Objects including dangling data, refs and index tested; coverage limits below |
| age-encrypted snapshots and vault-scoped dedup | Cross-snapshot ciphertext reuse and independent recovery tests |
| R2 snapshot publication/fetch | Implemented; completion published last; live validation pending |
| Integrity budgets | Local metadata/full/sampled ciphertext checks with explicit coverage |
| B2/Drive replicas | Schema reserved; adapters not implemented |

Archive decisions do not gate object operations or Worker deployment. The archive writer runs locally or in a dedicated trusted job; replication will run in a separate job and copy ciphertext without decryption keys. The webhook Worker receives only receipt bindings and allowed application secrets.

## Build and test

For the repeatable local check, run `./scripts/check --bootstrap` once, then
`./scripts/check`. On macOS, add `--keychain` to exercise temporary credential
enrollment and cleanup. See [macOS qualification and Worker handoff](docs/MACOS-CHECK.md).

Development requires Swift 6.2+, Node 22+ for the Worker adapter, and Git for Git capture. End-user prebuilt installation requires no compilation. No macOS prebuilt release has been produced in this Linux session.

```sh
swift build -c release
cd adapter
npm ci --ignore-scripts
cd ..
./scripts/fetch-age
export FK_TEST_AGE="$PWD/tools/age/age"
export FK_TEST_AGE_KEYGEN="$PWD/tools/age/age-keygen"
swift test
python3 scripts/smoke.py
```

Wrangler is exactly `4.120.0`; npm lockfile includes package integrity. age is exactly `1.3.1`; the bootstrap script verifies the publisher-reported release digest. Swift dependencies are pinned in `Package.resolved`. Node version is a declared prerequisite, not automatically fetched. The adapter rejects Node below 22; exact Node packaging remains a release task.

Configure trusted absolute tool paths:

```sh
export FK_NODE="$(command -v node)"
export FK_WORKER_ADAPTER="$PWD/adapter/worker.mjs"
export FK_AGE="$PWD/tools/age/age"
export FK_AGE_KEYGEN="$PWD/tools/age/age-keygen"
```

`examples/config.json` contains placeholder destinations and credential references, never token values. Replace the account/resource placeholders and select an explicit profile. Obtain separate S3 object credentials, bucket-management credentials, and Worker deployment credentials; do not put them in argv. Local Keychain references use provider `keychain`; CI uses `environment` and protected GitHub environment secrets.

Private Worker deployments support `services` bindings, including named `entrypoint` values, and external Durable Object `script_name` bindings. Profiles must explicitly grant target names in `allowedWorkerServiceNames` and `allowedWorkerDurableObjectScriptNames`; absent lists grant no access to these targets. Cross-environment bindings are unsupported. Deployment readback checks the service/entrypoint and Durable Object class/script as well as namespace presence, and inspection retains these nonsecret fields. The reviewed plan still binds the complete configuration and source artifact. These contracts support Trustless's private three-Worker layout; they do not establish live deployment or hardware admission qualification.

On October 7, the native CLI deployed two disposable personal Cloudflare fixtures, verified their returned versions and binding settings, and executed a named service RPC plus an external SQLite Durable Object call. Both returned the exact nonce; an invalid ingress credential was rejected with 403. Both fixture Workers were deleted and read back as absent. This qualifies the private binding deployment path, not Trustless's physical admission or native S3 credentials.

To repeat after building `.build/debug/fk`, use Python 3.12+ and the current macOS Wrangler OAuth session:

```sh
python3 scripts/qualify-private-bindings.py --account YOUR_ACCOUNT_ID --receipt /private/tmp/unique-bindings.receipt.json
```

The script creates randomly named `fk-bindings-*` fixtures and removes only its own attempted fixture resources. It reads the existing OAuth token internally, keeps deployment credentials out of argv and receipts, and preserves the login session. The receipt path must be new. A failed mutation or cleanup is reported explicitly; inspect the receipt before retrying.

```sh
.build/release/fk --help
.build/release/fk configuration validate --parameters examples/empty.json --config examples/config.json --json
.build/release/fk worker plan --parameters examples/worker.json --profile deployment --config examples/config.json --json
```

See [CLI reference](docs/CLI.md), [container/key/recovery design](docs/ARCHIVE-FORMAT-v1.md), [security boundaries](docs/SECURITY.md), [Git fidelity](docs/GIT-FIDELITY.md), [verification evidence and remaining gates](docs/VERIFICATION.md), and [schemas](schemas/).

## Important limitations

R2 lock durations remain an operator decision. Multipart completion is not assumed to support conditional creation; multipart requires readback of a covering Indefinite bucket lock before initiation/completion. Administrators can remove locks. Single PUT uses `If-None-Match: *`. Encrypted archives split large files into reusable 8 MiB payloads, so archive publication does not depend on multipart.

Git capture records incomplete external coverage honestly: only local LFS data and submodule stores are retained; missing remote data is not fetched. Linked worktree bytes/admin records are retained, but their automatic reconstruction is deferred. Reflogs and all available primary-repository objects, including alternates, are captured. Configuration and hooks remain quarantined. No ACL/xattr/resource-fork fidelity or active-source atomic snapshot guarantee is claimed.

Local vault writing is serialized with a local lock. Multi-host writers and remote encrypted-index reconciliation are not implemented. Recipient changes are rejected; rotation migration needs ciphertext rewriting and old-key recovery coverage. Signing/notarization, policy-seal integration, token revocation automation, logs/tail, distributed inventory/adoption/drift reconciliation, macOS live tests and Cloudflare disposable live tests remain release gates. Do not deploy valuable archives or production infrastructure based solely on mock/dry-run evidence.
