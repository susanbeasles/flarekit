# FlareKit CLI reference

Every operation is reachable through the same implementation:

```sh
fk run --request request.json --config config.json
fk storage object upload --parameters upload.json --profile archives --config config.json --json
```

Machine mode emits one versioned result on stdout. Failures contain a redacted error; raw HTTP bodies, token values, source code and Wrangler output are omitted. A profile authorizes operations and allowlists Worker bucket names and secret references. Plans include only secret references, never values. This increment has no continuous transfer progress UI, signal-to-journal cancellation integration, or standalone diagnostic exporter.

## Parameters and effects

| Operation | Required parameters | Credentials and remote effects | Result and recovery |
| --- | --- | --- | --- |
| `configuration.validate` | `{}` | None; local validation | valid or validation error |
| `credential.enroll` | reference; secret via stdin using request file | macOS Keychain; no remote effect | rejects existing identity; enroll replacement under a new reference |
| `storage.bucket.create` | bucket, approveCreate=true | Management write token; creates private bucket | public exposure readback; existing bucket requires explicit future adoption |
| `storage.bucket.inspect` | bucket or profile bucket | Management read; no mutation | metadata and domain exposure |
| `storage.retention.inspect` | bucket | Management read; no mutation | rules and expectedDigest for review |
| `storage.retention.apply` | bucket, expectedDigest, rules={rules:[...]}, acknowledgeAdministratorRemoval=true | Management write; replaces reviewed lock configuration | rejects changed baseline; readback mismatch is drift; administrator can remove locks |
| `storage.object.upload` | key, file, verification=metadata or full | S3 object write/read; conditional creation, up to 5 GiB | checksum, actual verification guarantee; collision never overwrites |
| `storage.object.download` | key, destination, expectedSHA256 | S3 read; no remote mutation | fresh output only after full checksum success |
| `storage.object.list` | optional prefix, continuationToken | S3 list; no mutation | one page and continuationToken; caller iterates |
| `storage.object.inspect` | key | S3 read; no mutation | declared metadata, contentVerified=false |
| `storage.object.verify` | key, expectedSHA256 | S3 read; downloads complete object | full checksum or integrity failure; incurs a full read |
| `storage.multipart.upload` | key, file, journal, verification | S3 write/read plus management read for existing Indefinite lock | bounded parts, resumable journal, completion receipt; uncertain completion needs manual verification |
| `storage.multipart.abort` | journal, approveAbort=true | S3 multipart abort; never deletes completed objects | abort confirmation; preserve journal on uncertainty |
| `worker.plan` | sourceDirectory, configuration, mode=upload/deploy/dry-run; optional sourceSHA, secretReferences | Deployment token for remote baseline; no mutation | plan and planDigest; migration-bearing configuration needs deploy/dry-run |
| `worker.apply` | same inputs plus approvedPlan and approvedPlanDigest | Deployment token; optional secret refs; uploads or activates exactly reviewed artifact | structured version data and API readback; reconcile remote state before retry after uncertainty |
| `worker.inspect` | name | Worker read token; no mutation | deployments and binding IDs; no secret values |
| `worker.promote` | configuration, versionID, expectedDeploymentDigest | Deployment token; activates selected version at 100% | deployments; code rollback does not reverse data/migrations |
| `worker.secret.stage` | configuration, secretReferences, expectedDeploymentDigest | Deployment token and explicitly allowed secret refs; creates a version | traffic unchanged check plus versions; inspect new version before promotion |
| `archive.git.capture` | source, destination | Local Git only | private plaintext staging, trusted manifestDigest and coverage; not a completed encrypted archive |
| `archive.git.verify` | capture, expectedManifestDigest | Local read only | complete capture hashes and bytes checked |
| `archive.git.restore` | capture, destination, expectedManifestDigest | Local Git only | fresh repo, fsck, matching refs/all-object inventory; unsafe config/hooks stay inactive |
| `archive.vault.initialize` | vault, identity, recoveryIdentity | Local age identities; no remote effect | independent-recipient challenge verification; retain recovery offline |
| `archive.snapshot.create` | vault, source, identity | Operational age identity; no remote effect | snapshotID, trusted manifestDigest, new/reused chunks; raw .git files/symlinks are rejected |
| `archive.snapshot.publish` | vault, snapshotID, expectedManifestDigest, identity, verification | S3 write/read; identity reference currently required structurally but never retrieved | ciphertext blobs first, completion last; full or metadata receipt; no eviction |
| `archive.snapshot.fetch` | vault (fresh local destination), vaultID, snapshotID, expectedManifestDigest, identity | S3 read plus selected restore identity to authenticate manifest before accepting its blob list | complete ciphertext container; index not needed; restore separately |
| `archive.snapshot.restore` | vault, snapshotID, expectedManifestDigest, identity, destination | Selected primary/recovery age identity | full authenticated plaintext restoration into fresh destination |
| `archive.snapshot.verify` | vault, snapshotID, expectedManifestDigest, identity, verification, byteBudget/requestBudget as decimal strings; optional seed | Local read; identity not retrieved for ciphertext-only checks | mode, sample seed, checked bytes/objects and completeCoverage; no silent full-check claim |

`identity` and other credential references are objects `{ "provider": "keychain", "reference": "PRIMARY_ARCHIVE_IDENTITY" }`. Secrets are never literals in parameter files. Enrollment reads exactly the bytes supplied on stdin; token input must not include an unintended newline.

## Worker handoff

The caller supplies prebuilt ES modules/WASM. The reviewed configuration supports explicit account/name/main, compatibility date/flags, workers.dev/routes, R2 bindings, Durable Object bindings/migrations and nonsecret vars. Package build hooks, environment files, implicit configuration and arbitrary passthrough are rejected. Named bindings and referenced secrets must also be explicitly allowed by the selected profile. The Worker adapter inherits a real POSIX pipe for secret payloads, avoiding plaintext secret files. Its token is transiently exposed in the child environment; this is a bearer-token boundary.

Save the plan result, add its `plan` and `planDigest` as `approvedPlan` and `approvedPlanDigest` to the same parameters, then run `fk worker apply`. Changed code/config/refs or remote deployment baseline blocks apply. Cloudflare has no cross-service atomic transaction: bucket setup, secret changes, migrations and deployment can partially succeed. Plan digest review is not equivalent to repoctl's hardware policy seal; seal integration remains pending.

## Archive sequence

1. Capture Git into a private staging directory; keep the returned manifest digest independently.
2. Initialize a vault with separately generated primary/recovery identities; preserve recovery material independently.
3. Snapshot the capture directory. The encrypted index reuses unchanged chunks across snapshots.
4. Publish to R2 with an explicit verification mode. Preserve the encrypted manifest digest outside the container.
5. Fetch into a fresh vault directory from a chosen destination; restore with the recovery identity alone.
6. Use Git restore on the recovered capture directory with its trusted capture manifest digest.

No archive operation enables repoctl promotion, changes GitHub rulesets or depends on Worker deployment success.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 2 | Validation, local input or missing resource |
| 3 | Authorization or expired credential |
| 4 | Collision |
| 5 | Integrity failure |
| 6 | Drift |
| 7 | Transport/subprocess/deployment failure |
| 8 | Unsupported/unavailable capability |

On interrupted local writers, determine that the original process is stopped before removing a stale `writer.lock` or multipart `.lock` directory. Retain journals and read remote state before retrying uncertain creation/completion. Never automatically retry rejected hardware PINs; hardware providers are unavailable in this increment.
