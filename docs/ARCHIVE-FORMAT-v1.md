# FlareKit container v1 — standard age payloads

This design is specified before the format writer. It implements the selected age option; incremental reuse within a vault is mandatory. It makes no key-rewrapping claim.

## Container

Each vault has a random UUID, a versioned descriptor, immutable ciphertext blobs under `blobs/sha256/<ciphertext-sha256>.age`, encrypted manifests under `snapshots/<random-snapshot-uuid>.json.age`, encrypted deduplication indexes under `indexes/<random-revision-uuid>.json.age`, and local journal/head records. Only opaque vault/snapshot identifiers, format version, ciphertext digests/sizes and completion records are exposed. Paths, plaintext digests, index mappings and provenance are encrypted.

Snapshot manifests independently contain everything needed to assemble their files: logical path, whole-file plaintext digest/size, ordered chunk plaintext digests/sizes, ciphertext object identities/digests, coverage and provenance. The deduplication index accelerates writing; it is never needed to restore a completed snapshot. A full replica must retain descriptor, manifests, all referenced ciphertext and completion/verification records. Replication cannot authorize deleting primary data.

Initial chunker: versioned fixed 8 MiB boundaries. Identical chunks are reusable; insertions that shift boundaries can reduce reuse. Chunker changes require a new manifest chunker ID, not reinterpretation of old data. No compression in format v1.

## Key hierarchy and reuse

Use two independently generated native age X25519 identities: a primary operational identity and an independently retained recovery identity. age generates its own random file key and streaming payload key for every newly encrypted blob, index and manifest; FlareKit does not derive encryption keys or nonces from content hashes. Each payload is encrypted to both public recipients. Private identities are obtained from credential providers and passed through pipes, never argv or plaintext config. V1 hardware integration remains unavailable with no fallback.

Within a vault, the encrypted index maps `(chunker-version, plaintext SHA-256, plaintext length)` to an already stored ciphertext digest. The plaintext digest is a private lookup key, never a public object key. Reuse returns the exact existing ciphertext. New content is encrypted once, then added to the next encrypted index revision. Equal content in another vault is separately encrypted. Vault writer serialization prevents duplicate concurrent encryption within one local vault; multi-host index reconciliation is a separate gate, not implied by a local lock.

Whole-file hashes and age authentication catch corrupted content. age does not establish publisher identity: a public-recipient holder can create new valid encrypted data. Restore therefore requires an independently retained manifest ciphertext digest or an agreed trusted signature/checkpoint. A completion marker alone cannot authorize a substituted manifest.

## Recovery

Initialization encrypts a random challenge independently to each recipient and decrypts it with its corresponding identity. Successful recovery verification is recorded with the recipient-set digest. Valuable archive writing requires that verified matching recipient set. This proves usability at enrollment; it does not prove continued independent custody. The operator must retain and periodically test recovery material outside the local device and cloud replicas. CI writers need public recipients and their operational identity only; recovery identity is not deployed into CI or Workers.

Independent recovery downloads a selected destination's manifest and referenced blobs, verifies the trusted ciphertext digest, and uses standard `age -d -i RECOVERY_IDENTITY_FILE` on each payload. The decrypted manifest describes byte assembly and plaintext verification. FlareKit can perform assembly, but payload decryption requires no FlareKit-specific cryptography or primary identity. Partial replication is explicitly not an independently restorable completed replica.

## Rotation

Credential replacement for the same age identity changes provider custody, not stored archive encryption. A new primary/recovery keypair defines a new recipient epoch. Existing ciphertext stays decryptable only with its original recipients. Do not reuse an old ciphertext in a snapshot promising recovery solely through the new epoch unless its old key coverage is retained explicitly. The first implementation refuses changing the vault's recipient set; epoch migration must decrypt, re-encrypt, upload new blobs and publish new manifests, while respecting old retention. Revoking an old credential does not revoke an adversary's already copied identity or ciphertext.

## Publication, replication and checks

Persist verified local ciphertext blobs before publishing the encrypted index and manifest. Remote publication uploads referenced blobs first and a completion record last, using conditional creation. Journal progress; completion discovery ignores unfinished state. Snapshot creation and Worker deployment have separate operations and outcomes.

Verification receipts distinguish metadata, full-content, and sampled checks. Metadata confirms declared size/digest/existence, not actual bytes. Full verification reads/hash-checks ciphertext; decrypt/assemble verification additionally authenticates age and checks plaintext. Sampling records the selection seed, checked objects/bytes and population; it proves only the sampled set. Recurring checks must obey configured byte/request budgets and report incomplete coverage, not silently downgrade full verification. Do not reread every historical blob on each snapshot. R2 request/storage estimates and B2/Drive read costs are reported separately when those adapters exist.

## Execution boundary

Archive writers run in the local `fk` process or a dedicated trusted archive job with bucket-scoped object credentials. Future replication runs in a separate local/CI job with per-destination object credentials. Ciphertext replication does not need decryption identities. Restores and plaintext integrity checks receive only the selected restore identity. The webhook Worker has only a receipt bucket binding; no archive identity, archive bucket binding, replica credential, or bucket-admin credential is supplied.

## Current limitations

Multi-host writer coordination, remote dedup index concurrency, automatic epoch migration, hardware providers, B2 and Drive uploads are not released. Schemas preserve those boundaries and per-destination recovery evidence. The initial local writer lock is not a distributed lock.
