# Verification and implementation handoff

Evidence collected on 2026-10-05 with Swift 6.2.1 on Linux. This is a development source release; production qualification remains open.

## Completed checks

- Native executable and test targets built successfully with pinned dependencies.
- All 18 XCTest tests passed, with age tests enabled rather than skipped.
- Tests cover policy rejection before credential access, signing/canonicalization, streaming conditional uploads, collision and corruption handling, retry bounds, XML pagination, retention validation, and Worker build-hook rejection.
- Multipart interruption/resume preserves acknowledged parts, reconciles remote parts, and verifies completed bytes using a mock service.
- Git capture/restore tests exercise dangling objects, refs, staged index data, source preservation, quarantined hooks, and tamper rejection.
- Two snapshots reuse existing encrypted chunks within one vault. Recovery succeeds with the recovery identity without the dedup index or primary identity. Stock age independently decrypts manifest and chunk files.
- Archive publication tests verify that incomplete uploads cannot publish a completion record, retries reuse objects safely, and recovery fetch/restore works without the writer index.
- Native CLI plan/apply through pinned Wrangler passed a credential-free dry-run with SQLite Durable Object and R2 receipt bindings. Fixture secrets and tokens did not appear in captured output.
- Configuration example and JSON schemas validated; age bootstrap download matched its pinned publisher digest.

Mock and dry-run checks establish local behavior, not Cloudflare service compatibility or production deployment success. Metadata verification does not read content. Full ciphertext verification establishes digest integrity, not plaintext authentication; restore additionally decrypts and verifies plaintext hashes. Sampled checks report their actual coverage and budget.

## Remaining implementation and qualification sequence

1. Run `scripts/live.py` only against an explicitly disposable Cloudflare account/environment. Verify private buckets, locks, object transfers, Worker activation/readback, HMAC receipts and cleanup. Settle retention durations before valuable archive use.
2. Validate on macOS: Keychain enrollment/access, POSIX subprocess behavior, filesystem semantics and native builds. Produce pinned Node packaging and signed/notarized prebuilt artifacts. Exercise installation and protected CI workflow with those published artifacts.
3. Implement B2 and Drive adapters, destination-specific credentials and verification journals. Replicate complete ciphertext containers and prove independent restore from each destination. Keep R2 primary objects; do not implement eviction.
4. Add durable remote index reconciliation and distributed writer coordination before using multiple writer hosts or ephemeral CI writers for incremental snapshots.
5. Complete linked-worktree/submodule reconstruction and richer filesystem fidelity as required by the consumer. Establish an atomic capture strategy for repositories being actively modified.
6. Implement recipient rotation migration with ciphertext rewrite, interruption recovery and old/new recovery drills. Do not claim header-only rewrap.
7. Complete inventory/adoption/drift reconciliation, token lifecycle automation, policy-seal integration and operational diagnostics before calling this the full V1 release.

The generic object and Worker interfaces can be qualified and deployed independently of archive and replica milestones. Archive writers run locally or in dedicated trusted jobs; future replication jobs copy ciphertext independently. The receipt Worker must remain outside archive-key and archive-management boundaries.
