# macOS qualification and generic Worker handoff

## Local qualification

Prerequisites: native Swift 6.2+, Node 22+, npm, Git and Python 3. No Homebrew installation is required. Run from the repository root:

```sh
./scripts/check --bootstrap --keychain
```

`--bootstrap` installs the lockfile's adapter dependencies with lifecycle scripts disabled and downloads the pinned age release with digest verification. Swift resolves only the checked-in dependency pins. Later runs can omit `--bootstrap`:

```sh
./scripts/check --keychain
```

The command builds native code, runs Swift tests with age enabled, exercises the Worker dry-run and script tests, and validates example configuration. Default serial compilation avoids the parallel compiler crash seen in the Linux execution environment. `--jobs N` is available for other hosts.

`--keychain` explicitly enables a test that creates one randomly named synthetic credential under `FlareKit.credentials.v1`, reads it, rejects duplicate enrollment, verifies preservation of the original value, and deletes only that temporary item. macOS may display a Keychain authorization prompt. Omitting this option skips Keychain coverage and reports that omission; Linux rejects it. This check does not validate Secure Enclave or YubiKey providers, signing/notarization, locked-Keychain behavior or provider credentials.

The qualification process strips named FlareKit/Cloudflare credentials from child environments. Worker smoke tests use synthetic values and `dry-run`; no cloud resources are created. Dependency downloads require network access. The final JSON report distinguishes local Worker validation from live cloud validation.

## Prepare a caller's Worker

Copy `examples/config.json` and `examples/worker.json` outside source control or into a reviewed configuration directory. Set account ID, deployment credential reference, exact receipt bucket/secret allowlists, caller Worker name, bindings and migration history. Keep archive bindings/keys out of receipt Worker configuration. Set `vaults: []` for infrastructure-only use. Use prebuilt JS/MJS/WASM rather than an application source directory containing package files.

```sh
export FK_NODE="$(command -v node)"
export FK_WORKER_ADAPTER="$PWD/adapter/worker.mjs"

./scripts/prepare-worker \
  --binary .build/debug/fk \
  --parameters /absolute/path/worker.json \
  --config /absolute/path/config.json \
  --profile deployment \
  --source /absolute/path/prebuilt-worker \
  --output /absolute/path/new-review-directory
```

The parameters must explicitly select `dry-run`, `upload`, or `deploy`. A dry-run plan needs no deployment credential; real planning reads the remote baseline. Stateful migrations require `deploy` or `dry-run`. The helper creates private `plan.json` and `apply-request.json` files and never executes application. Existing review directories are rejected rather than overwritten.

Review activation effects, configuration, source hashes, baseline and migration warnings in `plan.json`. Execute the exact request with the same configuration:

```sh
.build/debug/fk run \
  --request /absolute/path/new-review-directory/apply-request.json \
  --config /absolute/path/config.json
```

The core rechecks plan/artifact/deployment drift before application. This is generic Worker infrastructure; repoctl supplies its own code, bindings, allowlists and webhook secret reference. It does not provision repoctl's broker or alter its promotion policy.

## CI boundary

The reusable operation workflow exposes Worker token/webhook secret values only for `deployment`, and R2 object credentials/primary archive identity only for `archive`. Other values are empty. The caller must pass only secrets appropriate to the requested capability; this is environment scoping, not separate runner isolation. Archive and deployment still require separate scoped provider credentials. No production cloud validation is implied by local test success.
