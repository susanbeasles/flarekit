# GitHub Actions integration

`.github/workflows/operation.yml` is a reusable workflow using the same prebuilt `fk` implementation. It has no privileged PR path. Repository variables must pin `FLAREKIT_ALLOWED_REPOSITORY`, JSON-string actor IDs in `FLAREKIT_ALLOWED_ACTOR_IDS`, a reviewed HTTPS `FLAREKIT_TOOL_URL`, and its independently reviewed SHA-256. A published Linux tool package is required; none is published by this source handoff.

Use two independently protected environments: deployment contains only the Worker token/application webhook secret; archive contains only R2 object credentials and the operational age identity if that operation requires decryption. Neither needs the recovery identity. Do not give archive credentials to the deployment environment. Configure environment branch restrictions and approval reviewers separately. Workflow actor/ref checks supplement those protections; they do not create them.

The exact tool artifact digest pins the binary and adapter lockfile; Node is fixed at 24.19.0. All third-party actions are pinned to retrieved commit SHAs. The reusable workflow does not automatically create tokens, enroll vaults, change rulesets, enable promotion or perform production integration tests.

Minimal consumer example (replace the immutable workflow commit and paths):

```yaml
name: Independent archive and deployment
on:
  workflow_dispatch:
permissions: {}
jobs:
  archive:
    uses: YOUR_OWNER/FlareKit/.github/workflows/operation.yml@REVIEWED_FULL_COMMIT_SHA
    permissions:
      contents: read
    with:
      environment: archive
      capability: archive
      request-path: .flarekit/archive-request.json
      config-path: .flarekit/config.json
    secrets:
      FK_R2_ACCESS_KEY_ID: ${{ secrets.FK_R2_ACCESS_KEY_ID }}
      FK_R2_SECRET_ACCESS_KEY: ${{ secrets.FK_R2_SECRET_ACCESS_KEY }}
      FK_PRIMARY_IDENTITY: ${{ secrets.FK_PRIMARY_IDENTITY }}
  deploy:
    uses: YOUR_OWNER/FlareKit/.github/workflows/operation.yml@REVIEWED_FULL_COMMIT_SHA
    permissions:
      contents: read
    with:
      environment: deployment
      capability: deployment
      request-path: .flarekit/worker-request.json
      config-path: .flarekit/config.json
    secrets:
      FK_WORKER_TOKEN: ${{ secrets.FK_WORKER_TOKEN }}
      FK_WEBHOOK_SECRET: ${{ secrets.FK_WEBHOOK_SECRET }}
```

The jobs intentionally have no dependency on each other. Both record independent outcomes. The example assumes prepared requests/prebuilt Worker modules/local archive data are present; it does not pretend that a prior local vault automatically exists on an ephemeral runner. Persistent CI dedup-index loading and distributed-writer reconciliation are still a release gate. Local CLI operations already share the same schemas and implementation.

Environment secrets are resolved in the environment-bound reusable job; callers may also supply explicit secrets. Do not rely on broad `secrets: inherit`. Configure repository variables before enabling the workflow; missing repository/actor variables cause the privileged job to skip.
