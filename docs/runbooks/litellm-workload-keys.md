# LiteLLM workload keys

## Contract

FleetWork uses one virtual key per server workload, never per browser or per company:

| Alias | Models | Routes | Secret sink |
| --- | --- | --- | --- |
| `fleet-runner` | Five executable chat aliases plus the embedding route | Chat, embeddings, model listing | Runner `LITELLM_API_KEY` |
| `fleet-coordinator` | `gpt-5-nano` | Chat only | Coordinator `LITELLM_API_KEY` |
| `fleet-catalog-probe` | Five executable chat aliases | Chat and model listing | GitHub `production/LITELLM_PROBE_KEY` |
| `fleet-spend-reader` | None | `/spend/logs` only | Runner `LITELLM_SPEND_API_KEY` |

The spend key uses only the exact `allowed_routes: ["/spend/logs"]` grant. Do not set
`permissions.get_spend_routes`: LiteLLM 1.83.10 gates that key-generation field behind Enterprise,
while its pinned route checker independently accepts an explicitly allowed route. This OSS-safe
contract must still receive a real authenticated `/spend/logs` HTTP 200 smoke before rollout.
The probe has a 1 USD rolling budget, one parallel request, and low RPM/TPM limits. Empty
`allowed_routes` is forbidden because LiteLLM interprets it as unrestricted.

Runner and coordinator rate limits remain unset until production percentiles and burst requirements
are measured. Inventing a cap during a credential split would turn governance into an outage risk.
Their catalog cost/output limits still apply to each run.

The desired state is [litellm-workload-keys.json](../../config/litellm-workload-keys.json). The
reconciler validates its model sets against the approved web catalog before contacting production.

## Global configuration gate

The versioned global policy is
[litellm-global-settings.yaml](../../config/litellm-global-settings.yaml). It requires all four
settings together:

```yaml
litellm_settings:
  include_cost_in_streaming_usage: true
  drop_params: false
router_settings:
  num_retries: 0
  max_fallbacks: 0
```

The pinned digest in
[litellm-global-config.json](../../config/litellm-global-config.json) is a SHA-256 of canonical JSON
for those four scalars. YAML order, comments and whitespace do not change it. A changed value,
missing value, duplicate governed key or stale digest fails closed.

Before every workload-key or model `check`, `apply`, `rotate` or `smoke`, the workflow performs a
read-only three-copy gate:

1. Validate the versioned source and semantic digest.
2. Verify through the Coolify API that service `fnsbybwyqvg6ocuqzsqz3mzl` still binds the declared
   host file to `/app/config.yaml` in the declared container.
3. Read the host bind source and `/app/config.yaml` inside the running container over SSH as
   `debian`, compare the governed settings to source, then require the two live files to be byte
   identical.

The controller parses only governed scalar values. It never prints either production file, API
response bodies, SSH stderr or secret values. Its successful output contains only the service UUID,
the semantic policy digest and the three checked copy labels.

The protected `production` environment must provide
`FLEETWORK_PRODUCTION_SSH_HOST`, `FLEETWORK_PRODUCTION_SSH_PORT`,
`FLEETWORK_PRODUCTION_SSH_PRIVATE_KEY` and a pinned
`FLEETWORK_PRODUCTION_SSH_KNOWN_HOSTS`, in addition to the existing Coolify credentials. Missing SSH
material, host-key mismatch, password-requiring `sudo`, unreadable file, mount drift, policy drift or
host/runtime byte drift stops the workflow before any LiteLLM mutation or smoke.

The gate never edits production. Updating the live global file and restarting LiteLLM remain a
separate, explicitly approved production operation. Do not paste or export the full production
configuration into a PR, workflow log or issue.

## Safe operation

Only run `.github/workflows/reconcile-litellm-keys.yml`. It shares the
`production-fleetwork` concurrency group with every deployment and model reconciliation.

1. This first OpenRouter cutover is intentionally breaking: `gpt-4o-mini` cannot execute the
   runner's tool contract on its available ZDR route. Pause fresh producers and drain legacy jobs
   and pauses with the old runner before changing LiteLLM or deploying catalog `2026.08.05.3`.
2. Run the key workflow in `check` and review its safe report. The global configuration gate must be
   `current`; a failure blocks every later step. Do not bypass it by invoking a reconciler locally
   with production credentials.
3. Bootstrap workload keys before models. Run `apply` through the protected `production`
   environment, then run `check` again. Every workload must be `current`. Authorizing new aliases
   before they exist is additive and gives the model reconciler its required
   `production/LITELLM_PROBE_KEY`.
4. Run the model reconciler in `apply`, then `smoke`. The explicitly inactive managed
   `gpt-4o-mini` deployment is removed only after all five replacement canaries and public aliases
   pass. Its transactional rollback restores the removed route if that apply fails. Then run this
   workload-key workflow in `smoke`: runner chat/embedding, coordinator chat, catalog listing and
   spend lookup must return 2xx. Every negative uses the exact request that another least-privilege
   key proves valid; routes or models outside the tested grant must return exactly HTTP 403. A 400,
   401, 404, 429 or 5xx does not prove authorization and fails the gate.
5. Deploy the runner, coordinator, then web/worker in the same maintenance window. This release
   does not claim an accepted previous catalog version because its executable set changed.
6. Trigger a real coordinator summary and verify its key attribution, model, cost and health.
7. Enable `REQUIRE_MODEL_CATALOG_VERSION=true` only after those proofs, restart the affected
   consumers, and run the final application smoke. Fresh routine jobs carry the full contract too.
   New HITL snapshots preserve their model and provenance; older snapshots fail closed.

If key bootstrap fails, do not run model reconciliation. If model reconciliation fails, keep the
applications paused and do not deploy consumers. If an application deployment fails after the
breaking model cutover, keep maintenance mode active, restore the previous catalog and its routes
first, verify them, then roll consumers back in reverse order. Never restart an old runner against
an incompatible executable set.

For later additive releases, the normal expand/contract order remains consumer `{current,
previous}`, producer `current`, drain, then removal of `previous`. Never list a previous version in a
lock unless every alias executable in that version still has an executable compatibility route.

The one-time alias `fleet-services` is adopted in place and renamed to `fleet-runner`. Its secret is
not rotated merely to rename it.

## Failure behavior

- Duplicate aliases or managed metadata identities stop before mutation. A managed key is recovered
  by its metadata even if its alias was changed outside the reconciler.
- Existing keys are updated in place and snapshot-restored when later work fails.
- A newly generated key is sent to its sink in memory. It is never printed, placed in an argument,
  written to disk, or exposed through a workflow output.
- A failed or ambiguous creation is rediscovered by alias and revoked. Failure to prove that cleanup
  happened is an explicit incident.
- Every sink identity and read path is preflighted before key mutation. Write permission is proved
  only by the subsequent write plus read-back/fingerprint verification. A failed or ambiguous sink write keeps
  an identified `rotation_candidate` active, so a value that may already have reached a workload
  never dies. A later `rotate` run recognizes a fully published candidate by every sink fingerprint
  and finishes the switch. A partially published or uninspectable candidate blocks creation of any
  additional candidate until sink recovery or manual review. Five pending candidates remains a hard
  manual-review boundary.
- Coolify environment rows are listed first. Duplicate rows fail closed; zero creates; one patches;
  the value is reread and compared without logging.
- GitHub secrets are passed to `gh secret set` on stdin. A separate environment variable stores only
  the SHA-256 fingerprint. `check` also compares GitHub update timestamps: a secret changed after
  its fingerprint is stale. GitHub remains write-only, so an interrupted secret/fingerprint pair is
  reported as ambiguous and its candidate stays active until a later successful rotation.
- Existing Coolify values are hashed in memory and compared with LiteLLM's immutable key identifier.
  A mismatch is reported as `sink` drift and `apply` refuses until an explicit rotation is approved.

Never retry a failed `apply` blindly. Run `check`, inspect the four aliases in LiteLLM, and resolve an
`ambiguous and cleanup could not be proven` incident before continuing.

## Rotation

Routine rotation is additive and implemented by the protected workflow:

1. Run `check` and inspect any `rotation: pending` marker.
2. Dispatch `rotate` for exactly one selected workload. The replacement uses a distinct candidate
   alias and metadata, so an interrupted run remains recoverable.
3. The command publishes and verifies every sink before it revokes the previous credential. A
   previously published candidate is completed without generating another key.
4. Run `check` again, then smoke and restart only the affected workload if its platform requires it.
5. Confirm spend attribution under the canonical workload alias.

Do not use delete-then-create. It creates an outage and loses the rollback credential.

For a multi-sink workload, one successful sink followed by another failing sink is a partial
publication. Both old and candidate keys remain active. The next rotation refuses to mint a third
key until every sink is recovered or the candidate is reviewed manually.
