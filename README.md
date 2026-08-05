# FleetWorkAI organization workflows

`deploy-coolify.yml` is the only supported Coolify deployment entry point for
FleetWork applications. It accepts an allowlisted logical service and the full
SHA at that repository's current `main`.

The dispatcher refuses a deployment when a required check is missing, pending
or unsuccessful, when Coolify points at another repository or branch, when an
environment key is duplicated, or when the deployed commit and fresh boot
cannot be proven. The web and worker targets are always deployed sequentially.
Dry-run performs the GitHub and Coolify preflights but does not pin a SHA or
start a deployment.

The `production` GitHub environment owns these secrets:

- `FLEETWORK_GITHUB_READ_TOKEN`, read-only access to the private application repos;
- `COOLIFY_URL`;
- `COOLIFY_API_TOKEN`.

The workflow never sends Telegram messages. The production notifier remains the
single source for deployment success and failure notifications.

`merge-checked-pr.yml` is the merge entry point after it has been bootstrapped.
It rereads the current PR head, validates every required check on that exact SHA,
then supplies the same SHA to GitHub's squash-merge API. It never enables an
automatic merge.
