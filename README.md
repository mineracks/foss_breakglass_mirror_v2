# Breakglass FOSS Git Mirror v2

Append-only, tamper-resistant mirroring of GitHub repositories to a self-hosted Gitea instance. Designed to survive malicious upstream destruction.

## Threat model

This tool is built for the scenario where upstream repos you depend on are deliberately destroyed — whether by a compromised maintainer, a platform takedown, account suspension, or coerced force-push. Specifically:

- **Upstream force-pushes empty history** — Your copy keeps all previous commits, branches, and tags via timestamped backup refs. The wipe is detected and blocked.
- **Upstream deletes branches or tags** — Your copy retains them. The sync script never deletes local refs.
- **Upstream repo is deleted entirely** — Fetch fails gracefully; your existing local copy and Gitea copy are untouched.
- **GitHub account is banned/suspended** — Same as deletion — your copies persist.
- **DMCA takedown** — Your pre-takedown copy is preserved.
- **Subtle history rewrite** (less than 50% of refs removed) — Still captured in backup refs, and the live refs are updated so you can diff the before and after.

## How it works

The system maintains bare git clones on a dedicated Ubuntu VM, sitting between GitHub (upstream) and your Gitea (your archive).

```
GitHub ──fetch──► Ubuntu VM (bare clones) ──push──► Your Gitea
                  │
                  ├─ refs/heads/*        (live branches)
                  ├─ refs/tags/*         (live tags)
                  ├─ refs/backup/<ts>/*  (timestamped snapshots)
                  └─ audit logs          (tamper-evident)
```

### The append-only guarantee

Before every fetch from GitHub, the script snapshots all current refs into `refs/backup/<timestamp>/`. These backup refs are pushed to Gitea alongside the live refs.

After fetching, upstream changes are staged into a temporary namespace (`refs/upstream-staging/`) and compared against the existing state. If the upstream has lost more than 50% of its refs (configurable), the update is **blocked**, a notification is sent, and the previous state is preserved. This is the wipe detection.

Local refs that upstream has deleted are **never removed locally**. The sync is additive only.

### Wipe detection

If a repo goes from 40 branches and 100 tags to 1 branch and 0 tags, that's a 97% loss — the script refuses to update live refs and alerts you. The threshold is configurable (`WIPE_THRESHOLD` in mirror.env, default 50%).

Even below the threshold, every change is logged in the audit trail with before/after SHA hashes.

### Tamper-evident audit

Every sync writes a structured audit log recording exactly what happened: which refs were added, updated, or (on the upstream side) disappeared. Each audit file gets a SHA256 checksum appended to a checksums log. The health check verifies these haven't been tampered with.

The audit directory is set with the `+a` (append-only) filesystem attribute during install, so even the breakglass service user can't delete or modify previous audit entries.

## Features

### Organisation and repo metadata sync

On first sync, the script automatically creates Gitea organisations matching each GitHub owner and syncs their avatars. Repository metadata — including default branch, description, and homepage URL — is read from the GitHub API and applied to the Gitea repo. Descriptions are prefixed with `[BREAKGLASS]` so it's always clear which repos are mirrors.

This runs once per repo (tracked by marker files) and prevents Gitea from showing 500 errors due to default branch mismatches.

### Wiki mirroring

When `SYNC_WIKIS=true` (the default), the script checks whether each GitHub repo has an associated wiki. If one exists, it clones the wiki as a separate bare repo and pushes it to the matching Gitea repo's wiki. This preserves project documentation alongside the code.

Wiki repos use the standard `.wiki.git` suffix and are pushed via HTTP with credential-store authentication.

### Release asset downloads

When `SYNC_RELEASES=true`, the script downloads release assets (binaries, source archives, installers) for the latest N releases per repo (configured by `RELEASE_KEEP`, default 3). Assets are stored locally under `RELEASE_ROOT` and uploaded to Gitea as proper releases via the API, preserving the tag name, release title, and body text.

This ensures that even if GitHub removes download links, you have local copies of the actual release binaries people need to verify and install software.

### LFS support with timeouts

Repos using Git LFS are handled automatically. LFS objects are fetched and pushed alongside regular git objects. To prevent massive LFS repos (like seedsigner/buildroot) from blocking the entire sync indefinitely, each LFS operation is wrapped in a configurable timeout (`LFS_TIMEOUT`, default 600 seconds). If a timeout is hit, the sync continues with remaining repos rather than stalling.

### Push notifications

The sync script and health check both send push notifications for significant events. Supported backends are ntfy (recommended — free, no server needed, push to phone), email, and Telegram. Notifications include priority levels and tags:

- **Urgent** — wipe detection triggered, sync blocked
- **High** — errors during sync, healthcheck failures
- **Default** — sync completed successfully, new repos mirrored
- **Low** — routine status updates

### Disk space monitoring

The health check includes disk usage monitoring. It warns at 80% usage and sends a critical alert at 90%, giving you time to expand storage or prune release assets before the mirror runs out of space.

## Quick start

### Prerequisites

- Fresh Ubuntu 22.04+ VM (2 GB RAM, 20+ GB disk)
- Your Gitea instance accessible via HTTP/HTTPS
- Gitea personal access token (repo read/write scope)
- Optional: GitHub token for higher API rate limits (60 → 5000 req/h)

### Install

```bash
git clone <this-repo>
cd foss-breakglass-mirror-v2
sudo bash install.sh
```

The installer handles everything interactively: packages, user creation, config, systemd timers.

### What it creates

```
/opt/breakglass/scripts/         # sync and healthcheck scripts
/etc/breakglass/mirror.env       # tokens, URLs, settings (mode 600)
/etc/breakglass/sources.yml      # GitHub owners to mirror
/var/lib/breakglass/repos/       # bare git clones
/var/lib/breakglass/releases/    # downloaded release assets
/var/lib/breakglass/audit/       # tamper-evident audit logs (+a attr)
/var/log/breakglass/             # sync logs (90-day rotation)
```

Systemd timers:

- `breakglass-sync.timer` — daily at 02:00 local time, with `Persistent=true` so missed runs fire on next boot
- `breakglass-healthcheck.timer` — daily at 08:00 local time

Both services use `Restart=on-failure` with a 5-minute backoff and an 8-hour timeout to handle large initial syncs.

## Configuration

### sources.yml

Define which GitHub owners to mirror. You can mirror entire organisations or filter to specific repos:

```yaml
owners:
  - github: bitcoin
  - github: sparrowwallet
  - github: seedsigner
  - github: seedhammer

  # Mirror only specific repos from an org:
  - github: cmyk
    include:
      - "seedetcher"

  # Exclude repos by pattern:
  - github: some-large-org
    exclude:
      - "test-*"
      - "deprecated-*"
```

### mirror.env

| Variable | Purpose | Default |
|----------|---------|---------|
| `GITEA_URL` | Your Gitea instance URL | — |
| `GITEA_TOKEN` | Gitea API token | — |
| `GITEA_USER` | Gitea username for push auth | — |
| `GITHUB_TOKEN` | GitHub token (optional, raises rate limit) | — |
| `WIPE_THRESHOLD` | Block sync if upstream loses >N% of refs | `50` |
| `NOTIFY_METHOD` | `ntfy`, `email`, `telegram`, or `none` | `none` |
| `NTFY_TOPIC` | ntfy topic name (make it unguessable) | `breakglass` |
| `NTFY_SERVER` | ntfy server URL | `https://ntfy.sh` |
| `STALE_DAYS` | Alert if a repo hasn't synced in N days | `7` |
| `LFS_TIMEOUT` | Max seconds per LFS fetch/push (0 = no limit) | `600` |
| `SYNC_WIKIS` | Mirror GitHub wikis to Gitea | `true` |
| `SYNC_RELEASES` | Download and mirror release assets | `true` |
| `RELEASE_KEEP` | How many releases to keep per repo | `3` |
| `RELEASE_ROOT` | Where to store downloaded release assets | `/var/lib/breakglass/releases` |
| `FORCE_HTTP11` | Force HTTP/1.1 (helps with Cloudflare Tunnel) | `true` |

## Day-to-day commands

```bash
# Check timer status
sudo systemctl status breakglass-sync.timer

# Trigger immediate sync
sudo systemctl start breakglass-sync.service

# Run sync in foreground (useful for debugging)
sudo -u breakglass /opt/breakglass/scripts/breakglass-sync.sh

# Run sync detached from your SSH session (won't die if you disconnect)
sudo -u breakglass nohup /opt/breakglass/scripts/breakglass-sync.sh &

# Watch sync logs live
tail -f /var/log/breakglass/sync-$(date +%Y%m%d)*.log

# Run health check
sudo systemctl start breakglass-healthcheck.service

# View audit trail
ls -lt /var/lib/breakglass/audit/

# View recent sync logs
ls -lt /var/log/breakglass/ | head

# Check disk usage
du -sh /var/lib/breakglass/repos/ /var/lib/breakglass/releases/

# Re-sync metadata for all repos (e.g., after fixing a bug)
sudo rm -f /var/lib/breakglass/repos/.avatars/*.meta.synced
sudo systemctl start breakglass-sync.service

# Add a new GitHub org
sudo nano /etc/breakglass/sources.yml
```

## Health checks

The healthcheck script (runs daily at 08:00) verifies:

1. Gitea is reachable
2. Sync timer is active and enabled
3. Recent sync logs exist
4. No repos have gone stale (configurable threshold)
5. Backup refs exist in all repos (append-only is working)
6. Audit log checksums haven't been tampered with
7. Local ref counts haven't decreased (local deletion detection)
8. Disk usage is below warning (80%) and critical (90%) thresholds

Results are sent as a push notification with appropriate priority levels.

## What this does NOT protect against

To be transparent about limitations:

- **VM compromise** — If an attacker gets root on your mirror VM, they can delete everything. Mitigate with VM-level snapshots, ZFS snapshots, or offsite backups of `/var/lib/breakglass/repos/`.
- **Gitea compromise** — If someone gets admin on your Gitea, they could delete repos there. The bare clones on the VM are the primary archive; Gitea is a secondary copy and convenient browsing interface.
- **Disk failure** — Standard hardware risk. Use RAID or VM-level redundancy.
- **Repos you don't know about yet** — This only mirrors repos from the owners you've configured. If a new critical repo appears, you need to add the owner to `sources.yml`.
- **GitHub API rate limits** — Without a `GITHUB_TOKEN`, you're limited to 60 requests/hour. Large orgs with many repos will hit this. A token raises the limit to 5000/hour.

For maximum paranoia, consider also running periodic `tar` backups of `/var/lib/breakglass/repos/` to an offsite location (S3, another server, external drive).

## Differences from v1 (Umbrel version)

The original ran inside Umbrel's managed Docker environment. Umbrel silently recycled containers and broke the automation after a few weeks. This version runs on a plain Ubuntu VM where nothing can interfere with the systemd timers or filesystem.

Key improvements over v1: wipe detection with configurable threshold, tamper-evident audit trail with checksums, filesystem-level append-only on audit directory, staging namespace for safe fetch, wiki and release mirroring, LFS support with timeouts, org/repo avatar and metadata sync, 8-point health monitoring with disk space alerts, push notifications via ntfy/email/Telegram, systemd timers with persistence and failure restart, and no `--mirror` flag (which enables destructive pruning).

## License

MIT
