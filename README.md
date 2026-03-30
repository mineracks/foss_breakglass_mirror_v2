# Breakglass FOSS Git Mirror v2

Append-only, tamper-resistant mirroring of GitHub repositories to a self-hosted Gitea instance. Designed to survive malicious upstream destruction.

## Threat model

This tool is built for the scenario where upstream repos you depend on are deliberately destroyed — whether by a compromised maintainer, a platform takedown, account suspension, or coerced force-push. Specifically:

- **Upstream force-pushes empty history** → Your copy keeps all previous commits, branches, and tags via timestamped backup refs. The wipe is detected and blocked.
- **Upstream deletes branches or tags** → Your copy retains them. The sync script never deletes local refs.
- **Upstream repo is deleted entirely** → Fetch fails gracefully; your existing local copy and Gitea copy are untouched.
- **GitHub account is banned/suspended** → Same as deletion — your copies persist.
- **DMCA takedown** → Your pre-takedown copy is preserved.
- **Subtle history rewrite** (less than 50% of refs removed) → Still captured in backup refs, and the live refs are updated so you can diff the before and after.

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

## Quick start

### Prerequisites

- Fresh Ubuntu 22.04+ VM (2 GB RAM, 20+ GB disk)
- Your Gitea instance accessible via HTTPS
- Gitea personal access token (repo read/write scope)
- Optional: GitHub token for higher API rate limits

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
/var/lib/breakglass/audit/       # tamper-evident audit logs (+a attr)
/var/log/breakglass/             # sync logs (90-day rotation)
```

Systemd timers:
- `breakglass-sync.timer` — daily at 04:00 UTC (with 30min random jitter)
- `breakglass-healthcheck.timer` — daily at 08:00 UTC

## Configuration

### sources.yml

```yaml
owners:
  - github: bitcoin
  - github: sparrowwallet
  - github: seedsigner
  - github: seedhammer

  # With filters:
  - github: some-large-org
    include:
      - "important-repo"
    exclude:
      - "test-*"
```

### mirror.env

Key settings:

| Variable | Purpose | Default |
|----------|---------|---------|
| `GITEA_URL` | Your Gitea instance URL | — |
| `GITEA_TOKEN` | Gitea API token | — |
| `GITHUB_TOKEN` | GitHub token (optional) | — |
| `WIPE_THRESHOLD` | Block sync if upstream loses >N% of refs | 50 |
| `NOTIFY_METHOD` | `ntfy`, `email`, `telegram`, or `none` | none |
| `STALE_DAYS` | Alert if a repo hasn't synced in N days | 7 |

## Day-to-day commands

```bash
# Check timer status
sudo systemctl status breakglass-sync.timer

# Trigger immediate sync
sudo systemctl start breakglass-sync.service

# Watch sync live
sudo journalctl -u breakglass-sync.service -f

# Run health check
sudo systemctl start breakglass-healthcheck.service

# View audit trail
ls -lt /var/lib/breakglass/audit/

# View recent sync logs
ls -lt /var/log/breakglass/ | head

# Add a new GitHub org
sudo nano /etc/breakglass/sources.yml
```

## Health checks

The healthcheck script (runs daily) verifies:

1. Gitea is reachable
2. Sync timer is active
3. Recent sync logs exist
4. No repos have gone stale
5. Backup refs exist in all repos (append-only is working)
6. Audit log checksums haven't been tampered with
7. Local ref counts haven't decreased (local deletion detection)

## What this does NOT protect against

To be transparent about limitations:

- **VM compromise**: If an attacker gets root on your mirror VM, they can delete everything. Mitigate with VM-level snapshots, ZFS snapshots, or offsite backups of `/var/lib/breakglass/repos/`.
- **Gitea compromise**: If someone gets admin on your Gitea, they could delete repos there. The bare clones on the VM are the primary archive; Gitea is a secondary copy and convenient browsing interface.
- **Disk failure**: Standard hardware risk. Use RAID or VM-level redundancy.
- **Repos you don't know about yet**: This only mirrors repos from the owners you've configured. If a new critical repo appears, you need to add the owner to sources.yml.

For maximum paranoia, consider also running periodic `tar` backups of `/var/lib/breakglass/repos/` to an offsite location (S3, another server, external drive).

## Differences from v1 (Umbrel version)

The original ran inside Umbrel's managed Docker environment. Umbrel silently recycled containers and broke the automation after a few weeks. This version runs on a plain Ubuntu VM where nothing can interfere with the systemd timers or filesystem.

Key improvements: wipe detection, audit trail, filesystem-level append-only on audit dir, staging namespace for safe fetch, health monitoring with notifications, and no `--mirror` flag (which enables destructive pruning).

## License

MIT
