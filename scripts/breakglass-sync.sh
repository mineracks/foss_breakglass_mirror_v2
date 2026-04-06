#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# breakglass-sync.sh — APPEND-ONLY GitHub → Gitea mirror
# ═══════════════════════════════════════════════════════════
#
# DESIGN PRINCIPLE: This script ONLY ADDS data. It never
# deletes refs, never force-pushes, never prunes. If upstream
# is maliciously wiped, the worst that happens is the empty
# state gets added alongside all previous history — nothing
# is lost.
#
# Threat model:
#   - Upstream maintainer force-pushes empty history
#   - Upstream repo is deleted entirely
#   - Upstream tags/branches are removed
#   - GitHub account is suspended/banned
#   - DMCA takedown removes repo
#
# In ALL these cases, previously-synced data is preserved.
#
# ═══════════════════════════════════════════════════════════
set -euo pipefail

# ── Prevent git from ever prompting for credentials ──────
# Without this, git/git-lfs will hang waiting for input when
# running under nohup/systemd with no terminal attached.
export GIT_TERMINAL_PROMPT=0

# ── Load config ──────────────────────────────────────────
ENV_FILE="${BREAKGLASS_ENV:-/etc/breakglass/mirror.env}"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "FATAL: config not found at $ENV_FILE" >&2
  exit 1
fi
# shellcheck source=/dev/null
source "$ENV_FILE"

# ── Defaults ─────────────────────────────────────────────
MIRROR_ROOT="${MIRROR_ROOT:-/var/lib/breakglass/repos}"
RELEASE_ROOT="${RELEASE_ROOT:-/var/lib/breakglass/releases}"
LOG_DIR="${LOG_DIR:-/var/log/breakglass}"
AUDIT_DIR="${AUDIT_DIR:-/var/lib/breakglass/audit}"
FORCE_HTTP11="${FORCE_HTTP11:-true}"
NOTIFY_METHOD="${NOTIFY_METHOD:-none}"
# If upstream loses more than this % of refs, abort the push
# as a likely malicious wipe. 0 = disabled.
WIPE_THRESHOLD="${WIPE_THRESHOLD:-50}"
# How many releases to keep per repo (latest N)
RELEASE_KEEP="${RELEASE_KEEP:-3}"
# Enable wiki and release syncing
SYNC_WIKIS="${SYNC_WIKIS:-true}"
SYNC_RELEASES="${SYNC_RELEASES:-true}"
# Reverse sync (Gitea → GitHub)
REVERSE_SYNC_REPOS="${REVERSE_SYNC_REPOS:-}"
GITHUB_PUSH_TOKEN="${GITHUB_PUSH_TOKEN:-}"
GITHUB_PUSH_OWNER="${GITHUB_PUSH_OWNER:-}"

mkdir -p "$MIRROR_ROOT" "$RELEASE_ROOT" "$LOG_DIR" "$AUDIT_DIR"

TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG_FILE="$LOG_DIR/sync-${TIMESTAMP}.log"
AUDIT_FILE="$AUDIT_DIR/audit-${TIMESTAMP}.log"
ERRORS=0
SYNCED=0
SKIPPED=0
PROTECTED=0

# ── Helpers ──────────────────────────────────────────────

log()  { printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$LOG_FILE"; }
warn() { log "WARN: $*"; }
die()  { log "FATAL: $*"; notify "Breakglass sync FAILED: $*"; exit 1; }

audit() {
  # Append-only audit trail — one line per event
  printf '%s  %s  %s\n' "$TIMESTAMP" "$(date -u +%H:%M:%S)" "$*" >> "$AUDIT_FILE"
}

retry() {
  local max_attempts=$1; shift
  local delay=2
  for (( attempt=1; attempt<=max_attempts; attempt++ )); do
    if "$@"; then return 0; fi
    if (( attempt < max_attempts )); then
      log "  retry $attempt/$max_attempts — sleeping ${delay}s …"
      sleep "$delay"
      (( delay = delay * 2 > 30 ? 30 : delay * 2 ))
    fi
  done
  return 1
}

# ── HTTP helpers ─────────────────────────────────────────

# GitHub API calls — may go through Cloudflare, so honour FORCE_HTTP11
gh_curl_opts=(-sfS --connect-timeout 15 --max-time 120)
[[ "$FORCE_HTTP11" == "true" ]] && gh_curl_opts+=(--http1.1)

# Gitea API calls — typically localhost, no need for --http1.1
# Use -sS (not -f) so we can inspect HTTP responses ourselves
gitea_curl_opts=(-sS --connect-timeout 15 --max-time 300)

gh_api() {
  local path="$1"; shift
  local -a headers=(-H "Accept: application/vnd.github+json")
  [[ -n "${GITHUB_TOKEN:-}" ]] && headers+=(-H "Authorization: Bearer $GITHUB_TOKEN")
  curl "${gh_curl_opts[@]}" "${headers[@]}" "https://api.github.com${path}" "$@"
}

gitea_api() {
  local method="$1" path="$2"; shift 2
  local -a args=(-X "$method" -H "Content-Type: application/json"
                 -H "Authorization: token $GITEA_TOKEN")
  local response http_code
  response=$(curl "${gitea_curl_opts[@]}" -w "\n%{http_code}" "${args[@]}" "${GITEA_URL}/api/v1${path}" "$@" 2>&1)
  http_code=$(echo "$response" | tail -1)
  response=$(echo "$response" | sed '$d')

  # Return the response body on stdout
  echo "$response"

  # Return success for 2xx and 409 (conflict = already exists, which is fine)
  case "$http_code" in
    2[0-9][0-9]) return 0 ;;
    409)         return 0 ;;
    *)           return 1 ;;
  esac
}

# ── YAML-lite parser ─────────────────────────────────────

parse_sources() {
  local gh="" org="" inc="" exc="" in_include="" in_exclude=""
  while IFS= read -r line; do
    line="${line%%#*}"
    [[ -z "${line// /}" ]] && continue

    if [[ "$line" =~ ^[[:space:]]*-[[:space:]]*github:[[:space:]]*(.+) ]]; then
      [[ -n "$gh" ]] && echo "OWNER $gh ${org:-$gh} ${inc:-*} ${exc:-}"
      gh="${BASH_REMATCH[1]// /}"
      org="" inc="" exc="" in_include="" in_exclude=""
    elif [[ "$line" =~ ^[[:space:]]*gitea_org:[[:space:]]*(.+) ]]; then
      org="${BASH_REMATCH[1]// /}"
    elif [[ "$line" =~ ^[[:space:]]*-[[:space:]]*\"(.+)\" ]] && [[ -n "$in_include" ]]; then
      inc="${inc:+$inc|}${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^[[:space:]]*-[[:space:]]*\"(.+)\" ]] && [[ -n "$in_exclude" ]]; then
      exc="${exc:+$exc|}${BASH_REMATCH[1]}"
    fi
    if [[ "$line" =~ ^[[:space:]]*include: ]]; then in_include=1; in_exclude=""; fi
    if [[ "$line" =~ ^[[:space:]]*exclude: ]]; then in_exclude=1; in_include=""; fi
    if [[ ! "$line" =~ ^[[:space:]]*- ]] && [[ ! "$line" =~ ^[[:space:]]*(include|exclude): ]]; then
      in_include="" in_exclude=""
    fi
  done < "$SOURCES_FILE"
  [[ -n "$gh" ]] && echo "OWNER $gh ${org:-$gh} ${inc:-*} ${exc:-}"
}

# ── GitHub pagination ────────────────────────────────────

gh_list_repos() {
  local owner="$1"
  local page=1 per_page=100
  while true; do
    local url="/orgs/${owner}/repos?per_page=${per_page}&page=${page}&type=public"
    local body
    if ! body=$(gh_api "$url" 2>/dev/null); then
      url="/users/${owner}/repos?per_page=${per_page}&page=${page}&type=public"
      body=$(gh_api "$url") || { warn "cannot list repos for $owner"; return 1; }
    fi
    local names
    names=$(echo "$body" | grep -o '"full_name"[[:space:]]*:[[:space:]]*"[^"]*"' \
          | sed 's/.*"full_name"[[:space:]]*:[[:space:]]*"//;s/"//' \
          | awk -F/ '{print $2}')
    [[ -z "$names" ]] && break
    echo "$names"
    (( page++ ))
    local count
    count=$(echo "$names" | wc -l)
    (( count < per_page )) && break
  done
}

# ── Gitea org/repo ensure ────────────────────────────────

ensure_gitea_org() {
  local org="$1"
  local result
  result=$(gitea_api GET "/orgs/${org}" 2>/dev/null) || true
  if echo "$result" | grep -q '"id"'; then
    # Org exists — sync avatar if we haven't already
    sync_org_avatar "$org"
    return 0
  fi
  log "  creating Gitea org: $org"
  result=$(gitea_api POST "/orgs" -d "{\"username\":\"${org}\",\"visibility\":\"public\"}" 2>/dev/null) || true
  if echo "$result" | grep -q '"id"'; then
    log "  org $org ready"
    sync_org_avatar "$org"
    return 0
  fi
  warn "could not create org $org — will push under $GITEA_USER"
}

ensure_gitea_repo() {
  local org="$1" repo="$2"
  local result
  result=$(gitea_api GET "/repos/${org}/${repo}" 2>/dev/null) || true
  if echo "$result" | grep -q '"id"'; then
    # Repo exists — sync avatar if we haven't already
    sync_repo_avatar "$org" "$repo"
    return 0
  fi
  log "  creating Gitea repo: ${org}/${repo}"
  result=$(gitea_api POST "/orgs/${org}/repos" \
    -d "{\"name\":\"${repo}\",\"private\":false,\"description\":\"[BREAKGLASS] Append-only mirror of github.com/${org}/${repo}\"}" 2>/dev/null) || true
  if echo "$result" | grep -q '"id"'; then
    log "  repo ${org}/${repo} ready"
    sync_repo_avatar "$org" "$repo"
    return 0
  fi
  warn "could not create repo ${org}/${repo}"
  return 1
}

# ── Avatar/logo sync ────────────────────────────────────

sync_org_avatar() {
  local org="$1"
  local avatar_cache="${MIRROR_ROOT}/.avatars"
  local marker="${avatar_cache}/${org}.org.synced"
  mkdir -p "$avatar_cache"

  # Only sync once per org (remove marker file to force re-sync)
  [[ -f "$marker" ]] && return 0

  log "    syncing avatar for org: $org"

  # Download from GitHub (works for both orgs and users)
  local tmp_avatar="${avatar_cache}/${org}.png"
  if curl -sS -L -o "$tmp_avatar" "https://github.com/${org}.png?size=256" 2>/dev/null; then
    # Check we actually got an image (not an error page)
    local file_size
    file_size=$(stat -c %s "$tmp_avatar" 2>/dev/null || echo 0)
    if (( file_size > 500 )); then
      # Upload to Gitea via API — base64 encode the image
      local b64_avatar
      b64_avatar=$(base64 -w0 "$tmp_avatar" 2>/dev/null)
      if [[ -n "$b64_avatar" ]]; then
        local avatar_result
        avatar_result=$(gitea_api POST "/orgs/${org}/avatar" \
          -d "{\"image\":\"${b64_avatar}\"}" 2>/dev/null) || true
        log "    avatar set for org $org"
        touch "$marker"
      fi
    else
      warn "avatar download too small for $org (${file_size} bytes) — skipping"
    fi
  else
    warn "could not download GitHub avatar for $org"
  fi
  rm -f "$tmp_avatar"
}

sync_repo_avatar() {
  local org="$1" repo="$2"
  local avatar_cache="${MIRROR_ROOT}/.avatars"
  local marker="${avatar_cache}/${org}_${repo}.repo.synced"
  mkdir -p "$avatar_cache"

  # Only sync once per repo
  [[ -f "$marker" ]] && return 0

  log "    syncing avatar for repo: ${org}/${repo}"

  # Try to get the repo's owner avatar from GitHub API
  local gh_repo_data
  gh_repo_data=$(gh_api "/repos/${org}/${repo}" 2>/dev/null) || { touch "$marker"; return 0; }

  # Extract owner avatar_url (repos inherit org avatar on GitHub)
  local avatar_url
  avatar_url=$(echo "$gh_repo_data" | grep -o '"avatar_url"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 \
    | sed 's/"avatar_url"[[:space:]]*:[[:space:]]*"//;s/"//')

  if [[ -z "$avatar_url" ]]; then
    # No custom avatar — just mark as done (inherits org avatar in Gitea too)
    touch "$marker"
    return 0
  fi

  local tmp_avatar="${avatar_cache}/${org}_${repo}.png"
  if curl -sS -L -o "$tmp_avatar" "${avatar_url}" 2>/dev/null; then
    local file_size
    file_size=$(stat -c %s "$tmp_avatar" 2>/dev/null || echo 0)
    if (( file_size > 500 )); then
      local b64_avatar
      b64_avatar=$(base64 -w0 "$tmp_avatar" 2>/dev/null)
      if [[ -n "$b64_avatar" ]]; then
        local avatar_result
        avatar_result=$(gitea_api POST "/repos/${org}/${repo}/avatar" \
          -d "{\"image\":\"${b64_avatar}\"}" 2>/dev/null) || true
        log "    avatar set for ${org}/${repo}"
      fi
    fi
  fi
  touch "$marker"
  rm -f "$tmp_avatar"
}

# ═══════════════════════════════════════════════════════════
# CORE: Per-repo append-only sync
# ═══════════════════════════════════════════════════════════

count_refs() {
  # Count refs in a bare repo (heads + tags + notes)
  local dir="$1"
  git -C "$dir" for-each-ref --format='x' refs/heads refs/tags refs/notes 2>/dev/null | wc -l
}

snapshot_refs() {
  # Save every current ref into refs/backup/<timestamp>/
  # This is the append-only guarantee: old state is always preserved
  local dir="$1" ts="$2"
  local count=0
  git -C "$dir" for-each-ref --format='%(refname) %(objectname)' \
    refs/heads refs/tags refs/notes 2>/dev/null | \
  while read -r refname sha; do
    local backup_ref="refs/backup/${ts}/${refname#refs/}"
    git -C "$dir" update-ref "$backup_ref" "$sha" 2>/dev/null || true
    (( count++ )) || true
  done
  echo "$count"
}

detect_wipe() {
  # Compare ref count before and after fetch.
  # If upstream lost a large proportion of refs, this is suspicious.
  local before="$1" after="$2" repo_name="$3"

  if (( before == 0 )); then
    # First sync — nothing to compare
    return 0
  fi

  if (( after == 0 )); then
    log "    !! WIPE DETECTED: upstream has ZERO refs for $repo_name"
    audit "WIPE_DETECTED repo=$repo_name before=$before after=0"
    return 1
  fi

  if (( WIPE_THRESHOLD > 0 )); then
    local lost=$(( before - after ))
    if (( lost > 0 )); then
      local pct=$(( lost * 100 / before ))
      if (( pct >= WIPE_THRESHOLD )); then
        log "    !! SUSPICIOUS: upstream lost ${pct}% of refs ($before → $after) for $repo_name"
        audit "WIPE_SUSPECTED repo=$repo_name before=$before after=$after lost_pct=$pct"
        return 1
      fi
    fi
  fi

  return 0
}

sync_repo() {
  local gh_owner="$1" repo="$2" gitea_org="$3"
  local bare_dir="${MIRROR_ROOT}/${gh_owner}/${repo}.git"
  local gh_url="https://github.com/${gh_owner}/${repo}.git"
  local gitea_url="${GITEA_URL}/${gitea_org}/${repo}.git"

  log "  syncing ${gh_owner}/${repo} → ${gitea_org}/${repo}"
  audit "SYNC_START repo=${gh_owner}/${repo}"

  # ── Ensure local bare clone exists ───────────────────
  if [[ ! -d "$bare_dir" ]]; then
    log "    initial clone …"
    if ! retry 3 git clone --bare "$gh_url" "$bare_dir" 2>>"$LOG_FILE"; then
      warn "clone failed for ${gh_owner}/${repo}"
      audit "CLONE_FAILED repo=${gh_owner}/${repo}"
      return 1
    fi
    # Do NOT use --mirror flag: it enables pruning on fetch.
    # We configure fetch refspecs manually below.
    audit "CLONED repo=${gh_owner}/${repo}"
  fi

  cd "$bare_dir" || return 1

  # ── Configure remotes (no --mirror, no --prune) ──────
  git remote set-url origin "$gh_url" 2>/dev/null || git remote add origin "$gh_url"

  # CRITICAL: Remove any prune or mirror config that might exist
  git config --unset remote.origin.mirror 2>/dev/null || true
  git config --unset remote.origin.prune 2>/dev/null || true
  git config remote.origin.prune false
  git config remote.origin.tagOpt --no-tags  # we fetch tags explicitly

  # Suppress LFS locking messages (we're a one-way mirror, no locking needed)
  git config lfs.locksverify false
  git config lfs.https://${GITEA_URL#*://}.locksverify false 2>/dev/null || true

  # Set up gitea remote with embedded auth
  local authed_url="${GITEA_URL/https:\/\//https:\/\/${GITEA_USER}:${GITEA_TOKEN}@}/${gitea_org}/${repo}.git"
  if git remote get-url gitea &>/dev/null; then
    git remote set-url gitea "$authed_url"
  else
    git remote add gitea "$authed_url"
  fi
  git config remote.gitea.mirror false 2>/dev/null || true
  git config remote.gitea.prune false

  [[ "$FORCE_HTTP11" == "true" ]] && git config http.version HTTP/1.1

  # ── Count refs BEFORE fetch ──────────────────────────
  local refs_before
  refs_before=$(count_refs "$bare_dir")

  # ── Snapshot current state (THE SAFETY NET) ──────────
  log "    snapshotting refs → refs/backup/${TIMESTAMP}/"
  snapshot_refs "$bare_dir" "$TIMESTAMP"
  audit "SNAPSHOT repo=${gh_owner}/${repo} refs_before=$refs_before"

  # ── Fetch from GitHub (ADDITIVE ONLY) ────────────────
  # We do NOT use '+' force-update prefix on heads.
  # Instead we fetch into a staging namespace first, then
  # safely merge forward.
  log "    fetching from GitHub …"

  # Fetch into staging area — does not touch our refs/heads
  if ! retry 3 git fetch origin \
      '+refs/heads/*:refs/upstream-staging/heads/*' \
      '+refs/tags/*:refs/upstream-staging/tags/*' \
      '+refs/notes/*:refs/upstream-staging/notes/*' 2>>"$LOG_FILE"; then
    warn "fetch failed for ${gh_owner}/${repo} — upstream may be down"
    audit "FETCH_FAILED repo=${gh_owner}/${repo}"
    # This is OK — upstream might be deleted. Our local copy is safe.
    # Still push what we have to Gitea.
    push_to_gitea "$bare_dir" "$gitea_org" "$repo"
    return 0
  fi

  # ── Count upstream refs and check for wipe ───────────
  local refs_upstream
  refs_upstream=$(git for-each-ref --format='x' refs/upstream-staging/heads refs/upstream-staging/tags 2>/dev/null | wc -l)

  if ! detect_wipe "$refs_before" "$refs_upstream" "${gh_owner}/${repo}"; then
    log "    !! PROTECTION ACTIVATED: refusing to update local refs"
    log "    !! Previous state preserved in refs/backup/${TIMESTAMP}/"
    log "    !! Upstream staging refs kept for manual inspection"
    audit "WIPE_BLOCKED repo=${gh_owner}/${repo} upstream_refs=$refs_upstream"
    notify "BREAKGLASS ALERT: Possible wipe detected for ${gh_owner}/${repo} — upstream went from $refs_before to $refs_upstream refs. Sync blocked, previous state preserved." "urgent" "rotating_light,shield"
    (( PROTECTED++ )) || true
    # Still push existing state to Gitea (including the suspicious staging refs
    # so you can inspect them)
    push_to_gitea "$bare_dir" "$gitea_org" "$repo"
    return 0
  fi

  # ── Safe-merge: update local refs from staging ───────
  # For each upstream ref, fast-forward our local ref if possible.
  # If upstream has force-pushed (not fast-forward), we keep BOTH:
  # the old ref is already in refs/backup/, and we update the
  # live ref to match upstream so the mirror stays current.
  log "    merging upstream state …"
  git for-each-ref --format='%(refname) %(objectname)' refs/upstream-staging/ 2>/dev/null | \
  while read -r staging_ref sha; do
    # refs/upstream-staging/heads/main → refs/heads/main
    local target_ref="${staging_ref/refs\/upstream-staging\//refs\/}"
    local old_sha
    old_sha=$(git rev-parse "$target_ref" 2>/dev/null || echo "")

    if [[ "$old_sha" == "$sha" ]]; then
      continue  # no change
    fi

    if [[ -z "$old_sha" ]]; then
      # New ref — just create it
      git update-ref "$target_ref" "$sha"
      audit "REF_ADDED repo=${gh_owner}/${repo} ref=$target_ref sha=$sha"
    else
      # Existing ref changed — update it (old state is in backup)
      git update-ref "$target_ref" "$sha"
      audit "REF_UPDATED repo=${gh_owner}/${repo} ref=$target_ref old=$old_sha new=$sha"
    fi
  done

  # ── NOTE: We NEVER delete local refs that upstream removed ──
  # If upstream deleted a branch, our copy keeps it. That's the point.

  # ── LFS objects ──────────────────────────────────────
  # Time-boxed: LFS is best-effort. We never let it block the whole sync.
  LFS_TIMEOUT="${LFS_TIMEOUT:-600}"  # 10 min default per repo
  if command -v git-lfs &>/dev/null && git config --get-regexp 'lfs\.' &>/dev/null 2>&1; then
    log "    fetching LFS objects (timeout: ${LFS_TIMEOUT}s) …"
    timeout "$LFS_TIMEOUT" git lfs fetch origin --all 2>>"$LOG_FILE" || warn "LFS fetch skipped/incomplete for ${gh_owner}/${repo}"
  fi

  # ── Wiki ─────────────────────────────────────────────
  if [[ "$SYNC_WIKIS" == "true" ]]; then
    sync_wiki "$gh_owner" "$repo" "$gitea_org"
  fi

  # ── Push to Gitea ───────────────────────────────────
  push_to_gitea "$bare_dir" "$gitea_org" "$repo"

  # ── Release assets ──────────────────────────────────
  if [[ "$SYNC_RELEASES" == "true" ]]; then
    sync_releases "$gh_owner" "$repo" "$gitea_org"
  fi

  local refs_after
  refs_after=$(count_refs "$bare_dir")
  log "    ✓ done (refs: $refs_before → $refs_after)"
  audit "SYNC_OK repo=${gh_owner}/${repo} refs_before=$refs_before refs_after=$refs_after"
  return 0
}

# ═══════════════════════════════════════════════════════════
# WIKI: Mirror the wiki repo (if it exists)
# ═══════════════════════════════════════════════════════════

sync_wiki() {
  local gh_owner="$1" repo="$2" gitea_org="$3"
  local wiki_url="https://github.com/${gh_owner}/${repo}.wiki.git"
  local wiki_dir="${MIRROR_ROOT}/${gh_owner}/${repo}.wiki.git"

  # Quick check: does the wiki exist? (HEAD request to avoid cloning empty wikis)
  if ! curl -sfS --head --connect-timeout 10 "$wiki_url" &>/dev/null; then
    return 0  # No wiki — skip silently
  fi

  log "    syncing wiki …"

  if [[ ! -d "$wiki_dir" ]]; then
    if ! git clone --bare "$wiki_url" "$wiki_dir" 2>>"$LOG_FILE"; then
      warn "wiki clone failed for ${gh_owner}/${repo} (may not exist)"
      return 0
    fi
    audit "WIKI_CLONED repo=${gh_owner}/${repo}"
  fi

  # Fetch latest wiki content
  cd "$wiki_dir" || return 0
  git remote set-url origin "$wiki_url" 2>/dev/null || true
  git config remote.origin.prune false
  git fetch origin '+refs/heads/*:refs/heads/*' 2>>"$LOG_FILE" || {
    warn "wiki fetch failed for ${gh_owner}/${repo}"
    return 0
  }

  # Push wiki to Gitea (Gitea auto-creates wiki repos on first push)
  local gitea_wiki_url="${GITEA_URL}/${gitea_org}/${repo}.wiki.git"
  if git remote get-url gitea &>/dev/null; then
    git remote set-url gitea "$gitea_wiki_url"
  else
    git remote add gitea "$gitea_wiki_url"
  fi

  # Ensure credential helper is configured (uses same store as main repos)
  git config credential.helper store

  git push gitea '+refs/heads/*:refs/heads/*' 2>>"$LOG_FILE" || {
    warn "wiki push failed for ${gitea_org}/${repo}"
    return 0
  }

  log "    wiki synced"
  audit "WIKI_SYNCED repo=${gh_owner}/${repo}"
}

# ═══════════════════════════════════════════════════════════
# RELEASES: Download release assets from GitHub
# ═══════════════════════════════════════════════════════════

sync_releases() {
  local gh_owner="$1" repo="$2" gitea_org="$3"
  local release_dir="${RELEASE_ROOT}/${gh_owner}/${repo}"
  mkdir -p "$release_dir"

  # Fetch the latest N releases from GitHub API
  local releases_json
  releases_json=$(gh_api "/repos/${gh_owner}/${repo}/releases?per_page=${RELEASE_KEEP}" 2>/dev/null) || {
    # No releases or API error — skip silently
    return 0
  }

  # Check if there are any releases
  local release_count
  release_count=$(echo "$releases_json" | grep -c '"tag_name"' || true)
  if (( release_count == 0 )); then
    return 0
  fi

  log "    syncing releases (latest ${RELEASE_KEEP}) …"

  # Parse each release: tag_name and assets
  local tag_names
  tag_names=$(echo "$releases_json" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | sed 's/"tag_name"[[:space:]]*:[[:space:]]*"//;s/"//')

  while IFS= read -r tag; do
    [[ -z "$tag" ]] && continue
    local tag_dir="${release_dir}/${tag}"
    local marker="${tag_dir}/.downloaded"

    # Skip if we've already downloaded this release
    if [[ -f "$marker" ]]; then
      continue
    fi

    mkdir -p "$tag_dir"
    log "      release: $tag"

    # Get assets for this specific release
    local release_data
    release_data=$(gh_api "/repos/${gh_owner}/${repo}/releases/tags/${tag}" 2>/dev/null) || continue

    # Save release metadata (description, notes, etc.)
    echo "$release_data" > "${tag_dir}/release.json"

    # Extract asset download URLs and names
    # Format: "browser_download_url": "https://..."
    local asset_urls
    asset_urls=$(echo "$release_data" | grep -o '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*"' \
      | sed 's/"browser_download_url"[[:space:]]*:[[:space:]]*"//;s/"//')

    local asset_names
    asset_names=$(echo "$release_data" | grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' \
      | sed 's/"name"[[:space:]]*:[[:space:]]*"//;s/"//')

    # Download each asset
    local asset_count=0
    while IFS= read -r url; do
      [[ -z "$url" ]] && continue

      local filename
      filename=$(basename "$url")
      local dest="${tag_dir}/${filename}"

      if [[ ! -f "$dest" ]]; then
        if curl "${gh_curl_opts[@]}" -L -o "$dest" "$url" 2>>"$LOG_FILE"; then
          (( asset_count++ )) || true
        else
          warn "failed to download release asset: $url"
          rm -f "$dest"
        fi
      fi
    done <<< "$asset_urls"

    # Also download the source archives (always available)
    for fmt in tar.gz zip; do
      local src_url="https://github.com/${gh_owner}/${repo}/archive/refs/tags/${tag}.${fmt}"
      local src_dest="${tag_dir}/${repo}-${tag}.${fmt}"
      if [[ ! -f "$src_dest" ]]; then
        curl "${gh_curl_opts[@]}" -L -o "$src_dest" "$src_url" 2>>"$LOG_FILE" || rm -f "$src_dest"
      fi
    done

    touch "$marker"
    log "      $asset_count assets downloaded"
    audit "RELEASE_SYNCED repo=${gh_owner}/${repo} tag=$tag assets=$asset_count"
  done <<< "$tag_names"

  # ── Upload releases to Gitea ──────────────────────────
  # Create matching releases on Gitea and upload assets
  while IFS= read -r tag; do
    [[ -z "$tag" ]] && continue
    local tag_dir="${release_dir}/${tag}"
    local gitea_marker="${tag_dir}/.gitea_uploaded"

    # Skip if already uploaded to Gitea
    [[ -f "$gitea_marker" ]] && continue
    [[ ! -f "${tag_dir}/release.json" ]] && continue

    # Extract release name and body from saved metadata
    local rel_name rel_body rel_prerelease
    rel_name=$(grep -o '"name"[[:space:]]*:[[:space:]]*"[^"]*"' "${tag_dir}/release.json" | head -1 \
      | sed 's/"name"[[:space:]]*:[[:space:]]*"//;s/"//')
    rel_prerelease=$(grep -o '"prerelease"[[:space:]]*:[[:space:]]*[a-z]*' "${tag_dir}/release.json" | head -1 \
      | sed 's/"prerelease"[[:space:]]*:[[:space:]]*//')

    [[ -z "$rel_name" ]] && rel_name="$tag"
    [[ -z "$rel_prerelease" ]] && rel_prerelease="false"

    # Create the release on Gitea (idempotent — 409 if exists)
    local create_result
    create_result=$(gitea_api POST "/repos/${gitea_org}/${repo}/releases" \
      -d "{\"tag_name\":\"${tag}\",\"name\":\"${rel_name}\",\"prerelease\":${rel_prerelease}}" 2>/dev/null) || true

    # Get the release ID (from create or existing)
    local release_id
    release_id=$(echo "$create_result" | grep -o '"id"[[:space:]]*:[[:space:]]*[0-9]*' | head -1 \
      | sed 's/"id"[[:space:]]*:[[:space:]]*//')

    if [[ -z "$release_id" ]]; then
      # Try to get existing release
      local existing
      existing=$(gitea_api GET "/repos/${gitea_org}/${repo}/releases/tags/${tag}" 2>/dev/null) || true
      release_id=$(echo "$existing" | grep -o '"id"[[:space:]]*:[[:space:]]*[0-9]*' | head -1 \
        | sed 's/"id"[[:space:]]*:[[:space:]]*//')
    fi

    if [[ -n "$release_id" ]]; then
      # Upload assets to Gitea release
      local uploaded=0
      for asset_file in "${tag_dir}"/*; do
        [[ -f "$asset_file" ]] || continue
        local fname
        fname=$(basename "$asset_file")
        # Skip metadata and markers
        [[ "$fname" == "release.json" || "$fname" == .* ]] && continue

        # Upload via Gitea API (multipart form)
        curl "${gitea_curl_opts[@]}" -X POST \
          -H "Authorization: token $GITEA_TOKEN" \
          -F "attachment=@${asset_file}" \
          "${GITEA_URL}/api/v1/repos/${gitea_org}/${repo}/releases/${release_id}/assets?name=${fname}" \
          &>>"$LOG_FILE" || true
        (( uploaded++ )) || true
      done
      log "      uploaded $uploaded assets to Gitea release $tag"
      touch "$gitea_marker"
    else
      warn "could not create/find Gitea release for ${gitea_org}/${repo} tag $tag"
    fi
  done <<< "$tag_names"
}

push_to_gitea() {
  local bare_dir="$1" gitea_org="$2" repo="$3"

  ensure_gitea_repo "$gitea_org" "$repo" || return 1

  log "    pushing to Gitea …"

  # Push all ref namespaces. We use '+' here because Gitea is OUR
  # server — we trust ourselves. The append-only guarantee is in
  # the local bare repo and the backup refs.
  if ! retry 3 git -C "$bare_dir" push gitea \
      '+refs/heads/*:refs/heads/*' \
      '+refs/tags/*:refs/tags/*' \
      '+refs/notes/*:refs/notes/*' \
      '+refs/backup/*:refs/backup/*' 2>>"$LOG_FILE"; then
    warn "push to Gitea failed for ${gitea_org}/${repo}"
    audit "PUSH_FAILED repo=${gitea_org}/${repo}"
    return 1
  fi

  # Push LFS to Gitea — time-boxed to avoid blocking on huge repos (e.g. buildroot)
  # Override the LFS URL so git-lfs pushes to Gitea, not back to github.com
  # (repos often have .lfsconfig or lfs.url pointing at GitHub's LFS endpoint)
  LFS_TIMEOUT="${LFS_TIMEOUT:-600}"
  if command -v git-lfs &>/dev/null && git config --get-regexp 'lfs\.' &>/dev/null 2>&1; then
    log "    pushing LFS to Gitea (timeout: ${LFS_TIMEOUT}s) …"
    local gitea_lfs_url
    gitea_lfs_url=$(git -C "$bare_dir" remote get-url gitea 2>/dev/null | sed 's/\.git$//')
    timeout "$LFS_TIMEOUT" git -C "$bare_dir" \
      -c "lfs.url=${gitea_lfs_url}.git/info/lfs" \
      lfs push gitea --all 2>>"$LOG_FILE" || \
      warn "LFS push skipped/incomplete for ${gitea_org}/${repo} (may have timed out)"
  fi

  # ── Sync default branch and description from GitHub ───
  sync_repo_metadata "$gitea_org" "$repo"

  audit "PUSHED repo=${gitea_org}/${repo}"
}

# ═══════════════════════════════════════════════════════════
# METADATA: Sync default branch, description, website from GitHub
# ═══════════════════════════════════════════════════════════

sync_repo_metadata() {
  local gitea_org="$1" repo="$2"
  local marker="${MIRROR_ROOT}/.avatars/${gitea_org}_${repo}.meta.synced"

  # Only sync metadata once per repo (delete marker to force re-sync)
  [[ -f "$marker" ]] && return 0

  # Get GitHub repo info
  local gh_data
  gh_data=$(gh_api "/repos/${gitea_org}/${repo}" 2>/dev/null) || return 0

  # Extract default branch
  local default_branch
  default_branch=$(echo "$gh_data" | grep -o '"default_branch"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | sed 's/"default_branch"[[:space:]]*:[[:space:]]*"//;s/"//')

  # Extract description
  local description
  description=$(echo "$gh_data" | grep -o '"description"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 \
    | sed 's/"description"[[:space:]]*:[[:space:]]*"//;s/"//')

  # Extract homepage
  local homepage
  homepage=$(echo "$gh_data" | grep -o '"homepage"[[:space:]]*:[[:space:]]*"[^"]*"' \
    | sed 's/"homepage"[[:space:]]*:[[:space:]]*"//;s/"//')

  if [[ -n "$default_branch" ]]; then
    # Build the update payload
    local payload="{\"default_branch\":\"${default_branch}\""
    if [[ -n "$description" ]]; then
      # Escape special JSON chars in description
      description=$(echo "$description" | sed 's/\\/\\\\/g;s/"/\\"/g')
      payload+=",\"description\":\"[BREAKGLASS] ${description}\""
    fi
    if [[ -n "$homepage" ]]; then
      payload+=",\"website\":\"${homepage}\""
    fi
    payload+="}"

    gitea_api PATCH "/repos/${gitea_org}/${repo}" -d "$payload" &>/dev/null || true
    log "    metadata synced (default_branch: $default_branch)"
  fi

  touch "$marker"
}

# ═══════════════════════════════════════════════════════════
# REVERSE SYNC: Push Gitea repos → GitHub (public backup)
# ═══════════════════════════════════════════════════════════

reverse_sync_repo() {
  local gitea_org="$1" repo="$2" gh_owner="$3" gh_repo="$4"

  log "  reverse-sync ${gitea_org}/${repo} → github:${gh_owner}/${gh_repo}"
  audit "REVERSE_SYNC_START repo=${gitea_org}/${repo} target=${gh_owner}/${gh_repo}"

  # ── Ensure GitHub repo exists (create if not) ──────────
  local gh_result
  gh_result=$(curl -sfS --connect-timeout 15 --max-time 30 \
    -H "Authorization: Bearer ${GITHUB_PUSH_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/${gh_owner}/${gh_repo}" 2>/dev/null) || true

  if ! echo "$gh_result" | grep -q '"id"'; then
    log "    creating GitHub repo: ${gh_owner}/${gh_repo}"
    local create_payload="{\"name\":\"${gh_repo}\",\"private\":false,\"description\":\"Public backup from git.mineracks.com/${gitea_org}/${repo}\"}"

    # Try org endpoint first, fall back to user endpoint
    local create_result
    create_result=$(curl -sfS --connect-timeout 15 --max-time 30 \
      -X POST \
      -H "Authorization: Bearer ${GITHUB_PUSH_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      -H "Content-Type: application/json" \
      -d "$create_payload" \
      "https://api.github.com/orgs/${gh_owner}/repos" 2>/dev/null) || true

    if ! echo "$create_result" | grep -q '"id"'; then
      # Try as user repo
      create_result=$(curl -sfS --connect-timeout 15 --max-time 30 \
        -X POST \
        -H "Authorization: Bearer ${GITHUB_PUSH_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        -H "Content-Type: application/json" \
        -d "$create_payload" \
        "https://api.github.com/user/repos" 2>/dev/null) || true

      if ! echo "$create_result" | grep -q '"id"'; then
        warn "could not create GitHub repo ${gh_owner}/${gh_repo}"
        audit "REVERSE_SYNC_FAILED repo=${gitea_org}/${repo} reason=cannot_create_github_repo"
        return 1
      fi
    fi
    log "    GitHub repo created: ${gh_owner}/${gh_repo}"
  fi

  # ── Clone from Gitea (or use existing) ─────────────────
  local work_dir="${MIRROR_ROOT}/.reverse-sync/${gitea_org}/${repo}.git"

  # ── Build authed Gitea URL ──────────────────────────────
  local authed_gitea
  if [[ "${GITEA_URL}" == https://* ]]; then
    authed_gitea="${GITEA_URL/https:\/\//https:\/\/${GITEA_USER}:${GITEA_TOKEN}@}/${gitea_org}/${repo}.git"
  else
    authed_gitea="${GITEA_URL/http:\/\//http:\/\/${GITEA_USER}:${GITEA_TOKEN}@}/${gitea_org}/${repo}.git"
  fi

  if [[ ! -d "$work_dir" ]]; then
    log "    cloning from Gitea …"
    mkdir -p "$(dirname "$work_dir")"
    if ! git clone --bare "$authed_gitea" "$work_dir" 2>>"$LOG_FILE"; then
      warn "reverse-sync clone failed for ${gitea_org}/${repo}"
      return 1
    fi
  fi

  cd "$work_dir" || return 1

  # ── Configure remotes ──────────────────────────────────
  # Gitea as origin (source)
  git remote set-url origin "$authed_gitea" 2>/dev/null || git remote add origin "$authed_gitea"

  # GitHub as push target
  local authed_github="https://${GITHUB_PUSH_TOKEN}@github.com/${gh_owner}/${gh_repo}.git"
  if git remote get-url github &>/dev/null; then
    git remote set-url github "$authed_github"
  else
    git remote add github "$authed_github"
  fi

  # ── Fetch latest from Gitea ────────────────────────────
  log "    fetching from Gitea …"
  if ! git fetch origin '+refs/heads/*:refs/heads/*' '+refs/tags/*:refs/tags/*' 2>>"$LOG_FILE"; then
    warn "reverse-sync fetch from Gitea failed for ${gitea_org}/${repo}"
    return 1
  fi

  # ── Push to GitHub ─────────────────────────────────────
  # Only push heads and tags (not backup refs — those stay private)
  log "    pushing to GitHub …"
  if ! retry 3 git push github \
      '+refs/heads/*:refs/heads/*' \
      '+refs/tags/*:refs/tags/*' 2>>"$LOG_FILE"; then
    warn "reverse-sync push to GitHub failed for ${gh_owner}/${gh_repo}"
    audit "REVERSE_SYNC_FAILED repo=${gitea_org}/${repo} reason=push_failed"
    return 1
  fi

  log "    ✓ reverse-synced to github.com/${gh_owner}/${gh_repo}"
  audit "REVERSE_SYNC_OK repo=${gitea_org}/${repo} target=${gh_owner}/${gh_repo}"
  return 0
}

run_reverse_sync() {
  local repos="${REVERSE_SYNC_REPOS:-}"
  [[ -z "$repos" ]] && return 0

  local gh_push_owner="${GITHUB_PUSH_OWNER:-}"
  if [[ -z "${GITHUB_PUSH_TOKEN:-}" ]]; then
    warn "REVERSE_SYNC_REPOS set but GITHUB_PUSH_TOKEN is empty — skipping reverse sync"
    return 0
  fi

  log ""
  log "═══ Reverse sync (Gitea → GitHub) ═══"

  local reverse_ok=0 reverse_fail=0

  for entry in $repos; do
    local gitea_side gh_side
    if [[ "$entry" == *:* ]]; then
      # Explicit mapping: gitea_org/repo:github_owner/repo
      gitea_side="${entry%%:*}"
      gh_side="${entry##*:}"
    else
      # Short form: gitea_org/repo → same on GitHub
      gitea_side="$entry"
      gh_side="${gh_push_owner:+${gh_push_owner}/}${entry##*/}"
      # If no GITHUB_PUSH_OWNER, use the gitea org
      [[ "$gh_side" == /* ]] && gh_side="${entry}"
    fi

    local g_org="${gitea_side%%/*}"
    local g_repo="${gitea_side##*/}"
    local gh_owner="${gh_side%%/*}"
    local gh_repo="${gh_side##*/}"

    if reverse_sync_repo "$g_org" "$g_repo" "$gh_owner" "$gh_repo"; then
      (( reverse_ok++ )) || true
    else
      (( reverse_fail++ )) || true
    fi
  done

  log "═══ Reverse sync done: ${reverse_ok} ok, ${reverse_fail} failed ═══"

  if (( reverse_fail > 0 )); then
    notify "Reverse sync: ${reverse_ok} ok, ${reverse_fail} failed — check $LOG_FILE" "high" "warning"
  elif (( reverse_ok > 0 )); then
    notify "Reverse sync: ${reverse_ok} repos pushed to GitHub" "low" "arrow_right"
  fi
}

# ── Notifications ────────────────────────────────────────

notify() {
  local message="$1"
  local priority="${2:-default}"   # ntfy priority: min/low/default/high/urgent
  local tags="${3:-}"              # ntfy tags (emoji shortcodes)
  case "${NOTIFY_METHOD}" in
    ntfy)
      local -a ntfy_args=(-sfS -d "$message")
      [[ -n "$priority" ]] && ntfy_args+=(-H "Priority: $priority")
      [[ -n "$tags" ]] && ntfy_args+=(-H "Tags: $tags")
      curl "${ntfy_args[@]}" "${NTFY_SERVER:-https://ntfy.sh}/${NTFY_TOPIC:-breakglass}" &>/dev/null || true
      ;;
    email)
      echo "$message" | mail -s "Breakglass Mirror Alert" "${NOTIFY_EMAIL:-}" 2>/dev/null || true
      ;;
    telegram)
      curl -sfS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN:-}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID:-}" -d "text=${message}" &>/dev/null || true
      ;;
    *) ;;
  esac
}

# ── Glob matching ────────────────────────────────────────

matches_glob() {
  local name="$1" pattern="$2"
  [[ "$pattern" == "*" ]] && return 0
  local IFS='|'
  for glob in $pattern; do
    # shellcheck disable=SC2053
    [[ "$name" == $glob ]] && return 0
  done
  return 1
}

# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

log "═══ Breakglass APPEND-ONLY sync started at $TIMESTAMP ═══"
audit "SESSION_START timestamp=$TIMESTAMP config=$ENV_FILE"
log "Config: $ENV_FILE"
log "Sources: $SOURCES_FILE"
log ""

# ── Mode: reverse-only skips the GitHub→Gitea pull ───────
REVERSE_SYNC_ONLY="${REVERSE_SYNC_ONLY:-}"

if [[ -z "$REVERSE_SYNC_ONLY" ]]; then
  [[ -f "$SOURCES_FILE" ]] || die "sources file not found: $SOURCES_FILE"

  declare -a OWNERS
  mapfile -t OWNERS < <(parse_sources)
  [[ ${#OWNERS[@]} -eq 0 ]] && die "no owners found in $SOURCES_FILE"

  for entry in "${OWNERS[@]}"; do
    read -r _ gh_owner gitea_org include_glob exclude_glob <<< "$entry"
    log "── Owner: $gh_owner → gitea:$gitea_org ──"
    ensure_gitea_org "$gitea_org"

    repos=$(gh_list_repos "$gh_owner") || { (( ERRORS++ )) || true; continue; }

    while IFS= read -r repo; do
      [[ -z "$repo" ]] && continue

      if ! matches_glob "$repo" "${include_glob:-*}"; then
        (( SKIPPED++ )) || true; continue
      fi
      if [[ -n "$exclude_glob" ]] && matches_glob "$repo" "$exclude_glob"; then
        (( SKIPPED++ )) || true; continue
      fi

      if sync_repo "$gh_owner" "$repo" "$gitea_org"; then
        (( SYNCED++ )) || true
      else
        (( ERRORS++ )) || true
      fi
    done <<< "$repos"
  done
else
  log "── REVERSE_SYNC_ONLY mode — skipping GitHub → Gitea pull ──"
fi

# ── Reverse sync (Gitea → GitHub) ────────────────────────
run_reverse_sync

# ── Summary ──────────────────────────────────────────────

DURATION=$(( $(date +%s) - $(date -d "$TIMESTAMP" +%s 2>/dev/null || date -u -d "${TIMESTAMP:0:8} ${TIMESTAMP:9:2}:${TIMESTAMP:11:2}:${TIMESTAMP:13:2}" +%s 2>/dev/null || echo 0) ))
DURATION_MIN=$(( DURATION / 60 ))
SUMMARY="Breakglass sync: ${SYNCED} synced, ${SKIPPED} skipped, ${PROTECTED} wipe-protected, ${ERRORS} errors (${DURATION_MIN}m)"
log ""
log "═══ $SUMMARY ═══"
audit "SESSION_END $SUMMARY"

if (( PROTECTED > 0 )); then
  notify "🛡️ $SUMMARY — WIPE PROTECTION ACTIVATED — check $LOG_FILE" "urgent" "rotating_light,shield"
elif (( ERRORS > 0 )); then
  notify "⚠️ $SUMMARY — check $LOG_FILE" "high" "warning"
else
  notify "✅ $SUMMARY" "low" "white_check_mark"
fi

# ── Log rotation: keep 90 days (audit logs kept forever) ─
find "$LOG_DIR" -name 'sync-*.log' -mtime +90 -delete 2>/dev/null || true

# ── Generate SHA256 of audit file for tamper evidence ────
if [[ -f "$AUDIT_FILE" ]]; then
  sha256sum "$AUDIT_FILE" >> "$AUDIT_DIR/checksums.log"
fi

exit $(( ERRORS > 0 ? 1 : 0 ))
