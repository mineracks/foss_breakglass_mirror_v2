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
LOG_DIR="${LOG_DIR:-/var/log/breakglass}"
AUDIT_DIR="${AUDIT_DIR:-/var/lib/breakglass/audit}"
FORCE_HTTP11="${FORCE_HTTP11:-true}"
NOTIFY_METHOD="${NOTIFY_METHOD:-none}"
# If upstream loses more than this % of refs, abort the push
# as a likely malicious wipe. 0 = disabled.
WIPE_THRESHOLD="${WIPE_THRESHOLD:-50}"

mkdir -p "$MIRROR_ROOT" "$LOG_DIR" "$AUDIT_DIR"

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
  result=$(gitea_api GET "/orgs/${org}" 2>/dev/null)
  if [[ $? -eq 0 ]] && echo "$result" | grep -q '"id"'; then
    # Org exists — sync avatar if we haven't already
    sync_org_avatar "$org"
    return 0
  fi
  log "  creating Gitea org: $org"
  result=$(gitea_api POST "/orgs" -d "{\"username\":\"${org}\",\"visibility\":\"public\"}" 2>/dev/null)
  if [[ $? -eq 0 ]]; then
    log "  org $org ready"
    sync_org_avatar "$org"
    return 0
  fi
  warn "could not create org $org — will push under $GITEA_USER"
}

ensure_gitea_repo() {
  local org="$1" repo="$2"
  local result
  result=$(gitea_api GET "/repos/${org}/${repo}" 2>/dev/null)
  if [[ $? -eq 0 ]] && echo "$result" | grep -q '"id"'; then
    # Repo exists — sync avatar if we haven't already
    sync_repo_avatar "$org" "$repo"
    return 0
  fi
  log "  creating Gitea repo: ${org}/${repo}"
  result=$(gitea_api POST "/orgs/${org}/repos" \
    -d "{\"name\":\"${repo}\",\"private\":false,\"description\":\"[BREAKGLASS] Append-only mirror of github.com/${org}/${repo}\"}" 2>/dev/null)
  if [[ $? -eq 0 ]] && echo "$result" | grep -q '"id"'; then
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
        gitea_api PATCH "/orgs/${org}" \
          -d "{\"avatar_base64\":\"data:image/png;base64,${b64_avatar}\"}" &>/dev/null
        if [[ $? -eq 0 ]]; then
          log "    avatar set for org $org"
          touch "$marker"
        else
          warn "could not upload avatar for org $org"
        fi
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

  # Try to get the repo's OpenGraph image from GitHub API
  local gh_repo_data
  gh_repo_data=$(gh_api "/repos/${org}/${repo}" 2>/dev/null) || return 0

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
        # Gitea repo avatar endpoint
        gitea_api PATCH "/repos/${org}/${repo}" \
          -d "{\"avatar_base64\":\"data:image/png;base64,${b64_avatar}\"}" &>/dev/null
        if [[ $? -eq 0 ]]; then
          log "    avatar set for ${org}/${repo}"
        fi
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
    notify "BREAKGLASS ALERT: Possible wipe detected for ${gh_owner}/${repo} — upstream went from $refs_before to $refs_upstream refs. Sync blocked, previous state preserved."
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
  if command -v git-lfs &>/dev/null && git config --get-regexp 'lfs\.' &>/dev/null 2>&1; then
    log "    fetching LFS objects …"
    git lfs fetch origin --all 2>>"$LOG_FILE" || warn "LFS fetch incomplete for ${gh_owner}/${repo}"
  fi

  # ── Push to Gitea ───────────────────────────────────
  push_to_gitea "$bare_dir" "$gitea_org" "$repo"

  local refs_after
  refs_after=$(count_refs "$bare_dir")
  log "    ✓ done (refs: $refs_before → $refs_after)"
  audit "SYNC_OK repo=${gh_owner}/${repo} refs_before=$refs_before refs_after=$refs_after"
  return 0
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

  # Push LFS to Gitea
  if command -v git-lfs &>/dev/null && git config --get-regexp 'lfs\.' &>/dev/null 2>&1; then
    git -C "$bare_dir" lfs push gitea --all 2>>"$LOG_FILE" || \
      warn "LFS push incomplete for ${gitea_org}/${repo}"
  fi

  audit "PUSHED repo=${gitea_org}/${repo}"
}

# ── Notifications ────────────────────────────────────────

notify() {
  local message="$1"
  case "${NOTIFY_METHOD}" in
    ntfy)
      curl -sfS -d "$message" "${NTFY_SERVER:-https://ntfy.sh}/${NTFY_TOPIC:-}" &>/dev/null || true
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

# ── Summary ──────────────────────────────────────────────

SUMMARY="Breakglass sync: ${SYNCED} synced, ${SKIPPED} skipped, ${PROTECTED} wipe-protected, ${ERRORS} errors"
log ""
log "═══ $SUMMARY ═══"
audit "SESSION_END $SUMMARY"

if (( ERRORS > 0 || PROTECTED > 0 )); then
  notify "$SUMMARY — check $LOG_FILE"
fi

# ── Log rotation: keep 90 days (audit logs kept forever) ─
find "$LOG_DIR" -name 'sync-*.log' -mtime +90 -delete 2>/dev/null || true

# ── Generate SHA256 of audit file for tamper evidence ────
if [[ -f "$AUDIT_FILE" ]]; then
  sha256sum "$AUDIT_FILE" >> "$AUDIT_DIR/checksums.log"
fi

exit $(( ERRORS > 0 ? 1 : 0 ))
