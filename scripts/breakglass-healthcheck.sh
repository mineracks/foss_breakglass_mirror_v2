#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# breakglass-healthcheck.sh — integrity & freshness checks
# ═══════════════════════════════════════════════════════════
# Checks:
#   1. Gitea reachable
#   2. Sync timer active
#   3. Recent sync logs exist
#   4. No repos are stale (FETCH_HEAD age)
#   5. Backup refs exist and are growing (append-only proof)
#   6. Audit log checksums haven't been tampered with
#   7. Local bare repos have not lost refs (deletion detection)
# ═══════════════════════════════════════════════════════════
set -euo pipefail

ENV_FILE="${BREAKGLASS_ENV:-/etc/breakglass/mirror.env}"
[[ -f "$ENV_FILE" ]] || { echo "FATAL: $ENV_FILE not found" >&2; exit 1; }
# shellcheck source=/dev/null
source "$ENV_FILE"

MIRROR_ROOT="${MIRROR_ROOT:-/var/lib/breakglass/repos}"
LOG_DIR="${LOG_DIR:-/var/log/breakglass}"
AUDIT_DIR="${AUDIT_DIR:-/var/lib/breakglass/audit}"
STALE_DAYS="${STALE_DAYS:-7}"
NOTIFY_METHOD="${NOTIFY_METHOD:-none}"

PROBLEMS=()
WARNINGS=()

log() { printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*"; }

notify() {
  local message="$1"
  local priority="${2:-default}"
  local tags="${3:-}"
  case "${NOTIFY_METHOD}" in
    ntfy)
      local -a ntfy_args=(-sfS -d "$message")
      [[ -n "$priority" ]] && ntfy_args+=(-H "Priority: $priority")
      [[ -n "$tags" ]] && ntfy_args+=(-H "Tags: $tags")
      curl "${ntfy_args[@]}" "${NTFY_SERVER:-https://ntfy.sh}/${NTFY_TOPIC:-breakglass}" &>/dev/null || true
      ;;
    email)
      echo "$message" | mail -s "Breakglass Health Alert" "${NOTIFY_EMAIL:-}" 2>/dev/null || true
      ;;
    telegram)
      curl -sfS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN:-}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID:-}" -d "text=${message}" &>/dev/null || true
      ;;
    *) ;;
  esac
}

# ── Check 1: Gitea reachable ────────────────────────────
log "Check 1: Gitea connectivity …"
if ! curl -sfS --connect-timeout 10 "${GITEA_URL}/api/v1/version" &>/dev/null; then
  PROBLEMS+=("Gitea at ${GITEA_URL} is unreachable")
  log "  FAIL"
else
  log "  OK"
fi

# ── Check 2: Sync timer active ──────────────────────────
log "Check 2: Sync timer …"
if systemctl is-active --quiet breakglass-sync.timer 2>/dev/null; then
  log "  OK"
else
  PROBLEMS+=("breakglass-sync.timer is not active")
  log "  FAIL"
fi

# ── Check 3: Recent sync log ────────────────────────────
log "Check 3: Recent sync logs …"
LATEST_LOG=$(find "$LOG_DIR" -name 'sync-*.log' -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | awk '{print $2}')
if [[ -z "$LATEST_LOG" ]]; then
  PROBLEMS+=("No sync logs found in $LOG_DIR")
  log "  FAIL"
else
  LOG_AGE_DAYS=$(( ( $(date +%s) - $(stat -c %Y "$LATEST_LOG") ) / 86400 ))
  if (( LOG_AGE_DAYS > STALE_DAYS )); then
    PROBLEMS+=("Last sync log is ${LOG_AGE_DAYS} days old")
    log "  WARN: ${LOG_AGE_DAYS}d old"
  else
    log "  OK: ${LOG_AGE_DAYS}d old"
  fi
fi

# ── Check 4: Repo freshness ─────────────────────────────
log "Check 4: Repo freshness (threshold: ${STALE_DAYS}d) …"
STALE_THRESHOLD=$(( $(date +%s) - STALE_DAYS * 86400 ))
REPO_COUNT=0
STALE_COUNT=0

if [[ -d "$MIRROR_ROOT" ]]; then
  while IFS= read -r bare_dir; do
    [[ -d "$bare_dir" ]] || continue
    (( REPO_COUNT++ ))

    repo_name="${bare_dir#${MIRROR_ROOT}/}"
    repo_name="${repo_name%.git}"

    fetch_head="$bare_dir/FETCH_HEAD"
    if [[ -f "$fetch_head" ]]; then
      last_fetch=$(stat -c %Y "$fetch_head")
      if (( last_fetch < STALE_THRESHOLD )); then
        days_stale=$(( ( $(date +%s) - last_fetch ) / 86400 ))
        WARNINGS+=("${repo_name}: last fetched ${days_stale}d ago")
        (( STALE_COUNT++ ))
        log "  STALE: $repo_name (${days_stale}d)"
      fi
    else
      WARNINGS+=("${repo_name}: no FETCH_HEAD")
      log "  WARN: $repo_name has no FETCH_HEAD"
    fi
  done < <(find "$MIRROR_ROOT" -maxdepth 3 -name 'HEAD' -execdir pwd \;)
fi
log "  $REPO_COUNT repos checked, $STALE_COUNT stale"

# ── Check 5: Backup refs exist (append-only proof) ──────
log "Check 5: Backup ref integrity …"
REPOS_WITHOUT_BACKUPS=0

if [[ -d "$MIRROR_ROOT" ]]; then
  while IFS= read -r bare_dir; do
    [[ -d "$bare_dir" ]] || continue
    repo_name="${bare_dir#${MIRROR_ROOT}/}"
    repo_name="${repo_name%.git}"

    backup_count=$(git -C "$bare_dir" for-each-ref --format='x' refs/backup/ 2>/dev/null | wc -l)
    if (( backup_count == 0 )); then
      WARNINGS+=("${repo_name}: no backup refs — append-only not working?")
      (( REPOS_WITHOUT_BACKUPS++ ))
      log "  WARN: $repo_name has no backup refs"
    fi
  done < <(find "$MIRROR_ROOT" -maxdepth 3 -name 'HEAD' -execdir pwd \;)
fi
if (( REPOS_WITHOUT_BACKUPS > 0 )); then
  log "  $REPOS_WITHOUT_BACKUPS repos missing backup refs"
else
  log "  OK: all repos have backup refs"
fi

# ── Check 6: Audit log checksums ────────────────────────
log "Check 6: Audit log integrity …"
CHECKSUM_FILE="$AUDIT_DIR/checksums.log"
if [[ -f "$CHECKSUM_FILE" ]]; then
  TAMPERED=0
  while read -r expected_hash filepath; do
    if [[ -f "$filepath" ]]; then
      actual_hash=$(sha256sum "$filepath" | awk '{print $1}')
      if [[ "$actual_hash" != "$expected_hash" ]]; then
        PROBLEMS+=("TAMPERED audit log: $filepath")
        (( TAMPERED++ ))
      fi
    fi
  done < "$CHECKSUM_FILE"
  if (( TAMPERED > 0 )); then
    log "  FAIL: $TAMPERED tampered audit files"
  else
    log "  OK"
  fi
else
  log "  SKIP: no checksums yet (first run?)"
fi

# ── Check 7: Ref count file — detect local ref deletion ─
log "Check 7: Ref count stability …"
REF_COUNT_FILE="$AUDIT_DIR/ref-counts.dat"

if [[ -d "$MIRROR_ROOT" ]]; then
  CURRENT_COUNTS=$(mktemp)
  while IFS= read -r bare_dir; do
    [[ -d "$bare_dir" ]] || continue
    repo_name="${bare_dir#${MIRROR_ROOT}/}"
    repo_name="${repo_name%.git}"
    count=$(git -C "$bare_dir" for-each-ref --format='x' refs/heads refs/tags refs/notes refs/backup 2>/dev/null | wc -l)
    echo "$repo_name $count" >> "$CURRENT_COUNTS"
  done < <(find "$MIRROR_ROOT" -maxdepth 3 -name 'HEAD' -execdir pwd \;)

  if [[ -f "$REF_COUNT_FILE" ]]; then
    while read -r repo prev_count; do
      curr_count=$(grep "^${repo} " "$CURRENT_COUNTS" 2>/dev/null | awk '{print $2}')
      if [[ -n "$curr_count" ]] && (( curr_count < prev_count )); then
        PROBLEMS+=("${repo}: ref count DECREASED ($prev_count → $curr_count) — possible local tampering")
        log "  ALERT: $repo refs decreased $prev_count → $curr_count"
      fi
    done < "$REF_COUNT_FILE"
  fi

  # Save current counts for next run
  cp "$CURRENT_COUNTS" "$REF_COUNT_FILE"
  rm -f "$CURRENT_COUNTS"
  log "  OK"
fi

# ── Check 8: Disk space ─────────────────────────────────
log "Check 8: Disk space …"
DISK_WARN_PCT="${DISK_WARN_PCT:-80}"
DISK_CRIT_PCT="${DISK_CRIT_PCT:-90}"
DISK_USE_PCT=$(df --output=pcent "$MIRROR_ROOT" 2>/dev/null | tail -1 | tr -dc '0-9')
DISK_AVAIL=$(df -h --output=avail "$MIRROR_ROOT" 2>/dev/null | tail -1 | xargs)

if [[ -n "$DISK_USE_PCT" ]]; then
  if (( DISK_USE_PCT >= DISK_CRIT_PCT )); then
    PROBLEMS+=("Disk ${DISK_USE_PCT}% full (${DISK_AVAIL} free) — mirrors at risk")
    log "  CRITICAL: ${DISK_USE_PCT}% used, ${DISK_AVAIL} free"
  elif (( DISK_USE_PCT >= DISK_WARN_PCT )); then
    WARNINGS+=("Disk ${DISK_USE_PCT}% full (${DISK_AVAIL} free) — consider expanding")
    log "  WARN: ${DISK_USE_PCT}% used, ${DISK_AVAIL} free"
  else
    log "  OK: ${DISK_USE_PCT}% used, ${DISK_AVAIL} free"
  fi
else
  log "  SKIP: could not read disk usage"
fi

# ── Report ───────────────────────────────────────────────
log ""
TOTAL_ISSUES=$(( ${#PROBLEMS[@]} + ${#WARNINGS[@]} ))

if [[ ${#PROBLEMS[@]} -eq 0 && ${#WARNINGS[@]} -eq 0 ]]; then
  log "═══ Health check PASSED — all mirrors healthy ═══"
  exit 0
fi

if [[ ${#PROBLEMS[@]} -gt 0 ]]; then
  log "═══ Health check FAILED — ${#PROBLEMS[@]} critical issue(s): ═══"
  REPORT="BREAKGLASS HEALTH ALERT: ${#PROBLEMS[@]} critical, ${#WARNINGS[@]} warnings\n\nCRITICAL:\n"
  for p in "${PROBLEMS[@]}"; do
    log "  ✗ $p"
    REPORT+="✗ ${p}\n"
  done
fi

if [[ ${#WARNINGS[@]} -gt 0 ]]; then
  log "  ${#WARNINGS[@]} warning(s):"
  REPORT="${REPORT:-}WARNINGS:\n"
  for w in "${WARNINGS[@]}"; do
    log "  ⚠ $w"
    REPORT+="⚠ ${w}\n"
  done
fi

if [[ ${#PROBLEMS[@]} -gt 0 ]]; then
  notify "$(echo -e "${REPORT:-Health check completed with issues}")" "high" "warning,stethoscope"
else
  notify "$(echo -e "${REPORT:-Health check completed with warnings}")" "default" "stethoscope"
fi
exit $(( ${#PROBLEMS[@]} > 0 ? 1 : 0 ))
