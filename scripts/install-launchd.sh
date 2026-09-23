#!/usr/bin/env bash
# Install (or --uninstall) the shared es-mcp HTTP server as a launchd agent.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ES_MCP_BIN="$REPO_ROOT/.venv/bin/es-mcp"
PORT="${ES_MCP_HTTP_PORT:-7719}"
LABEL="com.es-mcp.http"
DOMAIN="gui/$(id -u)"
SERVICE_TARGET="$DOMAIN/$LABEL"
PLIST_DEST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG_DIR="$HOME/Library/Logs/es-mcp"

stop_service() {
  launchctl bootout "$SERVICE_TARGET" 2>/dev/null || true
  for ((attempt = 0; attempt < 50; attempt++)); do
    if ! launchctl print "$SERVICE_TARGET" >/dev/null 2>&1; then return 0; fi
    sleep 0.2
  done
  return 1
}

if [[ "${1:-}" == "--uninstall" ]]; then
  stop_service
  rm -f "$PLIST_DEST"
  echo "$LABEL removed"
  exit 0
fi

if [[ ! -x "$ES_MCP_BIN" ]]; then
  echo "error: $ES_MCP_BIN not found; run 'uv sync' in $REPO_ROOT first" >&2
  exit 1
fi

mkdir -p "$LOG_DIR" "$(dirname "$PLIST_DEST")"
PLIST_TMP="$(mktemp "$(dirname "$PLIST_DEST")/.es-mcp.plist.XXXXXX")"
PLIST_BACKUP=""
cleanup() {
  rm -f "$PLIST_TMP"
  if [[ -n "$PLIST_BACKUP" ]]; then rm -f "$PLIST_BACKUP"; fi
}
trap cleanup EXIT

sed -e "s|__ES_MCP__|$ES_MCP_BIN|g" \
    -e "s|__PORT__|$PORT|g" \
    -e "s|__LOG_DIR__|$LOG_DIR|g" \
    "$REPO_ROOT/launchd/$LABEL.plist" > "$PLIST_TMP"
plutil -lint "$PLIST_TMP" >/dev/null

if [[ -f "$PLIST_DEST" ]]; then
  PLIST_BACKUP="$(mktemp "$(dirname "$PLIST_DEST")/.es-mcp.backup.XXXXXX")"
  cp "$PLIST_DEST" "$PLIST_BACKUP"
fi

restore_previous() {
  stop_service || true
  if [[ -n "$PLIST_BACKUP" ]]; then
    cp "$PLIST_BACKUP" "$PLIST_DEST"
    launchctl bootstrap "$DOMAIN" "$PLIST_DEST" >/dev/null 2>&1 || true
  else
    rm -f "$PLIST_DEST"
  fi
}

if ! stop_service; then
  echo "error: $LABEL did not stop; left the previous agent in place" >&2
  exit 1
fi
mv "$PLIST_TMP" "$PLIST_DEST"
if ! launchctl bootstrap "$DOMAIN" "$PLIST_DEST"; then
  restore_previous
  echo "error: could not bootstrap $LABEL; restored the previous agent" >&2
  exit 1
fi

for ((attempt = 0; attempt < 50; attempt++)); do
  if launchctl print "$SERVICE_TARGET" 2>/dev/null | grep -q 'state = running' \
    && curl -fsS --max-time 1 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    echo "$LABEL running: http://127.0.0.1:$PORT/mcp"
    echo "logs: $LOG_DIR"
    exit 0
  fi
  sleep 0.2
done

restore_previous
echo "error: $LABEL did not become healthy; restored the previous agent (see $LOG_DIR)" >&2
exit 1
