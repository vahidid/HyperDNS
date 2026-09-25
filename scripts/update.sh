#!/usr/bin/env bash
# Update an installed controller/standalone or edge without running the fresh installer.
# Usage: sudo bash update.sh hyperdns|hyperdns-edge /path/to/new-binary [version.json]
set -Eeuo pipefail
umask 077

usage() {
    echo "Usage: sudo bash $0 hyperdns|hyperdns-edge /path/to/new-binary [version.json]" >&2
    exit 2
}
fail() { echo "[Update] $*" >&2; exit 1; }

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || usage
[ "$(id -u)" -eq 0 ] || fail 'Run as root with sudo.'
SERVICE=$1
case "$SERVICE" in hyperdns|hyperdns-edge) ;; *) usage ;; esac
for tool in systemctl tar install mktemp sha256sum readlink stat; do
    command -v "$tool" >/dev/null 2>&1 || fail "Missing command: $tool"
done

INSTALL_DIR=/opt/hyperdns
BACKUP_ROOT=/root/hyperdns-update-backups
SOURCE=$(readlink -f -- "$2") || fail 'New binary path does not exist.'
[ -f "$SOURCE" ] && [ -s "$SOURCE" ] || fail 'New binary must be a nonempty regular file.'
case "$SOURCE" in "$INSTALL_DIR"/*) fail 'Upload the new binary outside /opt/hyperdns, for example to /tmp.' ;; esac
[ -d "$INSTALL_DIR" ] && [ ! -L "$INSTALL_DIR" ] || fail 'Expected an existing /opt/hyperdns directory.'
[ "$(stat -c %u "$INSTALL_DIR")" = 0 ] || fail 'Install directory must be owned by root.'
[ -f "$INSTALL_DIR/hyperdns" ] && [ ! -L "$INSTALL_DIR/hyperdns" ] || fail 'Installed binary is missing or a symlink.'
systemctl cat "$SERVICE" >/dev/null 2>&1 || fail "Systemd service $SERVICE is not installed."
systemctl is-active --quiet "$SERVICE" || fail "Systemd service $SERVICE must be running before an update."

if [ "$SERVICE" = hyperdns ]; then
    STATE_DB=data.db
    STATE_KEY=master.key
else
    STATE_DB=edge-data.db
    STATE_KEY=edge-master.key
fi
[ -s "$INSTALL_DIR/$STATE_DB" ] && [ -s "$INSTALL_DIR/$STATE_KEY" ] ||
    fail "Existing $STATE_DB and $STATE_KEY must both be present."

VERSION_SOURCE=
if [ "$#" -eq 3 ]; then
    VERSION_SOURCE=$(readlink -f -- "$3") || fail 'version.json path does not exist.'
    [ -f "$VERSION_SOURCE" ] && [ -s "$VERSION_SOURCE" ] || fail 'version.json must be a nonempty regular file.'
fi

# -version is storage-free in HyperDNS. This also catches wrong CPU architecture
# and a truncated/non-executable upload before the running service is stopped.
"$SOURCE" -version >/dev/null 2>&1 || fail 'New binary failed its -version preflight (wrong architecture or invalid build).'
SOURCE_SHA=$(sha256sum "$SOURCE" | cut -d ' ' -f 1)
echo "[Update] Service: $SERVICE"
echo "[Update] New binary SHA-256: $SOURCE_SHA"

install -d -m 700 "$BACKUP_ROOT"
BACKUP_DIR=$(mktemp -d "$BACKUP_ROOT/${SERVICE}-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")
BACKUP_ARCHIVE="$BACKUP_DIR/install.tar.gz"
systemctl cat "$SERVICE" > "$BACKUP_DIR/unit.before.txt"

SERVICE_STOPPED=0
BACKUP_READY=0
NEW_INSTALLED=0
FINISHED=0
recover_on_exit() {
    local result=$?
    trap - EXIT INT TERM
    if [ "$FINISHED" -eq 1 ]; then return; fi
    rm -f "$INSTALL_DIR/.hyperdns.update-next" "$INSTALL_DIR/.version.update-next"
    if [ "$SERVICE_STOPPED" -eq 1 ]; then
        if [ "$NEW_INSTALLED" -eq 1 ]; then
            echo '[Update] New service did not remain healthy. Restoring the complete previous install...' >&2
            systemctl stop "$SERVICE" >/dev/null 2>&1 || true
            if [ "$BACKUP_READY" -ne 1 ] || ! tar -C /opt -xzf "$BACKUP_ARCHIVE"; then
                echo "[Update] Rollback failed. Service is stopped; inspect $BACKUP_DIR before restarting." >&2
                exit 2
            fi
        else
            rm -f "$BACKUP_ARCHIVE.partial"
            echo '[Update] Restoring the previously running service.' >&2
        fi
        if ! systemctl start "$SERVICE"; then
            echo "[Update] Could not restart $SERVICE. Inspect $BACKUP_DIR and the systemd journal." >&2
            exit 2
        fi
    fi
    exit "$result"
}
trap 'exit 130' INT
trap 'exit 143' TERM
trap recover_on_exit EXIT

# Stop before archiving BoltDB: a live filesystem copy is not a consistent
# database/key backup. The archive is outside /opt/hyperdns and root-only.
SERVICE_STOPPED=1
systemctl stop "$SERVICE"
tar -C /opt -czf "$BACKUP_ARCHIVE.partial" hyperdns
tar -tzf "$BACKUP_ARCHIVE.partial" >/dev/null
mv -f "$BACKUP_ARCHIVE.partial" "$BACKUP_ARCHIVE"
chmod 600 "$BACKUP_ARCHIVE"
BACKUP_READY=1
echo "[Update] Complete backup: $BACKUP_ARCHIVE"

install -m 755 "$SOURCE" "$INSTALL_DIR/.hyperdns.update-next"
NEW_INSTALLED=1
mv -f "$INSTALL_DIR/.hyperdns.update-next" "$INSTALL_DIR/hyperdns"
if [ -n "$VERSION_SOURCE" ]; then
    install -m 644 "$VERSION_SOURCE" "$INSTALL_DIR/.version.update-next"
    mv -f "$INSTALL_DIR/.version.update-next" "$INSTALL_DIR/version.json"
fi
[ "$(sha256sum "$INSTALL_DIR/hyperdns" | cut -d ' ' -f 1)" = "$SOURCE_SHA" ] || fail 'Installed binary checksum mismatch.'
systemctl start "$SERVICE"

# A restart loop can look "active" for a moment. Require one stable MainPID
# across four five-second checks, covering the edge's initial sync deadline.
LAST_PID=
STABLE=0
for _ in $(seq 1 12); do
    sleep 5
    if systemctl is-active --quiet "$SERVICE"; then
        PID=$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null || true)
        if [ -n "$PID" ] && [ "$PID" != 0 ]; then
            if [ "$PID" = "$LAST_PID" ]; then STABLE=$((STABLE + 1)); else STABLE=1; fi
            LAST_PID=$PID
            [ "$STABLE" -ge 4 ] && break
            continue
        fi
    fi
    LAST_PID=
    STABLE=0
done
[ "$STABLE" -ge 4 ] || fail "New $SERVICE did not stay active for 20 seconds."

FINISHED=1
trap - EXIT INT TERM
echo "[Update] $SERVICE updated and healthy. Backup retained at $BACKUP_ARCHIVE"
systemctl --no-pager --full status "$SERVICE" || true
