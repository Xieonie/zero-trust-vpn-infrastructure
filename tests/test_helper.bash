# shellcheck shell=bash
# Sandboxes every path the scripts touch under $BATS_TEST_TMPDIR.

REPO_ROOT="$(cd "$(dirname "${BATS_TEST_FILENAME}")/.." && pwd)"
export REPO_ROOT

ztvpn_sandbox() {
    local t="$BATS_TEST_TMPDIR"
    export ZTVPN_ETC="$t/etc"
    export ZTVPN_CONFIG="$t/etc/ztvpn.conf"
    export ZTVPN_HOME="$t/opt"
    export ZTVPN_STATE_DIR="$t/state"
    export ZTVPN_LOG_DIR="$t/log"
    export ZTVPN_BACKUP_DIR="$t/backup"
    export WG_DIR="$t/wireguard"
    export NO_COLOR=1
    mkdir -p "$ZTVPN_ETC" "$ZTVPN_HOME" "$ZTVPN_STATE_DIR" "$WG_DIR"
}

# Minimal server config + key pair so peer functions have something to edit.
ztvpn_fake_wg_server() {
    umask 077
    wg genkey >"$WG_DIR/server_private.key"
    wg pubkey <"$WG_DIR/server_private.key" >"$WG_DIR/server_public.key"
    printf '[Interface]\nAddress = 10.8.0.1/24\nListenPort = 51820\nPrivateKey = %s\n' \
        "$(<"$WG_DIR/server_private.key")" >"$WG_DIR/wg0.conf"
}

load_lib() {
    # shellcheck source=scripts/lib/common.sh
    source "$REPO_ROOT/scripts/lib/common.sh"
}
