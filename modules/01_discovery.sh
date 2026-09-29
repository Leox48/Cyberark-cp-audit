#!/bin/bash
# 01_discovery.sh — CyberArk CP Installation Discovery

source "$(dirname "${BASH_SOURCE[0]}")/../lib/output.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/errors.sh"

# ──────────────────────────────────────────────
# Global variables — populated by this module
# and used by subsequent modules
# ──────────────────────────────────────────────
CP_INSTALL_DIR=""
CP_VERSION=""
CP_PROCESS_USER=""
CP_PROCESS_PID=""
CP_BASIC_CONF=""
CP_VAULT_INI=""
CP_CRED_FILE=""
CP_ENTROPY_FILE=""
CP_LOG_DIR=""
CP_CACHE_DIR=""
CP_MAIN_CONF=""
CP_SDK_BIN=""
CP_SERVICE_NAME=""

run_discovery() {
    print_section "CyberArk CP — Installation Discovery"

    # ── Find installation directory ──────────────────
    for dir in /opt/CARKaim /opt/cyberark /opt/CyberArk; do
        if [ -d "$dir" ]; then
            CP_INSTALL_DIR="$dir"
            finding_ok "Installation directory found: $CP_INSTALL_DIR"
            break
        fi
    done

    if [ -z "$CP_INSTALL_DIR" ]; then
        # Fallback: broader search
        CP_INSTALL_DIR=$(find /opt /usr/local -maxdepth 3 -type d -name "*CARK*" -o -name "*cyberark*" 2>/dev/null | head -1)
        if [ -n "$CP_INSTALL_DIR" ]; then
            finding_ok "Installation directory found (non-standard path): $CP_INSTALL_DIR"
        else
            finding_warn "CyberArk CP installation directory not found. Is CP installed on this host?"
            return 1
        fi
    fi

    # ── Find SDK binary ──────────────────────────────
    for sdk in "$CP_INSTALL_DIR/sdk/clipasswordsdk" "$CP_INSTALL_DIR/bin/clipasswordsdk"; do
        if [ -f "$sdk" ]; then
            CP_SDK_BIN="$sdk"
            finding_ok "SDK binary found: $CP_SDK_BIN"
            break
        fi
    done

    if [ -z "$CP_SDK_BIN" ]; then
        finding_warn "clipasswordsdk not found — AppID testing will be skipped"
    fi

    # ── Find basic_appprovider.conf ──────────────────
    BASIC_CONF_PATHS=(
        "/etc/opt/CARKaim/conf/basic_appprovider.conf"
        "/etc/CARKaim/conf/basic_appprovider.conf"
        "$CP_INSTALL_DIR/conf/basic_appprovider.conf"
    )

    for conf in "${BASIC_CONF_PATHS[@]}"; do
        if [ -f "$conf" ]; then
            CP_BASIC_CONF="$conf"
            finding_ok "Main configuration file found: $CP_BASIC_CONF"
            break
        fi
    done

    if [ -z "$CP_BASIC_CONF" ]; then
        finding_warn "basic_appprovider.conf not found — using default paths"
    else
        # Parse all paths from basic_appprovider.conf
        CP_VAULT_INI=$(grep -i "AppProviderVaultFile" "$CP_BASIC_CONF" 2>/dev/null | cut -d'"' -f2)
        CP_CRED_FILE=$(grep -i "AppProviderCredFile" "$CP_BASIC_CONF" 2>/dev/null | cut -d'"' -f2)
        CP_LOG_DIR=$(grep -i "LogsFolder" "$CP_BASIC_CONF" 2>/dev/null | cut -d'"' -f2)
        LOCAL_PARMS=$(grep -i "LocalParmsFileFolder" "$CP_BASIC_CONF" 2>/dev/null | cut -d'"' -f2)

        if [ -n "$CP_CRED_FILE" ]; then
            CP_ENTROPY_FILE="${CP_CRED_FILE}.entropy"
        fi

        # Find main_appprovider.conf
        if [ -n "$LOCAL_PARMS" ]; then
            CP_MAIN_CONF=$(find "$LOCAL_PARMS" -name "main_appprovider.conf*" 2>/dev/null | head -1)
        fi

        finding_info "Vault config   : ${CP_VAULT_INI:-not found}"
        finding_info "Credential file: ${CP_CRED_FILE:-not found}"
        finding_info "Log directory  : ${CP_LOG_DIR:-not found}"
        finding_info "Main conf      : ${CP_MAIN_CONF:-not found}"
    fi

    # ── Fallback paths if conf not parsed ────────────
    [ -z "$CP_VAULT_INI" ]   && CP_VAULT_INI="/etc/opt/CARKaim/vault/vault.ini"
    [ -z "$CP_CRED_FILE" ]   && CP_CRED_FILE="/etc/opt/CARKaim/vault/appprovideruser.cred"
    [ -z "$CP_ENTROPY_FILE" ] && CP_ENTROPY_FILE="/etc/opt/CARKaim/vault/appprovideruser.cred.entropy"
    [ -z "$CP_LOG_DIR" ]     && CP_LOG_DIR="/var/opt/CARKaim/logs"
    [ -z "$CP_MAIN_CONF" ]   && CP_MAIN_CONF=$(find /var/opt/CARKaim -name "main_appprovider.conf*" 2>/dev/null | head -1)

    # ── Version detection ─────────────────────────────
    VERSION_FILE="/var/opt/CARKaim/.version_info"
    if [ -f "$VERSION_FILE" ]; then
        CP_VERSION=$(grep -oP 'version="\K[^"]+' "$VERSION_FILE" 2>/dev/null)
        RELEASE=$(grep -oP 'release="\K[^"]+' "$VERSION_FILE" 2>/dev/null)
        if [ -n "$CP_VERSION" ] && [ -n "$RELEASE" ]; then
            CP_VERSION="${CP_VERSION}.${RELEASE}"
        fi
        finding_ok "CP Version: $CP_VERSION"
    else
        # Fallback: strings on binary
        if [ -f "$CP_INSTALL_DIR/bin/appprovider" ]; then
            CP_VERSION=$(strings "$CP_INSTALL_DIR/bin/appprovider" 2>/dev/null \
                | grep -oP 'VERSION_\d+_\d+_\d+' | sort -V | tail -1 \
                | sed 's/VERSION_//;s/_/./g')
            if [ -n "$CP_VERSION" ]; then
                finding_ok "CP Version (from binary): $CP_VERSION"
            else
                finding_warn "Could not determine CP version"
                CP_VERSION="unknown"
            fi
        fi
    fi

    # ── Process detection ─────────────────────────────
    PROC_INFO=$(ps aux 2>/dev/null | grep -i "appprovider" | grep -v grep | head -1)
    if [ -n "$PROC_INFO" ]; then
        CP_PROCESS_USER=$(echo "$PROC_INFO" | awk '{print $1}')
        CP_PROCESS_PID=$(echo "$PROC_INFO" | awk '{print $2}')
        finding_ok "CP process running — PID: $CP_PROCESS_PID, User: $CP_PROCESS_USER"

        if [ "$CP_PROCESS_USER" = "root" ]; then
            finding_medium "appprovider daemon is running as ROOT — CWE-250 (Execution with Unnecessary Privileges)"
            print_evidence "$(echo "$PROC_INFO" | awk '{print $1, $2, $11, $12}')"
        fi
    else
        finding_warn "appprovider process not found — CP may be stopped or not installed"
    fi

    # ── Service detection ──────────────────────────────
    for svc in aimprv CARKaim cyberark-cp; do
        if systemctl status "$svc.service" &>/dev/null; then
            CP_SERVICE_NAME="$svc"
            finding_info "Systemd service: ${svc}.service"
            break
        fi
    done

    print_section_end
}
