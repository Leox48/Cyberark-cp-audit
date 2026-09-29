#!/bin/bash
# 03_configuration.sh — CP Configuration Analysis

source "$(dirname "${BASH_SOURCE[0]}")/../lib/output.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/errors.sh"

run_configuration() {
    print_section "CP Configuration Analysis"

    # ── vault.ini ─────────────────────────────────────
    echo -e "\n  ${BWHITE}[*] Vault Connection (vault.ini)${NC}"

    if [ -f "$CP_VAULT_INI" ]; then
        finding_ok "vault.ini found: $CP_VAULT_INI"

        VAULT_ADDR=$(grep -i "^ADDRESS" "$CP_VAULT_INI" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        VAULT_PORT=$(grep -i "^PORT" "$CP_VAULT_INI" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        VAULT_NAME=$(grep -i "^VAULT" "$CP_VAULT_INI" 2>/dev/null | cut -d'=' -f2 | tr -d ' "')
        PROXY_ADDR=$(grep -i "^PROXYADDRESS" "$CP_VAULT_INI" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')

        finding_info "Vault name   : ${VAULT_NAME:-not set}"
        finding_info "Vault address: ${VAULT_ADDR:-not set}"
        finding_info "Vault port   : ${VAULT_PORT:-1858 (default)}"

        [ -n "$PROXY_ADDR" ] && finding_info "Proxy address: $PROXY_ADDR"

        # Check for cleartext credentials in vault.ini
        CLEARTEXT_CREDS=$(grep -iE "password|passwd|secret|key" "$CP_VAULT_INI" 2>/dev/null | grep -v "^#")
        if [ -n "$CLEARTEXT_CREDS" ]; then
            finding_high "Potential cleartext credentials found in vault.ini — CWE-312"
            print_evidence "$CLEARTEXT_CREDS"
        else
            finding_ok "No cleartext credentials in vault.ini"
        fi

        # Check port (should be 1858)
        if [ -n "$VAULT_PORT" ] && [ "$VAULT_PORT" != "1858" ]; then
            finding_low "Non-standard Vault port configured: $VAULT_PORT (expected: 1858)"
        fi

    else
        finding_warn "vault.ini not found at: $CP_VAULT_INI"
        # Try to find it
        ALT_VAULT=$(find /etc /opt /var -name "vault.ini" 2>/dev/null | head -1)
        [ -n "$ALT_VAULT" ] && finding_info "Alternative vault.ini found at: $ALT_VAULT"
    fi

    # ── main_appprovider.conf ─────────────────────────
    echo -e "\n  ${BWHITE}[*] Advanced Configuration (main_appprovider.conf)${NC}"

    if [ -n "$CP_MAIN_CONF" ] && [ -f "$CP_MAIN_CONF" ]; then
        finding_ok "Main conf found: $CP_MAIN_CONF"

        VAULT_ACCESS=$(grep -i "VaultAccessInterval" "$CP_MAIN_CONF" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        CACHE_LEVEL=$(grep -i "CacheLevel" "$CP_MAIN_CONF" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        CACHE_EXPIRY=$(grep -i "CachedSecretExpiry" "$CP_MAIN_CONF" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        MAX_CONCURRENT=$(grep -i "MaxConcurrentRequests" "$CP_MAIN_CONF" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
        TCP_PORT=$(grep -i "^Port" "$CP_MAIN_CONF" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')

        finding_info "Cache level           : ${CACHE_LEVEL:-not set}"
        finding_info "CachedSecretExpiry    : ${CACHE_EXPIRY:-not set} hours"
        finding_info "MaxConcurrentRequests : ${MAX_CONCURRENT:-not set}"
        finding_info "Local TCP port        : ${TCP_PORT:-18923 (default)}"

        # VaultAccessInterval check
        if [ -n "$VAULT_ACCESS" ]; then
            DAYS=$(( VAULT_ACCESS / 86400 ))
            HOURS=$(( VAULT_ACCESS / 3600 ))
            finding_info "VaultAccessInterval   : $VAULT_ACCESS seconds (~${HOURS}h / ~${DAYS}d)"

            if [ "$VAULT_ACCESS" -gt 86400 ]; then
                finding_medium "VaultAccessInterval is ${DAYS} days — CWE-613 (Insufficient Session Expiration)"
                echo -e "  ${YELLOW}  In an incident response scenario, revoked credentials will continue to be distributed"
                echo -e "  from the local cache for up to ${DAYS} days. Recommended value: ≤3600 seconds.${NC}"
            elif [ "$VAULT_ACCESS" -gt 3600 ]; then
                finding_low "VaultAccessInterval is ${HOURS} hours — consider reducing to ≤3600 seconds"
            else
                finding_ok "VaultAccessInterval is within recommended range (${HOURS}h)"
            fi
        fi

    else
        finding_warn "main_appprovider.conf not found"
    fi

    # ── Credential file content check ──────────────────
    echo -e "\n  ${BWHITE}[*] Credential File Content${NC}"

    if [ -f "$CP_CRED_FILE" ]; then
        # Check if readable without sudo
        if cat "$CP_CRED_FILE" &>/dev/null; then
            CRED_CONTENT=$(cat "$CP_CRED_FILE" 2>/dev/null)

            # Check Secret field
            SECRET=$(echo "$CRED_CONTENT" | grep "^Secret=" | cut -d'=' -f2)
            if [ -n "$SECRET" ]; then
                # Is it hex/encrypted or cleartext?
                IS_HEX=$(echo "$SECRET" | grep -E '^[0-9A-Fa-f]+$')
                if [ -n "$IS_HEX" ]; then
                    finding_ok "Secret field appears to be encrypted (hex format)"
                else
                    finding_high "Secret field may contain cleartext password — CWE-312"
                    print_evidence "Secret field length: ${#SECRET} chars"
                fi
            fi

            # Extract service account username
            SVC_USER=$(echo "$CRED_CONTENT" | grep "^Username=" | cut -d'=' -f2)
            [ -n "$SVC_USER" ] && finding_info "CP service account: $SVC_USER"

        else
            finding_ok "Credential file is not readable without elevated privileges (expected behavior)"
        fi
    fi

    # ── Log content analysis ───────────────────────────
    echo -e "\n  ${BWHITE}[*] Log Content Analysis${NC}"

    CONSOLE_LOG="$CP_LOG_DIR/APPConsole.log"
    AUDIT_LOG="$CP_LOG_DIR/APPAudit.log"

    if [ -f "$CONSOLE_LOG" ] && [ -r "$CONSOLE_LOG" ]; then
        # Check for sensitive info in logs
        VAULT_IP_IN_LOG=$(grep -oP 'Vault \[\K[^\]]+' "$CONSOLE_LOG" 2>/dev/null | head -1)
        SVC_ACC_IN_LOG=$(grep -oP 'Provider \[\K[^\]]+' "$CONSOLE_LOG" 2>/dev/null | head -1)
        VERSION_IN_LOG=$(grep -oP 'version \[\K[^\]]+' "$CONSOLE_LOG" 2>/dev/null | head -1)
        FQDN_IN_LOG=$(grep -oP 'addresses for this provider \[\K[^\]]+' "$CONSOLE_LOG" 2>/dev/null | head -1)

        if [ -n "$VAULT_IP_IN_LOG" ] || [ -n "$SVC_ACC_IN_LOG" ]; then
            finding_low "Log files expose infrastructure details in cleartext — CWE-532"
            [ -n "$VAULT_IP_IN_LOG" ]  && finding_info "  Vault address in logs : $VAULT_IP_IN_LOG"
            [ -n "$SVC_ACC_IN_LOG" ]   && finding_info "  Service account in logs: $SVC_ACC_IN_LOG"
            [ -n "$VERSION_IN_LOG" ]   && finding_info "  CP version in logs    : $VERSION_IN_LOG"
            [ -n "$FQDN_IN_LOG" ]      && finding_info "  Host addresses in logs: $FQDN_IN_LOG"
        fi

        # Count historical log files
        OLD_LOGS=$(find "$CP_LOG_DIR/old" -name "*.log" 2>/dev/null | wc -l)
        if [ "$OLD_LOGS" -gt 14 ]; then
            finding_low "Log retention: $OLD_LOGS historical log files found — consider reducing retention period"
        fi

    elif [ -f "$CONSOLE_LOG" ]; then
        finding_info "Console log exists but requires elevated privileges to read"
    fi

    if [ -f "$AUDIT_LOG" ]; then
        AUDIT_SIZE=$(stat -c %s "$AUDIT_LOG" 2>/dev/null)
        if [ "$AUDIT_SIZE" -eq 0 ]; then
            finding_low "APPAudit.log is empty — no credential retrievals have been logged"
            echo -e "  ${YELLOW}  This may indicate audit logging is not configured or the CP has never served requests${NC}"
        else
            finding_ok "APPAudit.log contains entries ($AUDIT_SIZE bytes)"
        fi
    fi

    print_section_end
}
