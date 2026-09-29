#!/bin/bash
# 02_permissions.sh — File Permission Analysis

source "$(dirname "${BASH_SOURCE[0]}")/../lib/output.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/errors.sh"

run_permissions() {
    print_section "File & Directory Permission Analysis"

    # ── Credential file permissions ───────────────────
    echo -e "\n  ${BWHITE}[*] Credential Files${NC}"

    if [ -f "$CP_CRED_FILE" ]; then
        CRED_PERMS=$(stat -c "%a" "$CP_CRED_FILE" 2>/dev/null)
        CRED_OWNER=$(stat -c "%U:%G" "$CP_CRED_FILE" 2>/dev/null)
        finding_info "Credential file: $CP_CRED_FILE [$CRED_PERMS] [$CRED_OWNER]"

        # World-readable?
        if [ "$((CRED_PERMS & 4))" -ne 0 ] 2>/dev/null; then
            finding_high "Credential file is world-readable — direct exposure of encrypted CP service account password"
            print_evidence "$(ls -la "$CP_CRED_FILE")"
        else
            finding_ok "Credential file permissions are restricted"
        fi
    else
        finding_warn "Credential file not found at: $CP_CRED_FILE"
    fi

    # ── Entropy file — the critical check ─────────────
    if [ -f "$CP_ENTROPY_FILE" ]; then
        ENTROPY_PERMS=$(stat -c "%a" "$CP_ENTROPY_FILE" 2>/dev/null)
        ENTROPY_OWNER=$(stat -c "%U:%G" "$CP_ENTROPY_FILE" 2>/dev/null)
        finding_info "Entropy file   : $CP_ENTROPY_FILE [$ENTROPY_PERMS] [$ENTROPY_OWNER]"

        # World-readable? (others read bit = 4 in last octet)
        OTHERS_READ=$(( (8#$ENTROPY_PERMS) & 4 ))
        if [ "$OTHERS_READ" -ne 0 ]; then
            finding_medium "Entropy file is world-readable — CWE-732 (Incorrect Permission Assignment for Critical Resource)"
            print_evidence "$(ls -la "$CP_ENTROPY_FILE")"
            echo -e "  ${YELLOW}  Combined with .cred file access (requires root), enables offline decryption of CP service account password${NC}"
        else
            finding_ok "Entropy file permissions are restricted"
        fi

        # Compare with .cred permissions
        if [ -f "$CP_CRED_FILE" ] && [ "$CRED_PERMS" != "$ENTROPY_PERMS" ]; then
            finding_medium "Permission mismatch: .cred ($CRED_PERMS) vs .entropy ($ENTROPY_PERMS) — files should have identical permissions"
        fi
    else
        finding_warn "Entropy file not found at: $CP_ENTROPY_FILE"
    fi

    # ── Installation directory permissions ────────────
    echo -e "\n  ${BWHITE}[*] Installation Directory${NC}"

    if [ -d "$CP_INSTALL_DIR" ]; then
        # World-writable files
        WW_FILES=$(find "$CP_INSTALL_DIR" -perm -o+w 2>/dev/null)
        if [ -n "$WW_FILES" ]; then
            finding_high "World-writable files found in CP installation directory — CWE-732"
            echo "$WW_FILES" | while read -r f; do
                print_evidence "$(ls -la "$f")"
            done
        else
            finding_ok "No world-writable files in $CP_INSTALL_DIR"
        fi

        # Files not owned by root
        NON_ROOT=$(find "$CP_INSTALL_DIR" -not -user root -not -type l 2>/dev/null)
        if [ -n "$NON_ROOT" ]; then
            finding_low "Files not owned by root found in CP installation directory"
            echo "$NON_ROOT" | head -10 | while read -r f; do
                print_evidence "$(ls -la "$f")"
            done
        else
            finding_ok "All files in $CP_INSTALL_DIR are owned by root"
        fi
    fi

    # ── Log directory permissions ──────────────────────
    echo -e "\n  ${BWHITE}[*] Log Directory${NC}"

    if [ -d "$CP_LOG_DIR" ]; then
        LOG_PERMS=$(stat -c "%a" "$CP_LOG_DIR" 2>/dev/null)
        finding_info "Log directory: $CP_LOG_DIR [$LOG_PERMS]"

        # Check if individual log files are world-readable
        WR_LOGS=$(find "$CP_LOG_DIR" -name "*.log" -perm -o+r 2>/dev/null)
        if [ -n "$WR_LOGS" ]; then
            finding_medium "Log files are world-readable — CWE-532 (Information Exposure Through Log Files)"
            echo "$WR_LOGS" | while read -r f; do
                finding_info "  $f ($(stat -c "%a" "$f"))"
            done
        else
            finding_ok "Log files are not world-readable"
        fi
    fi

    # ── Cache directory permissions ────────────────────
    echo -e "\n  ${BWHITE}[*] Cache Directory${NC}"

    CACHE_DIR=$(grep -i "ProviderCacheFolder" "$CP_MAIN_CONF" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    [ -z "$CACHE_DIR" ] && CACHE_DIR="/var/opt/CARKaim/cache"

    if [ -d "$CACHE_DIR" ]; then
        CACHE_PERMS=$(stat -c "%a" "$CACHE_DIR" 2>/dev/null)
        finding_info "Cache directory: $CACHE_DIR [$CACHE_PERMS]"

        # Cache DB world-readable?
        CACHE_DB="$CACHE_DIR/appprovider_cache.db"
        if [ -f "$CACHE_DB" ]; then
            DB_PERMS=$(stat -c "%a" "$CACHE_DB" 2>/dev/null)
            OTHERS_READ_DB=$(( (8#$DB_PERMS) & 4 ))
            if [ "$OTHERS_READ_DB" -ne 0 ]; then
                finding_high "Cache database is world-readable — may expose cached credentials — CWE-732"
                print_evidence "$(ls -la "$CACHE_DB")"
            else
                finding_ok "Cache database is not world-readable [$DB_PERMS]"
            fi

            # Check if cache DB contains cleartext (should be encrypted)
            CLEARTEXT=$(strings "$CACHE_DB" 2>/dev/null | grep -iE "password|passwd|secret|credential" | head -5)
            if [ -n "$CLEARTEXT" ]; then
                finding_high "Potential cleartext content found in cache database"
                print_evidence "$CLEARTEXT"
            else
                finding_ok "Cache database does not appear to contain cleartext credentials"
            fi
        fi

        # Check file.opy (entropy companion in cache)
        FILE_OPY="$CACHE_DIR/file.opy"
        if [ -f "$FILE_OPY" ]; then
            OPY_PERMS=$(stat -c "%a" "$FILE_OPY" 2>/dev/null)
            OTHERS_READ_OPY=$(( (8#$OPY_PERMS) & 4 ))
            if [ "$OTHERS_READ_OPY" -ne 0 ]; then
                finding_medium "file.opy (cache entropy companion) is world-readable [$OPY_PERMS] — CWE-732"
                print_evidence "$(ls -la "$FILE_OPY")"
            else
                finding_ok "file.opy permissions are restricted [$OPY_PERMS]"
            fi
        fi
    fi

    print_section_end
}
