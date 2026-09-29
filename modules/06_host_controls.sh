#!/bin/bash
# 06_host_controls.sh — Host Security Controls

source "$(dirname "${BASH_SOURCE[0]}")/../lib/output.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/errors.sh"

run_host_controls() {
    print_section "Host Security Controls"

    # ── SELinux ───────────────────────────────────────
    echo -e "\n  ${BWHITE}[*] Mandatory Access Control${NC}"

    if command -v sestatus &>/dev/null || [ -f /usr/sbin/sestatus ]; then
        SELINUX_STATUS=$(sestatus 2>/dev/null | grep "SELinux status" | awk '{print $3}')
        SELINUX_MODE=$(sestatus 2>/dev/null | grep "Current mode" | awk '{print $3}')

        finding_info "SELinux status: ${SELINUX_STATUS:-unknown}"
        finding_info "SELinux mode  : ${SELINUX_MODE:-unknown}"

        if [ "$SELINUX_STATUS" = "disabled" ]; then
            finding_low "SELinux is disabled — CWE-284 (Improper Access Control)"
            echo -e "  ${YELLOW}  No MAC enforcement on the host. All other findings operate without OS-level containment.${NC}"
        elif [ "$SELINUX_MODE" = "permissive" ]; then
            finding_low "SELinux is in Permissive mode — policies are logged but not enforced — CWE-284"
        elif [ "$SELINUX_MODE" = "enforcing" ]; then
            finding_ok "SELinux is Enforcing"

            # Check if appprovider has a specific SELinux context
            if [ -n "$CP_PROCESS_PID" ]; then
                SELINUX_CTX=$(ps -Z -p "$CP_PROCESS_PID" 2>/dev/null | tail -1 | awk '{print $1}')
                finding_info "appprovider SELinux context: ${SELINUX_CTX:-unknown}"
                if echo "$SELINUX_CTX" | grep -q "unconfined"; then
                    finding_medium "appprovider is running in unconfined SELinux context — no targeted policy applied"
                fi
            fi
        fi
    else
        # Check AppArmor
        if command -v aa-status &>/dev/null || [ -f /usr/sbin/aa-status ]; then
            AA_STATUS=$(aa-status 2>/dev/null | head -3)
            if echo "$AA_STATUS" | grep -qi "apparmor module is loaded"; then
                finding_ok "AppArmor is active"
                finding_info "$AA_STATUS"
            else
                finding_low "AppArmor not active — CWE-284"
            fi
        else
            finding_low "Neither SELinux nor AppArmor detected — no MAC enforcement — CWE-284"
        fi
    fi

    # ── PATH hijacking analysis ────────────────────────
    echo -e "\n  ${BWHITE}[*] PATH Hijacking Analysis${NC}"

    # Skip PATH hijacking check when running as root:
    # root can write to system directories by definition — this would always
    # produce false positives and is not meaningful in a root context.
    if [ "$EUID" -eq 0 ]; then
        finding_info "Running as root — PATH hijacking check skipped"
        finding_info "Re-run as the application user to get meaningful results"
    else
        USERS_TO_CHECK=("$(whoami)")

        # Add detected application users (non-root only)
        APP_USERS=$(ps aux 2>/dev/null \
            | grep -iE "java|python|tomcat|jboss" \
            | grep -v "grep\|root" \
            | awk '{print $1}' | sort -u)

        for u in $APP_USERS; do
            USERS_TO_CHECK+=("$u")
        done

        for check_user in "${USERS_TO_CHECK[@]}"; do
            if [ "$check_user" = "$(whoami)" ]; then
                USER_PATH=$(env | grep "^PATH=" | cut -d'=' -f2)
            else
                USER_PATH=$(sudo -n -u "$check_user" env 2>/dev/null | grep "^PATH=" | cut -d'=' -f2)
            fi

            if [ -n "$USER_PATH" ]; then
                finding_info "PATH for $check_user: $USER_PATH"
                WRITABLE_IN_PATH=""
                IFS=':' read -ra PATH_DIRS <<< "$USER_PATH"
                for dir in "${PATH_DIRS[@]}"; do
                    # Only flag directories writable by non-root users
                    # Skip standard system directories owned by root with expected permissions
                    if [ -d "$dir" ] && [ -w "$dir" ]; then
                        DIR_OWNER=$(stat -c "%U" "$dir" 2>/dev/null)
                        DIR_PERMS=$(stat -c "%a" "$dir" 2>/dev/null)
                        # Flag only if writable by others (not just because we're the owner)
                        OTHERS_WRITE=$(( (8#${DIR_PERMS:-000}) & 2 ))
                        if [ "$OTHERS_WRITE" -ne 0 ] || [ "$DIR_OWNER" = "$check_user" ]; then
                            WRITABLE_IN_PATH="$WRITABLE_IN_PATH $dir"
                        fi
                    fi
                done

                if [ -n "$WRITABLE_IN_PATH" ]; then
                    finding_medium "Writable directories in PATH for user '$check_user' — PATH hijacking possible — CWE-427"
                    for wdir in $WRITABLE_IN_PATH; do
                        print_evidence "Writable: $wdir ($(stat -c "%a %U" "$wdir" 2>/dev/null))"
                    done
                else
                    finding_ok "No writable directories in PATH for '$check_user'"
                fi
            fi
        done
    fi

    # ── SUID/SGID binaries ────────────────────────────
    echo -e "\n  ${BWHITE}[*] SUID/SGID Binaries${NC}"

    # Only check for actual SUID/SGID files (not directories) in non-standard locations
    # -type f ensures we only match files, not directories with setgid bit
    # Excludes known safe system paths and journal directories
    SUID_CUSTOM=$(find /opt /home /tmp /var/tmp /srv 2>/dev/null \
        -type f \( -perm -4000 -o -perm -2000 \) \
        ! -path "*/systemd-journal/*" \
        ! -path "*/journal/*" \
        2>/dev/null)

    if [ -n "$SUID_CUSTOM" ]; then
        SUID_COUNT=$(echo "$SUID_CUSTOM" | wc -l)
        finding_medium "$SUID_COUNT SUID/SGID file(s) found in non-standard locations — CWE-250"
        echo "$SUID_CUSTOM" | while read -r f; do
            print_evidence "$(ls -la "$f" 2>/dev/null)"
        done
    else
        finding_ok "No SUID/SGID files in non-standard locations"
    fi

    # ── World-writable directories ─────────────────────
    echo -e "\n  ${BWHITE}[*] World-Writable Directories (non-standard)${NC}"

    WW_DIRS=$(find /opt /srv /home 2>/dev/null -type d -perm -o+w | grep -v "^/proc\|tmp$")

    if [ -n "$WW_DIRS" ]; then
        finding_medium "World-writable directories found — CWE-732"
        echo "$WW_DIRS" | head -10 | while read -r d; do
            print_evidence "$(ls -lad "$d" 2>/dev/null)"
        done
    else
        finding_ok "No unexpected world-writable directories found"
    fi

    # ── Vault network connectivity check ──────────────
    echo -e "\n  ${BWHITE}[*] Vault Network Connectivity${NC}"

    VAULT_ADDR=$(grep -i "^ADDRESS" "$CP_VAULT_INI" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    VAULT_PORT=$(grep -i "^PORT" "$CP_VAULT_INI" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    [ -z "$VAULT_PORT" ] && VAULT_PORT="1858"

    if [ -n "$VAULT_ADDR" ]; then
        CONN_CHECK=$(ss -tnp 2>/dev/null | grep ":$VAULT_PORT")
        if [ -n "$CONN_CHECK" ]; then
            finding_ok "Active connection to Vault ($VAULT_ADDR:$VAULT_PORT) detected"
            finding_info "$CONN_CHECK"
        else
            finding_info "No active connection to Vault on port $VAULT_PORT (may be idle)"
        fi

        # Check if port is reachable
        if command -v nc &>/dev/null; then
            if nc -z -w3 "$VAULT_ADDR" "$VAULT_PORT" 2>/dev/null; then
                finding_ok "Vault is reachable at $VAULT_ADDR:$VAULT_PORT"
            else
                finding_warn "Vault at $VAULT_ADDR:$VAULT_PORT is not reachable from this host"
            fi
        fi
    else
        finding_warn "Vault address not determined — skipping connectivity check"
    fi

    # ── OS and kernel info ─────────────────────────────
    echo -e "\n  ${BWHITE}[*] OS & Kernel Information${NC}"

    OS_INFO=$(cat /etc/os-release 2>/dev/null | grep "^PRETTY_NAME" | cut -d'"' -f2)
    KERNEL=$(uname -r 2>/dev/null)

    finding_info "OS     : ${OS_INFO:-unknown}"
    finding_info "Kernel : ${KERNEL:-unknown}"

    print_section_end
}
