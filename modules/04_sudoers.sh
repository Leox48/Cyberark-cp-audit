#!/bin/bash
# 04_sudoers.sh — Sudoers Analysis

source "$(dirname "${BASH_SOURCE[0]}")/../lib/output.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/errors.sh"

# Track identified application user for cross-reference
APP_USER_CANDIDATES=()

run_sudoers() {
    print_section "Sudoers & Privilege Analysis"

    # ── Identify application user from ps ─────────────
    echo -e "\n  ${BWHITE}[*] Application Process Detection${NC}"

    APP_PROCS=$(ps aux 2>/dev/null \
        | grep -iE "java|python|node|dotnet|ruby|perl|tomcat|jboss|wildfly|weblogic|websphere" \
        | grep -v "grep\|root" \
        | head -10)

    if [ -n "$APP_PROCS" ]; then
        finding_info "Application processes detected (potential authorized CP users):"
        echo "$APP_PROCS" | while read -r line; do
            APP_U=$(echo "$line" | awk '{print $1}')
            APP_CMD=$(echo "$line" | awk '{print $11}')
            finding_info "  User: $APP_U — Command: $APP_CMD"
            APP_USER_CANDIDATES+=("$APP_U")
        done
    else
        finding_warn "No application processes detected — cannot auto-identify authorized CP user"
    fi

    # ── Collect all sudoers content ────────────────────
    echo -e "\n  ${BWHITE}[*] Sudoers Files Analysis${NC}"

    SUDOERS_CONTENT=""

    if [ -r "/etc/sudoers" ]; then
        SUDOERS_CONTENT=$(cat /etc/sudoers 2>/dev/null)
    elif sudo cat /etc/sudoers &>/dev/null; then
        SUDOERS_CONTENT=$(sudo cat /etc/sudoers 2>/dev/null)
    fi

    # Read sudoers.d files
    SUDOERSD_FILES=""
    if [ -d "/etc/sudoers.d" ]; then
        if [ -r "/etc/sudoers.d" ]; then
            SUDOERSD_FILES=$(ls /etc/sudoers.d/ 2>/dev/null)
        else
            SUDOERSD_FILES=$(sudo ls /etc/sudoers.d/ 2>/dev/null)
        fi
    fi

    ALL_SUDOERS="$SUDOERS_CONTENT"

    if [ -n "$SUDOERSD_FILES" ]; then
        finding_info "sudoers.d files found: $(echo "$SUDOERSD_FILES" | wc -l)"
        for f in $SUDOERSD_FILES; do
            FULL_PATH="/etc/sudoers.d/$f"
            CONTENT=""
            if [ -r "$FULL_PATH" ]; then
                CONTENT=$(cat "$FULL_PATH" 2>/dev/null)
            else
                CONTENT=$(sudo cat "$FULL_PATH" 2>/dev/null)
            fi
            ALL_SUDOERS="$ALL_SUDOERS
### FILE: $FULL_PATH ###
$CONTENT"
        done
    fi

    if [ -z "$ALL_SUDOERS" ]; then
        finding_warn "Could not read sudoers files — try running with sudo"
        print_section_end
        return
    fi

    # ── Check 1: NOPASSWD: ALL ─────────────────────────
    echo -e "\n  ${BWHITE}[*] Unrestricted NOPASSWD: ALL Grants${NC}"

    NOPASSWD_ALL=$(echo "$ALL_SUDOERS" \
        | grep -v "^#" \
        | grep -iE "NOPASSWD.*ALL$|NOPASSWD.*ALL\s" \
        | grep -v "Cmnd_Alias\|User_Alias\|Host_Alias")

    if [ -n "$NOPASSWD_ALL" ]; then
        finding_high "Accounts with unrestricted NOPASSWD: ALL sudo — CWE-269 (Improper Privilege Management)"
        echo "$NOPASSWD_ALL" | while read -r line; do
            # Extract account name
            ACCOUNT=$(echo "$line" | awk '{print $1}')
            SOURCE_FILE=$(echo "$ALL_SUDOERS" | grep -B5 "$line" | grep "### FILE:" | tail -1 | sed 's/### FILE: //' | sed 's/ ###//')
            print_evidence "$line"
            [ -n "$SOURCE_FILE" ] && finding_info "  → Source: $SOURCE_FILE"
        done
    else
        finding_ok "No unrestricted NOPASSWD: ALL grants found"
    fi

    # ── Check 2: Impersonation of application users ────
    echo -e "\n  ${BWHITE}[*] Application User Impersonation Rules${NC}"

    # Get list of users with shell access
    SHELL_USERS=$(grep -v "nologin\|false\|sync\|halt\|shutdown" /etc/passwd 2>/dev/null \
        | cut -d: -f1 | tr '\n' '|' | sed 's/|$//')

    # Look for sudo rules that allow becoming another user via su
    SU_RULES=$(echo "$ALL_SUDOERS" \
        | grep -v "^#" \
        | grep -iE "NOPASSWD.*su\s*-|NOPASSWD.*su\s+[a-zA-Z]")

    if [ -n "$SU_RULES" ]; then
        finding_high "Passwordless sudo rules allowing user impersonation detected — CWE-269"
        echo "$SU_RULES" | while read -r line; do
            # Extract target user from su - USERNAME
            TARGET_USER=$(echo "$line" | grep -oP 'su\s*-\s*\K\S+')
            GRANTING_ENTITY=$(echo "$line" | awk '{print $1}')
            print_evidence "$line"

            if [ -n "$TARGET_USER" ]; then
                finding_info "  → Grants impersonation of: $TARGET_USER"

                # Cross-check: is this user the CP application user?
                for app_user in "${APP_USER_CANDIDATES[@]}"; do
                    if [ "$TARGET_USER" = "$app_user" ]; then
                        finding_critical "Target user '$TARGET_USER' matches application process user — direct CP credential extraction path exists"
                        echo -e "  ${BRED}    Attack chain: compromise $GRANTING_ENTITY → sudo su - $TARGET_USER → call clipasswordsdk → extract credentials${NC}"
                    fi
                done
            fi
        done
    else
        finding_ok "No passwordless user impersonation rules found"
    fi

    # ── Check 3: Dangerous NOPASSWD commands ──────────
    echo -e "\n  ${BWHITE}[*] Dangerous NOPASSWD Command Grants${NC}"

    DANGEROUS_CMDS="bash|sh|python|python3|perl|ruby|vim|vi|nano|less|more|awk|find|tee|dd|cp|mv|chmod|chown|install|env|xargs"

    DANGER_RULES=$(echo "$ALL_SUDOERS" \
        | grep -v "^#" \
        | grep "NOPASSWD" \
        | grep -iE "$DANGEROUS_CMDS" \
        | grep -v "NOPASSWD.*ALL$")

    if [ -n "$DANGER_RULES" ]; then
        finding_medium "Potentially dangerous commands with NOPASSWD detected — CWE-269"
        echo "$DANGER_RULES" | while read -r line; do
            print_evidence "$line"
        done
        echo -e "  ${YELLOW}  These commands may allow privilege escalation even when scoped to specific paths${NC}"
    else
        finding_ok "No obviously dangerous NOPASSWD command grants found"
    fi

    # ── Check 4: Wildcard in sudo rules ───────────────
    echo -e "\n  ${BWHITE}[*] Wildcard Usage in Sudo Rules${NC}"

    WILDCARD_RULES=$(echo "$ALL_SUDOERS" \
        | grep -v "^#" \
        | grep "NOPASSWD" \
        | grep "\*")

    if [ -n "$WILDCARD_RULES" ]; then
        finding_medium "Sudo rules with wildcards detected — may allow argument injection — CWE-269"
        echo "$WILDCARD_RULES" | while read -r line; do
            print_evidence "$line"
        done
    else
        finding_ok "No wildcard usage in NOPASSWD sudo rules"
    fi

    # ── Check 5: ALL users rule (world-applicable) ────
    echo -e "\n  ${BWHITE}[*] Rules Applicable to ALL Users${NC}"

    ALL_USERS_RULES=$(echo "$ALL_SUDOERS" \
        | grep -v "^#" \
        | grep -E "^ALL\s+ALL" \
        | grep "NOPASSWD")

    if [ -n "$ALL_USERS_RULES" ]; then
        finding_medium "Sudo rules applicable to ALL users detected — CWE-269"
        echo "$ALL_USERS_RULES" | while read -r line; do
            print_evidence "$line"
        done
    else
        finding_ok "No sudo rules applicable to ALL users found"
    fi

    # ── Check 6: Duplicate entries ────────────────────
    echo -e "\n  ${BWHITE}[*] Duplicate Sudoers Entries${NC}"

    DUPLICATES=$(echo "$ALL_SUDOERS" \
        | grep -v "^#\|^$\|^Defaults\|^###" \
        | sort | uniq -d)

    if [ -n "$DUPLICATES" ]; then
        finding_low "Duplicate sudoers entries detected — suggests poor lifecycle management — CWE-269"
        echo "$DUPLICATES" | while read -r line; do
            print_evidence "$line"
        done
    else
        finding_ok "No duplicate sudoers entries found"
    fi

    print_section_end
}
