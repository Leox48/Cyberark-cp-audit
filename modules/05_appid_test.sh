#!/bin/bash
# 05_appid_test.sh — AppID Restriction Testing

source "$(dirname "${BASH_SOURCE[0]}")/../lib/output.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/errors.sh"

run_appid_test() {
    print_section "AppID Restriction Testing"

    # ── Pre-flight checks ─────────────────────────────
    if [ -z "${CP_SDK_BIN:-}" ] || [ ! -f "${CP_SDK_BIN:-}" ]; then
        finding_skip "clipasswordsdk not found — AppID restriction tests cannot run"
        finding_info "Expected path: /opt/CARKaim/sdk/clipasswordsdk"
        print_section_end
        return 0
    fi

    if [ -z "${AUDIT_APPID:-}" ]; then
        finding_skip "No AppID specified — use -a <AppID> to enable this module"
        print_section_end
        return 0
    fi

    # Warn if Safe not provided — generate a safe probe name
    if [ -z "${AUDIT_SAFE:-}" ]; then
        finding_warn "No Safe specified — using a non-existent probe Safe to test authentication only"
        finding_info "Tip: use -s <SafeName> to also verify credential retrieval"
        AUDIT_SAFE="probe_$(date +%s)"
    fi

    finding_info "Testing AppID : $AUDIT_APPID"
    finding_info "Safe target   : $AUDIT_SAFE"

    # ── Helper: call CP safely ─────────────────────────
    # Quotes AppID and Safe to handle special characters
    call_cp() {
        local user="$1"
        local appid="$2"
        local safe="$3"
        local result=""
        local exit_code=0

        if [ "$user" = "current" ]; then
            result=$("$CP_SDK_BIN" GetPassword \
                -p "AppDescs.AppID=${appid}" \
                -p "Query=Safe=${safe}" \
                -o Password 2>&1) || exit_code=$?
        else
            # Verify we can sudo as that user before trying
            if ! sudo -n -u "$user" true 2>/dev/null; then
                echo "SUDO_UNAVAILABLE"
                return 0
            fi
            result=$(sudo -n -u "$user" "$CP_SDK_BIN" GetPassword \
                -p "AppDescs.AppID=${appid}" \
                -p "Query=Safe=${safe}" \
                -o Password 2>&1) || exit_code=$?
        fi

        echo "$result"
        return 0
    }

    # ── Parse CP result ───────────────────────────────
    # Returns:
    #   0 = restricted (expected)
    #   1 = auth passed (Safe/object not found)
    #   2 = credential returned (critical)
    #   3 = sudo unavailable for this user
    #   4 = unknown/unhandled response
    parse_cp_result() {
        local result="$1"
        local user="$2"

        case "$result" in
            "SUDO_UNAVAILABLE")
                echo -e "  ${PURPLE}[SKIP]${NC} ${user}: cannot sudo as this user — skipping"
                return 3
                ;;
            *APPAP133E*OSUser*)
                echo -e "  ${GREEN}[-]${NC} ${user}: ${CYAN}APPAP133E${NC} — OSUser restriction ACTIVE — unauthorized ✓"
                return 0
                ;;
            *APPAP133E*Path*)
                echo -e "  ${GREEN}[-]${NC} ${user}: ${CYAN}APPAP133E${NC} — Path restriction ACTIVE ✓"
                return 0
                ;;
            *APPAP133E*)
                echo -e "  ${GREEN}[-]${NC} ${user}: ${CYAN}APPAP133E${NC} — Authentication restriction ACTIVE ✓"
                return 0
                ;;
            *APPAP004E*|*APPBC004E*)
                echo -e "  ${BRED}[!]${NC} ${user}: ${RED}APPAP004E${NC} — Authentication PASSED (Safe/object not found)"
                echo -e "  ${BRED}    → '$user' IS authorized for AppID '$AUDIT_APPID'${NC}"
                log_finding "HIGH" "User '$user' passes AppID '$AUDIT_APPID' OS User restriction"
                return 1
                ;;
            *APPAP081E*)
                echo -e "  ${CYAN}[-]${NC} ${user}: ${CYAN}APPAP081E${NC} — Malformed request (missing parameters)"
                return 0
                ;;
            *APPAP425E*|*ITATS982E*)
                echo -e "  ${CYAN}[-]${NC} ${user}: AppID '$AUDIT_APPID' not found in Vault"
                echo -e "  ${YELLOW}       Verify the AppID name is correct (case-sensitive)${NC}"
                return 0
                ;;
            *APPEX003E*)
                echo -e "  ${YELLOW}[-]${NC} ${user}: ${CYAN}APPEX003E${NC} — CP internal error"
                echo -e "  ${YELLOW}       Check CP logs: sudo tail -20 ${CP_LOG_DIR}/APPConsole.log${NC}"
                return 4
                ;;
            *APPBC008E*)
                echo -e "  ${YELLOW}[-]${NC} ${user}: ${CYAN}APPBC008E${NC} — Vault connectivity issue"
                echo -e "  ${YELLOW}       CP cannot reach the Vault — check network/firewall${NC}"
                return 4
                ;;
            "")
                echo -e "  ${YELLOW}[-]${NC} ${user}: Empty response from CP"
                return 4
                ;;
            *)
                # No error code in response = possible password in cleartext
                if ! echo "$result" | grep -qE 'APP[A-Z0-9]+E|ITATS[0-9]+E'; then
                    echo -e "  ${BRED}[!!!]${NC} ${user}: ${BRED}CREDENTIAL RETURNED IN CLEARTEXT — CRITICAL${NC}"
                    echo -e "  ${BRED}      Full credential extraction confirmed for AppID '$AUDIT_APPID'${NC}"
                    log_finding "CRITICAL" "Credential extracted from Vault for AppID '$AUDIT_APPID' as user '$user'"
                    return 2
                else
                    echo -e "  ${YELLOW}[-]${NC} ${user}: Unrecognized response: ${result:0:80}"
                    return 4
                fi
                ;;
        esac
    }

    # ── Test 1: AppID enumeration ─────────────────────
    echo -e "\n  ${BWHITE}[*] AppID Existence Check & Enumeration${NC}"

    KNOWN_RESULT=$(call_cp "current" "$AUDIT_APPID" "$AUDIT_SAFE")
    FAKE_APPID="NonExistentApp_$(date +%s)"
    FAKE_RESULT=$(call_cp "current" "$FAKE_APPID" "$AUDIT_SAFE")

    KNOWN_CODE=$(echo "$KNOWN_RESULT" | grep -oE 'APP[A-Z0-9]+E|ITATS[0-9]+E' | head -1)
    FAKE_CODE=$(echo "$FAKE_RESULT" | grep -oE 'APP[A-Z0-9]+E|ITATS[0-9]+E' | head -1)

    finding_info "AppID '$AUDIT_APPID' error  : ${KNOWN_CODE:-no error code — possible credential returned}"
    finding_info "Fake AppID error            : ${FAKE_CODE:-no error code}"

    # AppID not found at all
    if echo "$KNOWN_RESULT" | grep -qE 'APPAP425E|ITATS982E'; then
        finding_warn "AppID '$AUDIT_APPID' was NOT found in the Vault"
        echo -e "  ${YELLOW}  Possible causes:${NC}"
        echo -e "  ${YELLOW}  1. AppID name is incorrect (case-sensitive — try exact case)${NC}"
        echo -e "  ${YELLOW}  2. AppID does not exist in this Vault${NC}"
        echo -e "  ${YELLOW}  3. CP cannot reach the Vault (check connectivity)${NC}"
        print_section_end
        return 0
    fi

    if [ -n "$KNOWN_CODE" ] && [ -n "$FAKE_CODE" ] && [ "$KNOWN_CODE" != "$FAKE_CODE" ]; then
        finding_low "AppID enumeration via error differentiation — CWE-203"
        echo -e "  ${YELLOW}  Valid AppIDs return '$KNOWN_CODE', invalid AppIDs return '$FAKE_CODE'${NC}"
    fi

    # ── Test 2: Systematic OS User testing ────────────
    echo -e "\n  ${BWHITE}[*] OS User Restriction — Systematic Testing${NC}"

    AUTHORIZED_USERS=()

    # Current user
    CURRENT_USER=$(whoami)
    CURRENT_RESULT=$(call_cp "current" "$AUDIT_APPID" "$AUDIT_SAFE")
    parse_cp_result "$CURRENT_RESULT" "$CURRENT_USER"
    CURRENT_STATUS=$?
    [ $CURRENT_STATUS -eq 1 ] || [ $CURRENT_STATUS -eq 2 ] && AUTHORIZED_USERS+=("$CURRENT_USER")

    # Root
    ROOT_RESULT=$(call_cp "root" "$AUDIT_APPID" "$AUDIT_SAFE")
    parse_cp_result "$ROOT_RESULT" "root"
    ROOT_STATUS=$?
    [ $ROOT_STATUS -eq 1 ] || [ $ROOT_STATUS -eq 2 ] && AUTHORIZED_USERS+=("root")
    if [ $ROOT_STATUS -eq 1 ] || [ $ROOT_STATUS -eq 2 ]; then
        finding_high "root bypasses OS User restriction — CWE-269"
    fi

    # All local users with interactive shell
    SHELL_USERS=$(grep -v "nologin\|false\|sync\|halt\|shutdown" /etc/passwd 2>/dev/null \
        | cut -d: -f1 | grep -v "^root$" | grep -v "^${CURRENT_USER}$")

    for user in $SHELL_USERS; do
        RESULT=$(call_cp "$user" "$AUDIT_APPID" "$AUDIT_SAFE")
        parse_cp_result "$RESULT" "$user"
        STATUS=$?
        [ $STATUS -eq 1 ] || [ $STATUS -eq 2 ] && AUTHORIZED_USERS+=("$user")
    done

    # ── Test 3: Path restriction ──────────────────────
    echo -e "\n  ${BWHITE}[*] Path Restriction Test${NC}"

    TEMP_SDK="/tmp/.cp_audit_sdk_$$"

    if cp "$CP_SDK_BIN" "$TEMP_SDK" 2>/dev/null && chmod +x "$TEMP_SDK" 2>/dev/null; then
        if [ ${#AUTHORIZED_USERS[@]} -eq 0 ]; then
            finding_info "No authorized users identified — path restriction test skipped"
            finding_info "Identify the authorized OS User first, then re-run with that user"
        else
            for auth_user in "${AUTHORIZED_USERS[@]}"; do
                local path_result=""
                if [ "$auth_user" = "$(whoami)" ]; then
                    path_result=$("$TEMP_SDK" GetPassword \
                        -p "AppDescs.AppID=${AUDIT_APPID}" \
                        -p "Query=Safe=${AUDIT_SAFE}" \
                        -o Password 2>&1) || true
                else
                    path_result=$(sudo -n -u "$auth_user" "$TEMP_SDK" GetPassword \
                        -p "AppDescs.AppID=${AUDIT_APPID}" \
                        -p "Query=Safe=${AUDIT_SAFE}" \
                        -o Password 2>&1) || true
                fi

                PATH_CODE=$(echo "$path_result" | grep -oE 'APP[A-Z0-9]+E' | head -1)

                if echo "$path_result" | grep -q "APPAP133E"; then
                    finding_ok "Path restriction ACTIVE for '$auth_user' — call from /tmp was blocked ✓"
                elif echo "$path_result" | grep -qE "APPAP004E|APPBC004E"; then
                    finding_high "Path restriction NOT configured for AppID '$AUDIT_APPID' — CWE-284"
                    echo -e "  ${RED}  Any binary running as '$auth_user' can retrieve credentials${NC}"
                    echo -e "  ${RED}  Recommendation: add Path restriction in PVWA for this AppID${NC}"
                    log_finding "HIGH" "Path restriction not configured for AppID '$AUDIT_APPID'"
                elif ! echo "$path_result" | grep -qE 'APP[A-Z0-9]+E|ITATS[0-9]+E'; then
                    finding_critical "Credential extracted from /tmp path — Path restriction ABSENT — CWE-284"
                    log_finding "CRITICAL" "Credential extracted from non-standard path for AppID '$AUDIT_APPID'"
                else
                    finding_info "Path test result for '$auth_user': ${PATH_CODE:-${path_result:0:60}}"
                fi
            done
        fi

        rm -f "$TEMP_SDK" 2>/dev/null || true
    else
        finding_skip "Cannot copy SDK to /tmp — path restriction test skipped"
        finding_info "This may be due to /tmp being mounted noexec"
    fi

    # ── Post-test: read CP log ─────────────────────────
    echo -e "\n  ${BWHITE}[*] CP Log — Post-Test Entries${NC}"

    LOG_FILE="${CP_LOG_DIR:-/var/opt/CARKaim/logs}/APPConsole.log"
    if [ -f "$LOG_FILE" ]; then
        LOG_ENTRIES=$(sudo tail -15 "$LOG_FILE" 2>/dev/null \
            | grep -E "APPAP|APPEX|APPBC" | tail -8) || true
        if [ -n "$LOG_ENTRIES" ]; then
            finding_info "Recent CP log entries (most recent first):"
            echo "$LOG_ENTRIES" | tac | while IFS= read -r line; do
                echo -e "  ${WHITE}  $line${NC}"
            done
        else
            finding_info "No relevant CP log entries found (log may require elevated access)"
        fi
    fi

    print_section_end
    return 0
}
