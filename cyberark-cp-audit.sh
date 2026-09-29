#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#  cyberark-cp-audit.sh
#  CyberArk Credential Provider Security Audit Tool
#
#  Author : Leonardo Sole — Offensive Security Engineer
#  GitHub : https://github.com/Leox48/cyberark-cp-audit
#  License: MIT
#
#  DISCLAIMER: For use in authorized security assessments only.
# ══════════════════════════════════════════════════════════════════

# NO set -e here — we handle errors explicitly per command
# We only use -u (unbound variables) and -o pipefail
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load libraries
source "$SCRIPT_DIR/lib/colors.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/errors.sh"

# Load modules
source "$SCRIPT_DIR/modules/01_discovery.sh"
source "$SCRIPT_DIR/modules/02_permissions.sh"
source "$SCRIPT_DIR/modules/03_configuration.sh"
source "$SCRIPT_DIR/modules/04_sudoers.sh"
source "$SCRIPT_DIR/modules/05_appid_test.sh"
source "$SCRIPT_DIR/modules/06_host_controls.sh"

# ──────────────────────────────────────────────
# Global options (safe defaults)
# ──────────────────────────────────────────────
AUDIT_APPID=""
AUDIT_SAFE=""
SKIP_APPID_TEST=false
MODULES_TO_RUN="all"

# ──────────────────────────────────────────────
# Usage
# ──────────────────────────────────────────────
usage() {
    echo -e "${BWHITE}Usage:${NC}"
    echo "  $0 [OPTIONS]"
    echo ""
    echo -e "${BWHITE}Options:${NC}"
    echo "  -a <AppID>    AppID to test (required for module 05)"
    echo "  -s <Safe>     Safe name associated with the AppID"
    echo "  -m <modules>  Comma-separated list of modules to run (default: all)"
    echo "                Available: discovery,permissions,configuration,sudoers,appid,host"
    echo "  -n            Skip AppID restriction testing (module 05)"
    echo "  -h            Show this help"
    echo ""
    echo -e "${BWHITE}Examples:${NC}"
    echo "  sudo $0 -a MyAppID -s MySafe"
    echo "  sudo $0 -m discovery,permissions,sudoers"
    echo "  sudo $0 -n"
    echo ""
    echo -e "${YELLOW}  [!] Requires sudo for complete results${NC}"
    exit 0
}

# ──────────────────────────────────────────────
# Parse and validate arguments
# ──────────────────────────────────────────────
parse_args() {
    while getopts "a:s:m:nh" opt; do
        case $opt in
            a)
                AUDIT_APPID="$OPTARG"
                validate_appid "$AUDIT_APPID" || exit 1
                ;;
            s)
                AUDIT_SAFE="$OPTARG"
                validate_safe "$AUDIT_SAFE"
                ;;
            m)
                MODULES_TO_RUN="$OPTARG"
                # Validate module names
                IFS=',' read -ra MODS <<< "$MODULES_TO_RUN"
                for mod in "${MODS[@]}"; do
                    case "$mod" in
                        discovery|permissions|configuration|sudoers|appid|host) ;;
                        *)
                            echo -e "${RED}[!] Unknown module: '$mod'${NC}"
                            echo -e "    Valid modules: discovery,permissions,configuration,sudoers,appid,host"
                            exit 1
                            ;;
                    esac
                done
                ;;
            n) SKIP_APPID_TEST=true ;;
            h) usage ;;
            *)
                echo -e "${RED}[!] Unknown option. Use -h for help.${NC}"
                exit 1
                ;;
        esac
    done
}

# ──────────────────────────────────────────────
# Privilege check — warn but never block
# ──────────────────────────────────────────────
check_privileges() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}[!] Not running as root. Some checks may return incomplete results.${NC}"
        echo -e "${YELLOW}    For best results: sudo $0 $*${NC}"
        echo ""
        sleep 1
    fi
}

# ──────────────────────────────────────────────
# Module selector
# ──────────────────────────────────────────────
should_run() {
    local module="$1"
    if [ "$MODULES_TO_RUN" = "all" ]; then
        return 0
    fi
    echo "$MODULES_TO_RUN" | tr ',' '\n' | grep -qx "$module"
}

# ──────────────────────────────────────────────
# Safe module runner — catches unexpected errors
# ──────────────────────────────────────────────
run_module() {
    local module_name="$1"
    local module_func="$2"

    {
        $module_func
    } || {
        echo -e "\n${YELLOW}  [!] Module '$module_name' encountered an unexpected error and was skipped.${NC}"
        echo -e "${YELLOW}      This may be due to missing permissions or an unsupported configuration.${NC}\n"
    }
}

# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
main() {
    clear
    print_banner

    parse_args "$@"
    check_dependencies
    check_privileges "$@"

    echo -e "${WHITE}  Started at : $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e "${WHITE}  Running as : $(whoami) (UID: $EUID)${NC}"
    echo -e "${WHITE}  Hostname   : $(hostname -f 2>/dev/null || hostname 2>/dev/null || echo 'unknown')${NC}"
    echo -e "${WHITE}  OS         : $(grep -oP 'PRETTY_NAME="\K[^"]+' /etc/os-release 2>/dev/null || uname -s)${NC}"
    [ -n "$AUDIT_APPID" ] && echo -e "${WHITE}  AppID      : $AUDIT_APPID${NC}"
    [ -n "$AUDIT_SAFE"  ] && echo -e "${WHITE}  Safe       : $AUDIT_SAFE${NC}"
    [ "$MODULES_TO_RUN" != "all" ] && echo -e "${WHITE}  Modules    : $MODULES_TO_RUN${NC}"
    echo ""

    # Module 01 — Discovery (always runs, gates everything else)
    run_module "discovery" "run_discovery"

    if [ -z "${CP_INSTALL_DIR:-}" ]; then
        echo -e "\n${RED}[!] CyberArk CP installation not found on this host.${NC}"
        echo -e "${YELLOW}    If CP is installed in a non-standard path, the tool may have missed it.${NC}"
        echo -e "${YELLOW}    Checked paths: /opt/CARKaim, /opt/cyberark, /opt/CyberArk${NC}"
        echo -e "${YELLOW}    Tip: find / -name 'appprovider' 2>/dev/null${NC}\n"
        print_summary
        exit 0
    fi

    # Module 02 — Permissions
    should_run "permissions" && run_module "permissions" "run_permissions"

    # Module 03 — Configuration
    should_run "configuration" && run_module "configuration" "run_configuration"

    # Module 04 — Sudoers
    should_run "sudoers" && run_module "sudoers" "run_sudoers"

    # Module 05 — AppID Testing
    if $SKIP_APPID_TEST; then
        echo -e "\n${PURPLE}  [SKIP] AppID restriction testing skipped (-n flag)${NC}"
    elif ! should_run "appid"; then
        : # module not selected
    elif [ -z "$AUDIT_APPID" ]; then
        echo -e "\n${YELLOW}  [SKIP] AppID restriction testing skipped — no AppID provided.${NC}"
        echo -e "${YELLOW}         Use -a <AppID> to enable this module.${NC}"
        echo -e "${YELLOW}         Example: sudo $0 -a MyApp -s MySafe${NC}"
    else
        check_cp_daemon && run_module "appid" "run_appid_test"
    fi

    # Module 06 — Host Controls
    should_run "host" && run_module "host" "run_host_controls"

    # Summary
    print_summary
    echo -e "${WHITE}  Completed at: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo ""
}

main "$@"
