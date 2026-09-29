#!/bin/bash
# output.sh — Output formatting functions

source "$(dirname "${BASH_SOURCE[0]}")/colors.sh"

# ──────────────────────────────────────────────
# Section header (like linpeas)
# ──────────────────────────────────────────────
print_section() {
    echo ""
    echo -e "${BBLUE}╔══════════════════════════════════════════════╣${NC} ${BWHITE}$1${NC}"
}

print_section_end() {
    echo -e "${BBLUE}╚══════════════════════════════════════════════${NC}"
}

# ──────────────────────────────────────────────
# Finding severity output
# ──────────────────────────────────────────────
finding_critical() {
    echo -e "  ${BRED}[CRITICAL P0]${NC} $1"
    log_finding "CRITICAL" "$1"
}

finding_high() {
    echo -e "  ${RED}[HIGH P1]${NC} $1"
    log_finding "HIGH" "$1"
}

finding_medium() {
    echo -e "  ${YELLOW}[MEDIUM P2]${NC} $1"
    log_finding "MEDIUM" "$1"
}

finding_low() {
    echo -e "  ${ORANGE}[LOW P3]${NC} $1"
    log_finding "LOW" "$1"
}

finding_info() {
    echo -e "  ${CYAN}[INFO]${NC} $1"
}

finding_ok() {
    echo -e "  ${GREEN}[OK]${NC} $1"
}

finding_warn() {
    echo -e "  ${YELLOW}[WARN]${NC} $1"
}

finding_skip() {
    echo -e "  ${PURPLE}[SKIP]${NC} $1"
}

# ──────────────────────────────────────────────
# Evidence block
# ──────────────────────────────────────────────
print_evidence() {
    echo -e "  ${BWHITE}Evidence:${NC}"
    echo -e "  ${WHITE}$1${NC}"
}

# ──────────────────────────────────────────────
# Log findings to report file
# ──────────────────────────────────────────────
REPORT_FILE="/tmp/cyberark_cp_audit_$(date +%Y%m%d_%H%M%S).txt"
FINDINGS_COUNT=0
FINDINGS_CRITICAL=0
FINDINGS_HIGH=0
FINDINGS_MEDIUM=0
FINDINGS_LOW=0

log_finding() {
    local severity="$1"
    local message="$2"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$severity] $message" >> "$REPORT_FILE"
    FINDINGS_COUNT=$((FINDINGS_COUNT + 1))
    case "$severity" in
        CRITICAL) FINDINGS_CRITICAL=$((FINDINGS_CRITICAL + 1)) ;;
        HIGH)     FINDINGS_HIGH=$((FINDINGS_HIGH + 1)) ;;
        MEDIUM)   FINDINGS_MEDIUM=$((FINDINGS_MEDIUM + 1)) ;;
        LOW)      FINDINGS_LOW=$((FINDINGS_LOW + 1)) ;;
    esac
}

# ──────────────────────────────────────────────
# Print summary at the end
# ──────────────────────────────────────────────
print_summary() {
    echo ""
    echo -e "${BWHITE}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${BWHITE}║           AUDIT SUMMARY                      ║${NC}"
    echo -e "${BWHITE}╚══════════════════════════════════════════════╝${NC}"
    echo -e "  ${BRED}Critical (P0):${NC} $FINDINGS_CRITICAL"
    echo -e "  ${RED}High     (P1):${NC} $FINDINGS_HIGH"
    echo -e "  ${YELLOW}Medium   (P2):${NC} $FINDINGS_MEDIUM"
    echo -e "  ${ORANGE}Low      (P3):${NC} $FINDINGS_LOW"
    echo -e "  ${WHITE}Total findings: $FINDINGS_COUNT${NC}"
    echo ""
    echo -e "  ${CYAN}Full report saved to: ${REPORT_FILE}${NC}"
}

# ──────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────
print_banner() {
    echo -e "${BCYAN}"
    echo '  ██████╗██╗   ██╗██████╗ ███████╗██████╗  █████╗ ██████╗ ██╗  ██╗'
    echo ' ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝'
    echo ' ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████║██████╔╝█████╔╝ '
    echo ' ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██║██╔══██╗██╔═██╗ '
    echo ' ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║██║  ██║██║  ██╗'
    echo '  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝'
    echo -e "${NC}"
    echo -e "${BWHITE}  CyberArk Credential Provider Security Audit Tool${NC}"
    echo -e "${WHITE}  Version 1.0.0 — github.com/Leox48/cyberark-cp-audit${NC}"
    echo -e "${WHITE}  Author: Leonardo Sole — Offensive Security Engineer${NC}"
    echo ""
    echo -e "${YELLOW}  [!] For use in authorized security assessments only${NC}"
    echo ""
}
