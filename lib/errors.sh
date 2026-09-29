#!/bin/bash
# errors.sh — Centralized error handling and input validation

source "$(dirname "${BASH_SOURCE[0]}")/output.sh"

# ──────────────────────────────────────────────
# Safe command execution — never crashes the script
# Usage: safe_run <description> <command> [args...]
# Returns: 0 if ok, 1 if failed (never exits)
# ──────────────────────────────────────────────
safe_run() {
    local desc="$1"
    shift
    local output=""
    local exit_code=0

    output=$("$@" 2>&1) || exit_code=$?

    if [ $exit_code -ne 0 ]; then
        finding_info "Command failed ($desc): exit $exit_code"
        echo ""
        return 1
    fi

    echo "$output"
    return 0
}

# ──────────────────────────────────────────────
# Safe sudo execution
# Usage: safe_sudo <description> <command> [args...]
# ──────────────────────────────────────────────
safe_sudo() {
    local desc="$1"
    shift

    if ! command -v sudo &>/dev/null; then
        finding_warn "sudo not available — skipping: $desc"
        return 1
    fi

    if ! sudo -n true 2>/dev/null; then
        finding_warn "sudo requires password or is not configured — skipping: $desc"
        return 1
    fi

    local output=""
    local exit_code=0
    output=$(sudo "$@" 2>&1) || exit_code=$?

    if [ $exit_code -ne 0 ]; then
        finding_info "sudo command failed ($desc): exit $exit_code"
        return 1
    fi

    echo "$output"
    return 0
}

# ──────────────────────────────────────────────
# Safe file read — handles permissions gracefully
# Usage: safe_read <filepath>
# Returns file content or empty string
# ──────────────────────────────────────────────
safe_read() {
    local filepath="$1"

    if [ -z "$filepath" ]; then
        return 1
    fi

    if [ ! -e "$filepath" ]; then
        finding_warn "File not found: $filepath"
        return 1
    fi

    if [ -r "$filepath" ]; then
        cat "$filepath" 2>/dev/null
        return 0
    fi

    # Try with sudo
    local content=""
    content=$(sudo cat "$filepath" 2>/dev/null) || {
        finding_warn "Cannot read $filepath (no permission, even with sudo)"
        return 1
    }
    echo "$content"
    return 0
}

# ──────────────────────────────────────────────
# Safe grep — never fails even with no match
# Usage: safe_grep <pattern> <file_or_string>
# ──────────────────────────────────────────────
safe_grep() {
    local pattern="$1"
    local input="$2"

    if [ -f "$input" ]; then
        grep -i "$pattern" "$input" 2>/dev/null || true
    else
        echo "$input" | grep -i "$pattern" 2>/dev/null || true
    fi
}

# ──────────────────────────────────────────────
# Safe find — never fails
# Usage: safe_find <path> <options...>
# ──────────────────────────────────────────────
safe_find() {
    find "$@" 2>/dev/null || true
}

# ──────────────────────────────────────────────
# Check file permissions safely (cross-platform)
# Usage: is_world_readable <filepath>
# Returns 0 if world-readable, 1 if not
# ──────────────────────────────────────────────
is_world_readable() {
    local filepath="$1"

    if [ ! -e "$filepath" ]; then
        return 1
    fi

    # Use ls and parse the permission string — more portable than stat arithmetic
    local perms
    perms=$(ls -la "$filepath" 2>/dev/null | awk '{print $1}')

    # Check if the 'other' read bit is set (position 8 in -rwxrwxrwx)
    if echo "$perms" | grep -qE '^.{7}r'; then
        return 0
    fi
    return 1
}

# ──────────────────────────────────────────────
# Check file permissions as octal
# Usage: get_perms_octal <filepath>
# ──────────────────────────────────────────────
get_perms_octal() {
    local filepath="$1"
    stat -c "%a" "$filepath" 2>/dev/null || \
    stat -f "%OLp" "$filepath" 2>/dev/null || \
    echo "unknown"
}

# ──────────────────────────────────────────────
# Validate AppID format
# Usage: validate_appid <appid>
# ──────────────────────────────────────────────
validate_appid() {
    local appid="$1"

    if [ -z "$appid" ]; then
        echo -e "${RED}[!] AppID cannot be empty${NC}" >&2
        return 1
    fi

    # AppIDs should be alphanumeric + underscore + hyphen
    if echo "$appid" | grep -qP '[^a-zA-Z0-9_\-\.]'; then
        finding_warn "AppID '$appid' contains unusual characters — will be quoted for safety"
    fi

    # Check length
    if [ ${#appid} -gt 127 ]; then
        echo -e "${RED}[!] AppID exceeds maximum length (127 chars)${NC}" >&2
        return 1
    fi

    return 0
}

# ──────────────────────────────────────────────
# Validate Safe name format
# Usage: validate_safe <safe>
# ──────────────────────────────────────────────
validate_safe() {
    local safe="$1"

    if [ -z "$safe" ]; then
        finding_warn "No Safe specified — AppID restriction tests will use 'Safe=test' as probe"
        return 0
    fi

    if [ ${#safe} -gt 28 ]; then
        finding_warn "Safe name exceeds CyberArk maximum length (28 chars) — may cause errors"
    fi

    return 0
}

# ──────────────────────────────────────────────
# Check if CP is actually running (daemon check)
# ──────────────────────────────────────────────
check_cp_daemon() {
    local daemon_running=false

    if ps aux 2>/dev/null | grep -i "appprovider" | grep -qv grep; then
        daemon_running=true
    fi

    if ! $daemon_running; then
        finding_warn "appprovider daemon is NOT running — AppID tests will fail (CP must be running)"
        finding_info "To start CP: sudo systemctl start aimprv.service"
        return 1
    fi

    return 0
}

# ──────────────────────────────────────────────
# Dependency check at startup
# ──────────────────────────────────────────────
check_dependencies() {
    local missing=()
    local optional_missing=()

    # Required
    for cmd in bash grep find stat ls ps awk cut; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done

    # Optional but useful
    for cmd in sudo strings nc tcpdump sestatus aa-status openssl; do
        command -v "$cmd" &>/dev/null || optional_missing+=("$cmd")
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing required commands: ${missing[*]}${NC}"
        echo -e "${RED}    Cannot proceed without these.${NC}"
        exit 1
    fi

    if [ ${#optional_missing[@]} -gt 0 ]; then
        finding_info "Optional tools not found (some checks will be skipped): ${optional_missing[*]}"
    fi
}
