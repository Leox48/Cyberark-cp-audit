#!/bin/bash
# setup-mock-env.sh
# Creates a mock CyberArk CP environment to test cyberark-cp-audit
# without requiring a real CyberArk installation.
#
# Usage: sudo ./lab/setup-mock-env.sh [--vuln | --hardened | --clean]
#
# --vuln     (default) Create environment with intentional misconfigurations
# --hardened Create environment with correct security settings
# --clean    Remove the mock environment

set -e

MODE="${1:---vuln}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] This script must be run as root${NC}"
    exit 1
fi

clean_env() {
    echo -e "${YELLOW}[*] Removing mock CP environment...${NC}"
    rm -rf /opt/CARKaim
    rm -rf /etc/opt/CARKaim
    rm -rf /var/opt/CARKaim
    # Remove mock application user if it was created by this script
    if id "mockappuser" &>/dev/null; then
        userdel -r mockappuser 2>/dev/null || true
        echo -e "${GREEN}[+] Mock user 'mockappuser' removed${NC}"
    fi
    echo -e "${GREEN}[+] Mock environment removed${NC}"
    exit 0
}

[ "$MODE" = "--clean" ] && clean_env

echo -e "${CYAN}"
echo "  ┌─────────────────────────────────────────────┐"
echo "  │  CyberArk CP Mock Environment Setup         │"
echo "  │  Mode: $MODE                        │"
echo "  └─────────────────────────────────────────────┘"
echo -e "${NC}"

# ── Directory structure ───────────────────────────
echo -e "${YELLOW}[*] Creating directory structure...${NC}"

mkdir -p /opt/CARKaim/{bin,sdk,lib,conf}
mkdir -p /etc/opt/CARKaim/{conf,vault}
mkdir -p /var/opt/CARKaim/{logs/old,cache,temp}

# ── basic_appprovider.conf ────────────────────────
echo -e "${YELLOW}[*] Creating basic_appprovider.conf...${NC}"

cat > /etc/opt/CARKaim/conf/basic_appprovider.conf << 'EOF'
[Main]
AppProviderParmsSafe="AppProviderConf"
AppProviderVaultParmsFolder=Root
AppProviderVaultParmsFile="main_appprovider.conf.linux.14.02"
AppProviderVaultFile="/etc/opt/CARKaim/vault/vault.ini"
AppProviderCredFile="/etc/opt/CARKaim/vault/appprovideruser.cred"
LogsFolder="/var/opt/CARKaim/logs"
LocalParmsFileFolder="/var/opt/CARKaim"
TempFolder="/var/opt/CARKaim/temp"
PIMConfigurationSafe="PVWAConfig"
PIMConfigurationFolder="Root"
EOF

# ── vault.ini ─────────────────────────────────────
echo -e "${YELLOW}[*] Creating vault.ini...${NC}"

cat > /etc/opt/CARKaim/vault/vault.ini << 'EOF'
VAULT = "MOCKVAULT01"
ADDRESS=192.168.100.50
PORT=1858
TIMEOUT=8
EOF

# ── Credential files ──────────────────────────────
echo -e "${YELLOW}[*] Creating credential files...${NC}"

cat > /etc/opt/CARKaim/vault/appprovideruser.cred << 'EOF'
SecretFileType=Password
SecretFileVersion=3
Username=Prov_mockhost
VerificationsFlag=197665
Secret=BA122EBD8D114D06797E277BA930FC5CC93054E9C123058528F32A3D4568A710
ExternalAuthentication=None
AdditionalInformation=B85E3E25607949C7C49A67D9D2DC70D6D033E350943CADD6812171A50F94605C
EOF

echo "entropy_material=A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6" \
    > /etc/opt/CARKaim/vault/appprovideruser.cred.entropy

# ── main_appprovider.conf ─────────────────────────
echo -e "${YELLOW}[*] Creating main_appprovider.conf...${NC}"

if [ "$MODE" = "--hardened" ]; then
    VAULT_ACCESS_INTERVAL=3600
else
    VAULT_ACCESS_INTERVAL=31536000  # 365 days — intentional misconfiguration
fi

cat > /var/opt/CARKaim/main_appprovider.conf.linux.14.02 << EOF
[Main]
MaxConcurrentRequests=40
AutomaticParmsRefreshInterval=3600
ProviderCacheFolder=/var/opt/CARKaim/cache

[Debug]
#CacheDebugLevels=1,2

[Cache]
CacheLevel=persistent
CacheFile=/var/opt/CARKaim/cache/appprovider_cache.db
CacheRefreshInterval=1500
KeyStorage=Local
VaultAccessInterval=${VAULT_ACCESS_INTERVAL}
CachedSecretExpiry=168

[TCP]
Port=18923
EOF

# ── Version info ──────────────────────────────────
echo -e "${YELLOW}[*] Creating version info...${NC}"

cat > /var/opt/CARKaim/.version_info << 'EOF'
version="14.02"
release="5.2"
EOF

# ── Mock log files ────────────────────────────────
echo -e "${YELLOW}[*] Creating mock log files...${NC}"

cat > /var/opt/CARKaim/logs/APPConsole.log << 'EOF'
[01/09/2026 | 04:14:12] |  ::  | APPAP435I Credential Provider cache is encrypted in local mode
[01/09/2026 | 04:14:12] |  ::  | APPAP032I Main parameters file [main_appprovider.conf.linux.14.02] was loaded successfully
[01/09/2026 | 04:14:13] |  ::  | APPAP258I Supported addresses for this provider [192.168.100.10;mockhost;mockhost.corp.internal;fe80::1]
[01/09/2026 | 04:14:13] |  ::  | APPAP035I Application Password Provider [Prov_mockhost] on machine [192.168.100.10] version [14.2.5.2] is up [AAM mode] and working with Vault [192.168.100.50]
EOF

touch /var/opt/CARKaim/logs/APPAudit.log
touch /var/opt/CARKaim/logs/APPTrace.log

# ── Mock cache files ──────────────────────────────
echo -e "${YELLOW}[*] Creating mock cache...${NC}"

# Create a fake SQLite-like file (not a real DB, just for testing)
echo "SQLite format 3 mock_cache_data" > /var/opt/CARKaim/cache/appprovider_cache.db
echo "entropy_data_for_cache" > /var/opt/CARKaim/cache/file.opy

# ── Mock SDK binary (wrapper script) ──────────────
echo -e "${YELLOW}[*] Creating mock SDK binary...${NC}"

cat > /opt/CARKaim/sdk/clipasswordsdk << 'MOCKEOF'
#!/bin/bash
# Mock clipasswordsdk for testing cyberark-cp-audit
# Simulates CyberArk CP error codes based on calling user

APPID=""
SAFE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -p)
            case "$2" in
                AppDescs.AppID=*) APPID="${2#AppDescs.AppID=}" ;;
                Query=Safe=*)     SAFE="${2#Query=Safe=}" ;;
            esac
            shift 2 ;;
        *) shift ;;
    esac
done

CALLING_USER=$(whoami)
AUTHORIZED_USER="mockappuser"
VALID_APPID="MockApp"
VALID_SAFE="MockSafe"

# Simulate error codes
if [ -z "$APPID" ] || [ -z "$SAFE" ]; then
    echo "APPAP081E Request Message content is invalid" >&2
    exit 1
fi

if [ "$APPID" = "FakeAppID"* ]; then
    echo "APPBC008E Problem occurred while trying to use user in the Vault (Error: ITATS982E User $APPID is not defined. Diagnostic Info: -1)" >&2
    exit 1
fi

if [ "$APPID" != "$VALID_APPID" ]; then
    echo "APPAP425E Failed getting application ($APPID) from backend. Diagnostic Info: 10" >&2
    exit 1
fi

if [ "$CALLING_USER" != "$AUTHORIZED_USER" ]; then
    echo "APPAP133E Failed to verify application authentication data: OSUser \"$CALLING_USER\" is unauthorized" >&2
    exit 1
fi

if [ "$SAFE" != "$VALID_SAFE" ]; then
    echo "APPAP004E Password object matching query [Safe=$SAFE] was not found (Diagnostic Info: 1)." >&2
    exit 1
fi

# Authorized user + correct Safe = return mock password
echo "MockP@ssw0rd!2026"
MOCKEOF

chmod +x /opt/CARKaim/sdk/clipasswordsdk

# Create appprovider mock
cat > /opt/CARKaim/bin/appprovider << 'EOF'
#!/bin/bash
echo "CyberArk AIM mock appprovider — not a real daemon"
EOF
chmod +x /opt/CARKaim/bin/appprovider

# ── Permissions ───────────────────────────────────
echo -e "${YELLOW}[*] Setting permissions...${NC}"

# Always correct permissions for .cred
chmod 640 /etc/opt/CARKaim/vault/appprovideruser.cred
chown root:root /etc/opt/CARKaim/vault/appprovideruser.cred

if [ "$MODE" = "--hardened" ]; then
    # Correct permissions
    chmod 640 /etc/opt/CARKaim/vault/appprovideruser.cred.entropy
    chmod 640 /var/opt/CARKaim/logs/APPConsole.log
    chmod 640 /var/opt/CARKaim/logs/APPAudit.log
    chmod 640 /var/opt/CARKaim/logs/APPTrace.log
    chmod 640 /var/opt/CARKaim/cache/file.opy
    chmod 600 /var/opt/CARKaim/cache/appprovider_cache.db
    echo -e "${GREEN}[+] Hardened permissions applied${NC}"
else
    # Intentional misconfigurations — only the ones relevant to CyberArk CP
    chmod 644 /etc/opt/CARKaim/vault/appprovideruser.cred.entropy  # world-readable — FINDING P2
    chmod 644 /var/opt/CARKaim/logs/APPConsole.log                  # world-readable — FINDING P2
    chmod 644 /var/opt/CARKaim/logs/APPAudit.log                    # world-readable — FINDING P2
    chmod 644 /var/opt/CARKaim/logs/APPTrace.log                    # world-readable — FINDING P2
    chmod 644 /var/opt/CARKaim/cache/file.opy                       # world-readable — FINDING P2
    chmod 600 /var/opt/CARKaim/cache/appprovider_cache.db           # correctly restricted (not a finding)
    echo -e "${RED}[+] Vulnerable permissions applied (intentional misconfigurations)${NC}"
fi

chmod 700 /var/opt/CARKaim/cache
chmod +x /opt/CARKaim/sdk/clipasswordsdk

# ── Mock application user ──────────────────────────
# This user simulates the OS User authorized in the AppID restriction.
# The mock clipasswordsdk returns a password only when called as 'mockappuser'.
echo -e "${YELLOW}[*] Creating mock application user 'mockappuser'...${NC}"

if id "mockappuser" &>/dev/null; then
    echo -e "${CYAN}    User 'mockappuser' already exists — skipping creation${NC}"
else
    useradd -r -s /bin/bash -m -c "CyberArk CP mock application user" mockappuser 2>/dev/null || {
        echo -e "${YELLOW}    Warning: could not create 'mockappuser' — AppID auth test will show OSUser unauthorized${NC}"
        echo -e "${YELLOW}    This is expected on systems where useradd is restricted${NC}"
    }
    if id "mockappuser" &>/dev/null; then
        echo -e "${GREEN}    User 'mockappuser' created${NC}"
    fi
fi

# ── Summary ───────────────────────────────────────
echo ""
echo -e "${GREEN}[+] Mock CP environment created successfully!${NC}"
echo ""
echo -e "  Mode: ${YELLOW}$MODE${NC}"
echo ""
echo -e "  ${BWHITE}Mock credentials:${NC}"
echo -e "  AppID          : ${CYAN}MockApp${NC}"
echo -e "  Safe           : ${CYAN}MockSafe${NC}"
echo -e "  Authorized user: ${CYAN}mockappuser${NC}  (OS User restriction)"
echo ""
echo -e "  ${BWHITE}Step 1 — Passive audit (no AppID testing):${NC}"
echo -e "  ${WHITE}sudo ./cyberark-cp-audit.sh -n${NC}"
echo ""
echo -e "  ${BWHITE}Step 2 — Full audit with AppID restriction testing:${NC}"
echo -e "  ${WHITE}sudo ./cyberark-cp-audit.sh -a MockApp -s MockSafe${NC}"
echo ""
echo -e "  ${BWHITE}Step 3 — Test credential extraction as authorized user:${NC}"
echo -e "  ${WHITE}sudo -u mockappuser /opt/CARKaim/sdk/clipasswordsdk GetPassword \\${NC}"
echo -e "  ${WHITE}  -p AppDescs.AppID=MockApp -p \"Query=Safe=MockSafe\" -o Password${NC}"
echo -e "  ${CYAN}  → Expected output: MockP@ssw0rd!2026${NC}"
echo ""
echo -e "  ${BWHITE}Step 4 — Verify restriction blocks other users:${NC}"
echo -e "  ${WHITE}/opt/CARKaim/sdk/clipasswordsdk GetPassword \\${NC}"
echo -e "  ${WHITE}  -p AppDescs.AppID=MockApp -p \"Query=Safe=MockSafe\" -o Password${NC}"
echo -e "  ${CYAN}  → Expected output: APPAP133E OSUser unauthorized${NC}"
echo ""
if [ "$MODE" != "--hardened" ]; then
    echo -e "  ${YELLOW}Expected findings in vulnerable mode:${NC}"
    echo -e "  ${RED}  [MEDIUM P2]${NC} .entropy file world-readable (CWE-732)"
    echo -e "  ${RED}  [MEDIUM P2]${NC} VaultAccessInterval = 365 days (CWE-613)"
    echo -e "  ${RED}  [MEDIUM P2]${NC} Log files world-readable (CWE-532)"
    echo -e "  ${RED}  [LOW P3]   ${NC} Information disclosure in logs (CWE-532)"
    echo -e "  ${CYAN}  [OK]       ${NC} .cred file correctly restricted (640)"
    echo -e "  ${CYAN}  [OK]       ${NC} Cache database correctly restricted (600)"
    echo -e "  ${CYAN}  [OK]       ${NC} Installation directory — no world-writable files"
    echo ""
fi
echo -e "  ${BWHITE}To remove the mock environment:${NC}"
echo -e "  ${WHITE}sudo ./lab/setup-mock-env.sh --clean${NC}"
echo ""
