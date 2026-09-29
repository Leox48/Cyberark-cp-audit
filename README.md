# cyberark-cp-audit

> A security audit tool for CyberArk Credential Provider (AIM/CP) deployments on Linux.  
> Inspired by [linPEAS](https://github.com/carlospolop/PEASS-ng) — focused entirely on CyberArk CP attack surface.

```
  ██████╗██╗   ██╗██████╗ ███████╗██████╗  █████╗ ██████╗ ██╗  ██╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████║██████╔╝█████╔╝
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔══██║██╔══██╗██╔═██╗
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║  ██║██║  ██║██║  ██╗
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Platform](https://img.shields.io/badge/platform-Linux-blue)
![Shell](https://img.shields.io/badge/shell-bash-green)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-leonardo--sole48-blue?logo=linkedin)](https://www.linkedin.com/in/leonardo-sole48/)

---

## What is this?

`cyberark-cp-audit` is a bash-based security assessment tool designed to audit CyberArk **Credential Provider (CP/AIM)** installations on Linux hosts.

CyberArk CP is widely deployed in enterprise environments to provide application-to-application credential management, eliminating hardcoded passwords. While the CyberArk Vault is heavily hardened, the CP agent runs on **application hosts** — a much larger and more accessible attack surface.

This tool automates the manual checks typically performed during a CyberArk CP security assessment, covering:

- Installation discovery and version fingerprinting
- Sensitive file permission analysis (credential file, entropy file, cache)
- Configuration review (VaultAccessInterval, cache settings, vault.ini)
- Sudoers analysis for privilege escalation and user impersonation paths
- AppID restriction testing (OS User, Path restriction bypass)
- Host security controls (SELinux, AppArmor, PATH hijacking, SUID)

---

## Companion Research

This tool is part of the [pam-security-assessments](https://github.com/Leox48/pam-security-assessments) repository.  
Full methodology, attack chains, and hardening guidance: [cyberark/credential-provider-methodology.md](https://github.com/Leox48/pam-security-assessments/blob/main/cyberark/cyberark-cp-security-research.md)

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/Leox48/cyberark-cp-audit.git
cd cyberark-cp-audit
chmod +x cyberark-cp-audit.sh

# Full audit (recommended: run with sudo for complete results)
sudo ./cyberark-cp-audit.sh

# Passive audit — no AppID testing
sudo ./cyberark-cp-audit.sh -n

# Full audit with AppID restriction testing (real environment)
sudo ./cyberark-cp-audit.sh -a <YourAppID> -s <YourSafe>

# Full audit using the mock lab environment (see Lab Environment section)
sudo ./cyberark-cp-audit.sh -a MockApp -s MockSafe

# Discovery and permissions only
sudo ./cyberark-cp-audit.sh -m discovery,permissions
```

---

## Modules

| Module | Flag | Description |
|---|---|---|
| `01_discovery` | always | Find CP installation, version, running process |
| `02_permissions` | `permissions` | Audit .cred, .entropy, cache, log file permissions |
| `03_configuration` | `configuration` | Review vault.ini, VaultAccessInterval, cache settings |
| `04_sudoers` | `sudoers` | Analyze sudoers for NOPASSWD:ALL and user impersonation |
| `05_appid_test` | `appid` | Test AppID OS User and Path restrictions via clipasswordsdk |
| `06_host_controls` | `host` | SELinux, AppArmor, PATH hijacking, SUID, connectivity |

Run specific modules with `-m`:
```bash
sudo ./cyberark-cp-audit.sh -m discovery,sudoers,appid -a MockApp -s MockSafe
```

---

## Output Example

```
╔══════════════════════════════════════════════╣ CyberArk CP — Installation Discovery
  [OK]    Installation directory found: /opt/CARKaim
  [OK]    SDK binary found: /opt/CARKaim/sdk/clipasswordsdk
  [OK]    Main configuration file found: /etc/opt/CARKaim/conf/basic_appprovider.conf
  [OK]    CP Version: 14.2.5.2
  [OK]    CP process running — PID: 2237, User: root
  [MEDIUM P2] appprovider daemon is running as ROOT — CWE-250

╔══════════════════════════════════════════════╣ File & Directory Permission Analysis
  [OK]    Credential file permissions are restricted
  [MEDIUM P2] Entropy file is world-readable — CWE-732
  Evidence: -rw-r--r-- 1 root root 1056 appprovideruser.cred.entropy
  [MEDIUM P2] Permission mismatch: .cred (640) vs .entropy (644)

╔══════════════════════════════════════════════╣ CP Configuration Analysis
  [MEDIUM P2] VaultAccessInterval is 365 days — CWE-613
              In an incident response scenario, revoked credentials will continue
              to be distributed from local cache for up to 365 days.

╔══════════════════════════════════════════════╣ Sudoers & Privilege Analysis
  [HIGH P1] Accounts with unrestricted NOPASSWD: ALL sudo — CWE-269
  Evidence: nxautomation (ALL) NOPASSWD: ALL
  [HIGH P1] Passwordless sudo rules allowing user impersonation — CWE-269
  Evidence: %Admins.App.Operations ALL=(root) NOPASSWD: /usr/bin/su - appuser
  [CRITICAL P0] Target user 'appuser' matches application process user
                Attack chain: compromise group → sudo su - appuser → clipasswordsdk → extract credentials

╔══════════════════════════════════════════════╣ AppID Restriction Testing
  [-] current_user: APPAP133E — OSUser restriction ACTIVE ✓
  [-] root: APPAP133E — OSUser restriction ACTIVE ✓
  [!] appuser: APPAP004E — Authentication PASSED — Safe/Object not found
      → User 'appuser' is authorized for AppID 'MyAppID'
  [HIGH P1] Path restriction NOT configured — CWE-284
            Any process running as 'appuser' can extract credentials

╔══════════════════════════════════════════════╗
║           AUDIT SUMMARY                      ║
╚══════════════════════════════════════════════╝
  Critical (P0): 1
  High     (P1): 3
  Medium   (P2): 4
  Low      (P3): 2
  Total findings: 10

  Full report saved to: /tmp/cyberark_cp_audit_20260922_103045.txt
```

---

## Options Reference

```
Usage: ./cyberark-cp-audit.sh [OPTIONS]

Options:
  -a <AppID>    AppID to test (required for AppID restriction testing)
  -s <Safe>     Safe name associated with the AppID
  -m <modules>  Comma-separated list of modules to run (default: all)
                Available: discovery,permissions,configuration,sudoers,appid,host
  -n            Skip AppID restriction testing (module 05)
  -h            Show help
```

---

## What it checks (mapped to CWE/finding classes)

| Check | CWE | Severity |
|---|---|---|
| CP daemon running as root | CWE-250 | Medium |
| `.entropy` file world-readable | CWE-732 | Medium |
| `.cred` / `.entropy` permission mismatch | CWE-732 | Medium |
| Cache DB world-readable | CWE-732 | High |
| Cache DB cleartext content | CWE-312 | High |
| Cleartext credentials in vault.ini | CWE-312 | High |
| VaultAccessInterval > 24h | CWE-613 | Medium |
| NOPASSWD: ALL sudo grants | CWE-269 | High |
| User impersonation via sudo | CWE-269 | High/Critical |
| Application user impersonation + CP access | CWE-269 + CWE-284 | Critical |
| AppID OS User restriction bypass | CWE-284 | Critical |
| Path restriction not configured | CWE-284 | High |
| AppID enumeration via error differentiation | CWE-203 | Low |
| Sensitive information in logs | CWE-532 | Low |
| SELinux/AppArmor disabled | CWE-284 | Low |
| PATH hijacking potential | CWE-427 | Medium |

---

## Lab Environment (Testing without CyberArk)

You don't need a real CyberArk installation to test this tool.
The included `lab/setup-mock-env.sh` script creates a simulated CP environment on any Linux host.

### Mock credentials

| Parameter | Value |
|---|---|
| AppID | `MockApp` |
| Safe | `MockSafe` |
| Authorized OS User | `mockappuser` |
| Mock password returned | `MockP@ssw0rd!2026` |

### Quick lab setup

```bash
# 1. Create the vulnerable mock environment
chmod +x ./lab/setup-mock-env.sh
sudo ./lab/setup-mock-env.sh --vuln

# 2. Run passive audit (no AppID testing)
sudo ./cyberark-cp-audit.sh -n

# 3. Run full audit with AppID testing
sudo ./cyberark-cp-audit.sh -a MockApp -s MockSafe

# 4. Manually verify the mock AppID restriction works
#    This should return the mock password (authorized user):
sudo -u mockappuser /opt/CARKaim/sdk/clipasswordsdk GetPassword \
  -p AppDescs.AppID=MockApp \
  -p "Query=Safe=MockSafe" \
  -o Password
# → MockP@ssw0rd!2026

#    This should be blocked (unauthorized user):
/opt/CARKaim/sdk/clipasswordsdk GetPassword \
  -p AppDescs.AppID=MockApp \
  -p "Query=Safe=MockSafe" \
  -o Password
# → APPAP133E Failed to verify application authentication data: OSUser "youruser" is unauthorized

# 5. Compare with the hardened configuration
sudo ./lab/setup-mock-env.sh --clean
sudo ./lab/setup-mock-env.sh --hardened
sudo ./cyberark-cp-audit.sh -n

# 6. Cleanup
sudo ./lab/setup-mock-env.sh --clean
```

### What the mock simulates

| Component | Real CyberArk | Mock |
|---|---|---|
| `/opt/CARKaim/` directory | CP binaries | Fake structure + mock SDK script |
| `clipasswordsdk` | Calls real CP daemon | Bash script returning real error codes |
| `vault.ini` | Real Vault IP | Fake IP `192.168.100.50` |
| `.cred` file | Encrypted service account | Fake encrypted-looking content |
| `.entropy` file | Real entropy material | Fake content, intentionally world-readable |
| `main_appprovider.conf` | Real config | Identical structure, VaultAccessInterval=365d |
| OS User restriction | Vault-enforced | Enforced by the mock SDK script |

### Manual mock environment (alternative)

```bash
# Create fake CP structure
sudo mkdir -p /opt/CARKaim/{bin,sdk,lib}
sudo mkdir -p /etc/opt/CARKaim/{conf,vault}
sudo mkdir -p /var/opt/CARKaim/{logs,cache}

# Create fake config files
sudo bash -c 'cat > /etc/opt/CARKaim/conf/basic_appprovider.conf << EOF
[Main]
AppProviderVaultFile="/etc/opt/CARKaim/vault/vault.ini"
AppProviderCredFile="/etc/opt/CARKaim/vault/appprovideruser.cred"
LogsFolder="/var/opt/CARKaim/logs"
LocalParmsFileFolder="/var/opt/CARKaim"
EOF'

# Create fake vault.ini
sudo bash -c 'cat > /etc/opt/CARKaim/vault/vault.ini << EOF
VAULT = "TESTVAULT"
ADDRESS=192.168.1.100
PORT=1858
EOF'

# Create fake credential files with intentional permission misconfiguration
sudo bash -c 'echo "SecretFileType=Password
Username=Prov_testhost
Secret=AABBCCDD" > /etc/opt/CARKaim/vault/appprovideruser.cred'
sudo chmod 640 /etc/opt/CARKaim/vault/appprovideruser.cred

sudo bash -c 'echo "entropy_data=XXYYZZ" > /etc/opt/CARKaim/vault/appprovideruser.cred.entropy'
sudo chmod 644 /etc/opt/CARKaim/vault/appprovideruser.cred.entropy  # intentional misconfiguration

# Create fake version file
sudo bash -c 'echo "version=\"14.02\"
release=\"5.2\"" > /var/opt/CARKaim/.version_info'

echo "[+] Mock CP environment created. Run: sudo ./cyberark-cp-audit.sh -n"
```

---

## Disclaimer

This tool is provided for **authorized security testing and educational purposes only**.

- Only use on systems you have explicit written authorization to test
- The author is not responsible for any unauthorized or illegal use
- Always follow responsible disclosure practices if findings are identified

---

## Author

**Leonardo Sole** — Offensive Security Engineer

[![LinkedIn](https://img.shields.io/badge/LinkedIn-leonardo--sole48-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/leonardo-sole48/)
[![GitHub](https://img.shields.io/badge/GitHub-Leox48-black?style=flat&logo=github)](https://github.com/Leox48)

---

## License

MIT License — see [LICENSE](./LICENSE) for details.

---

*If you find this useful, a ⭐ is appreciated.*
