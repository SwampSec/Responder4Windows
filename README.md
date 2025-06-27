# Responder4Windows

> A customized version of [Responder](https://github.com/lgandx/Responder) built to run natively on **Windows 10/11**. Includes Windows compatibility patches, an auto-elevating interface selector, and support for Python 3.x. Fully usable without WSL or Linux.

---

## 🔧 Project Background

Responder is a LLMNR, NBT-NS and mDNS poisoner that can capture and relay NTLM credentials in internal networks. This edition is modified for Windows use and includes enhancements for portability, reliability, and ease of use on modern systems.

---

## 🩛 Windows-Specific Enhancements

- ✅ Replaced Linux-only commands in `settings.py` with Windows equivalents:
  - `ifconfig` → `ipconfig`
  - `netstat` → `route print`
  - `resolvectl` → `ipconfig /all`
- ✅ Rewrote root check (`os.geteuid`) to detect **Administrator** on Windows
- ✅ `ResponderLauncher.bat`:
  - Auto-elevates to Administrator
  - Auto-detects active interfaces and IPs
  - Prompts user to select interface
- ✅ Python 3.13+ compatible

---

## 🚀 How to Use

### 📦 Prerequisites

Before running Responder4Windows, ensure the following are installed:

#### ✅ Required Software

- [Python 3.x for Windows](https://www.python.org/downloads/)
- Git for Windows (optional, but helpful for updates)

#### ✅ Python Dependencies

Install all required packages using:

```powershell
pip install -r requirements.txt
```

Or individually:

```powershell
pip install netifaces pycryptodome colorama six impacket psutil tabulate
```

#### 🧾 `requirements.txt` contents:

```
netifaces
pycryptodome
colorama
six
impacket
psutil
tabulate
```

> 💡 If you plan to use patched Responder tools like `RunFinger.py`, `FindSQLSrv.py`, or Impacket-based scripts like `secretsdump.py`, the full list is strongly recommended.

---

### ▶️ Launch

```cmd
ResponderLauncher.bat
```

- Auto-elevates as Administrator
- Prompts for an active interface
- Launches Responder with selected IP

Or run manually:
```powershell
python responder.py -I ALL -i <your-ip> -v
```

---

## 💡 Example Output

```
[*] Detecting network interfaces...
  [1] Wi-Fi - 10.88.88.98
  [2] Ethernet - 192.168.1.74
  [3] VPN - 172.16.0.2
[*] Select an interface number to use for Responder:
```

---

## ⚠️ Known Limitations on Windows

Due to Windows security architecture, the following ports may not be bindable:
- `135`, `445`, `5355`, `5353`, `5986`, `443`, `636`

➡️ These services are usually owned by Windows services (SMB, DNS Client, WinRM).  
➡️ You may still run HTTP, FTP, DNS, SQL, Kerberos, LDAP, etc.

---

## 📁 File Structure

| File | Description |
|------|-------------|
| `Responder.py`         | Patched Python script for Windows |
| `settings.py`          | Rewritten to use Windows-compatible commands |
| `ResponderLauncher.bat`| Launcher with admin + IP/interface selector |
| `README.md`            | This file |
| `interfaces.txt`       | Temp output of interface scan |
| `.gitignore`           | Excludes logs, cache, pyc files |
| `windows_tools/`         | Windows-compatible versions of auxiliary tools |

---
## 🧰 Windows-Compatible Tools (`/Windows_tools`)

This folder contains patched and enhanced versions of Responder and Impacket scripts originally designed for Linux. These versions are rewritten or adapted to run natively on Windows 10/11 without WSL.

Each script in this folder is named with a `_Windows.py` suffix and is tailored for use in offensive security assessments where Windows hosts are the primary toolset.

---

### 📁 Script List & Descriptions

| Script                     | Status      | Description                                                                 |
|----------------------------|-------------|-----------------------------------------------------------------------------|
| `RunFinger_Windows.py`     | ✅ Complete | Enumerates MSRPC endpoint UUIDs over TCP/135 using Impacket. Adds CIDR support and CSV export. |
| `FindSQLSrv_Windows.py`    | 🛠️ Planned  | SQL Server broadcast discovery using Windows-safe UDP broadcast (port 1434). |
| `DNSUpdate_Windows.py`     | 🛠️ Planned  | Sends spoofed DNS updates with modified socket usage for Windows.           |
| `MultiRelay_Windows.py`    | 🔬 Planned  | NTLM relay framework over HTTP/LDAP. SMB features disabled for Windows compatibility. |
| `SMBFinger_Windows.py`     | 🔬 Planned  | SMB enumeration using Impacket SMBConnection, replacing Linux tools like `smbclient`. |
| `Netview_Windows.py`       | 🛠️ Planned  | NetBIOS and DNS hostname enumeration without `nmblookup`.                   |

### Scripts to Fix
#### Minimal or Minor Tweaks Needed (Start Here)
**Script / Tool | Description | Action Needed**
- [x] RunFinger.py | MSRPC endpoint mapper via Impacket | ✅ Minor cleanup (path handling, verbosity)
- [ ] netview.py (Impacket) | NetBIOS scanner | ✅ Update DNS logic, avoid nmblookup
- [x] DNSUpdate.py | Sends DNS registration updates | ✅ Adjust socket binding, test for admin interface use
- [x] FindSQLSrv.py | SQL Server discovery via broadcast | ✅ Replace broadcast socket logic

#### Fully Fixable (Moderate Patching Required)
**Script / Tool | Description | Action Needed**
- [ ] ntlmrelayx.py | NTLM relay to SMB/HTTP/LDAP | ⚠️ Disable SMB relay, allow HTTP/LDAP-only
- [ ] rdp_check.py (Impacket) | RDP CredSSP vulnerability check | ⚠️ Patch socket error handling for port 3389
- [ ] SMBFinger/ | Finger SMB shares via smbclient, etc. | ⚠️ Rewrite using impacket.smbconnection
- [x] MultiRelay.py | NTLM relay engine with custom modules | ⚠️ Strip SMB/server logic and isolate HTTP logic only

#### Needs Major Rewrite
**Script / Tool | Description | Action Needed**
- [ ] MultiRelay/ | All custom relay modules + raw socket logic | ❌ Linux-only raw socket + multithread — needs full rearchitecture
- [ ] Icmp-Redirect.py | Sends raw ICMP redirect packets | ❌ Requires raw socket perms → not supported on Windows
- [ ] BrowserListener.py | NetBIOS datagram listener (port 138) | ❌ Not usable on Windows due to port/service conflicts

#### Already Works (No Changes Needed)
**Script / Tool | Description**
- secretsdump.py | Dumps local/remote NTDS and SAM hashes
- wmiexec.py | WMI remote command execution
- smbexec.py | SMB-based service command exec
- dcomexec.py | DCOM remote execution
- psexec.py | PsExec-style SMB execution
- ticketer.py | Kerberos TGT generator
- getTGT.py | Get TGT from KDC
- addcomputer.py | Add a computer to domain
- GetUserSPNs.py | Kerberoasting via SPNs
- lookupsid.py | SID brute-force and user enumeration
- RunFingerPackets.py | Pure Python MSRPC packet templates
- odict.py | OrderedDict shim used in legacy Python

---

### 🛠️ Feature Enhancements Across Tools

- Replaced Linux-only socket options with cross-platform code
- Removed raw socket dependencies (unsupported in Windows)
- Replaced CLI parsing with `argparse` for usability
- CSV export support for report writing
- Graceful error handling for offline hosts or blocked ports
- CIDR and list-based input support for easier mass-scanning

---

### 💡 Usage Example

```powershell
python windows_tools\\RunFinger_Windows.py -i 192.168.1.0/24 --csv output.csv
```

---

> All original scripts remain in place under their default names.  
> This folder is intended for pentesters, red teamers, or lab researchers who prefer or require a Windows-native toolchain.

---

## 🧠 Advanced Module Details (from Original Responder)

> ⚠️ Some features may not work on Windows. Full support available in Linux environments.

### ✅ Auth Servers

- **SMB**: Supports NTLMv1/v2, LM downgrade (`--lm`) and ESS bypass (`--disable-ess`)  
  ❌ *Not functional on Windows due to port 445 binding*
- **MSSQL**: Captures hashes over TCP 1433  
- **HTTP/HTTPS**: NTLM + Basic auth capture; supports WebDAV  
- **LDAP/LDAPS**: Captures NTLM or cleartext auth over 389/636  
- **DCE-RPC, RDP, WinRM**: Useful for legacy services  
  ⚠️ *Some may not bind on Windows due to system conflicts*
- **FTP/IMAP/SMTP/POP3**: Captures cleartext login attempts
- **DNS (UDP 53)**: Answers A/SRV records, useful with spoofing

---

## 🔨 Additional Tools (Mostly Linux Only)

- `tools/DHCP.py`: Rogue DHCP server (inject DNS + WPAD)
- `tools/Icmp-Redirect.py`: ICMP MITM attack for legacy hosts
- `tools/RunFinger.py`: RPC endpoint mapper
- Passive mode (`--analyze`) logs LLMNR/NBT-NS/MDNS queries silently

---

## 📜 CLI Reference

```bash
-A, --analyze           Analyze mode (no poisoning)
-I, --interface=IFACE   Interface to use (e.g., ALL, eth0, etc.)
-i, --ip=ADDR           Local IP to use
-d, --DHCP              Rogue DHCP server (requires Linux)
-D, --DHCP-DNS          Inject DNS server into DHCP response
-w, --wpad              Start WPAD rogue proxy server
-F, --ForceWpadAuth     Force auth on WPAD (can trigger login prompts)
-P, --ProxyAuth         Transparent NTLM auth relay via proxy
--lm                    Force LM hash downgrade
--disable-ess           Disable Extended Session Security for NTLMv1
--externalip=IP         Poison with a spoofed IP
-v                      Verbose mode
-Q, --quiet             Quiet output
-t TTLVAL               Set TTL for poisoned responses
-N ANSWERNAME           Set fake hostname in LLMNR responses
```

---

## 🔎 Hash Logging & Output

- Captured hashes: `logs/` folder
- Log files:
  - `Responder-Session.log`
  - `Analyzer-Session.log`
  - `Poisoners-Session.log`
- Hash format: `MODULE-HASHTYPE-IP.txt`
- SQLite backend enabled via `Responder.conf`

---

## 📌 Usage Example

```bash
python responder.py -I ALL -i 192.168.1.100 -v
```

---

## ✍️ Configuration

Edit `Responder.conf` to:
- Enable/disable modules
- Set WPAD PAC URLs
- Define TTL, server names, exclusions

---

## 🤝 Acknowledgments

Windows version author: **Ryan Soper**

Major sponsors of the original project:
- [Laurent Gaffié](https://g-laurent.blogspot.com)
- [SecureWorks](https://www.secureworks.com/)
- [Synacktiv](https://www.synacktiv.com/)
- [Black Hills Information Security](https://www.blackhillsinfosec.com/)
- [TrustedSec](https://www.trustedsec.com/)
- [Red Siege InfoSec](https://www.redsiege.com/)
- [Open-Sec](http://www.open-sec.com/)
- And all the individual pentesters who donated


---

## 📜 License

**Responder** is licensed under the GNU General Public License v3.0.  
You may redistribute or modify under the same terms.

Original project: https://github.com/lgandx/Responder  
This fork: https://github.com/SwampSec/Responder4Windows
