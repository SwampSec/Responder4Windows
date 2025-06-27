# 🧰 Windows-Compatible Tools

This folder contains patched and rewritten versions of auxiliary Responder/Impacket scripts designed to work natively on Windows 10/11 without WSL or Linux dependencies.

All tools are suffixed with `_Windows.py` and updated for:
- Modern `argparse` CLI usage
- Windows-safe socket handling (no raw sockets)
- Optional CSV output
- Cleaner formatting and error handling

---

## 📊 Tool Summary

| Script Name | Description | Status   |
|-------------|------------------------------------------|----------|
| [`RunFinger_Windows.py`](#runfinger_windowspy)  | Enumerates MSRPC UUIDs on port 135          | ✅ Complete |
| [`FindSQLSrv_Windows.py`](#findsqlsrv_windowspy) | Discovers SQL Server instances via UDP      | ✅ Complete |
| `DNSUpdate_Windows.py`   | Sends forged DNS updates (Windows-safe)  | ✅ Complete |
| `MultiRelay_Windows.py`  | NTLM relay engine adapted for Windows    | ✅ Complete |
| `Ntlm_B64_to_Pcap.py` | NTLM Base64 hash converter to pcap | ✅ Complete |
| `Ntlm_Type2_Generator.py` |NTLMSSP_CHALLENGE (Type 2) generator for testing/debugging PCAPs. | ✅ Complete | 
| `SMBFinger_Windows.py`   | SMB enumeration using Impacket           | 🚧 Planned |
| `Netview_Windows.py`     | NetBIOS/DNS discovery without `nmblookup`| 🚧 Planned |

---

## 📜 Tools

### ✅ RunFinger_Windows.py
Enumerates MSRPC endpoints (UUIDs) over port 135 using Impacket.

```powershell
python RunFinger_Windows.py -i 192.168.1.0/24 --csv rpc_results.csv
```

* Accepts single IP, CIDR, or IP list file
* Checks if port 135 is open before attempting enumeration
* Outputs discovered UUIDs in summary table or CSV

---

### 🔍 FindSQLSrv_Windows.py
Scans local network for SQL Server instances via UDP broadcast (port 1434).

```powershell
python FindSQLSrv_Windows.py --broadcast 192.168.1.255 --timeout 5
```

* Sends MSSQL discovery byte (`\x02`) to broadcast address
* Parses response for:
  - Server name
  - Instance name
  - SQL version
  - TCP port

> ⚠️ Broadcast may be blocked on public Wi-Fi or VPNs. Best used on LAN or lab setups.

---

### 📡 DNSUpdate_Windows.py
Manage DNS A records via LDAP queries to a Domain Controller.

```powershell
python DNSUpdate_Windows.py -DNS 192.168.1.10 -u DOMAIN\user -a ad -r roguehost -d 10.10.10.123
```

* Supports three actions:
  - `ad` — Add A records
  - `rm` — Remove existing records
  - `an` — Analyze Responder logs for record targeting
* Authentication: NTLM with domain credentials
* Queries or modifies DNS data under DC=DomainDnsZones,DC=domain,DC=com

> ⚠️ Requires valid credentials and appropriate LDAP permissions.

---

### 🔥 MultiRelay_Windows_Lite.py
Lightweight NTLM HTTP capture server with optional LDAP relay capability.

```powershell
python MultiRelay_Windows_Lite.py --relay ldap --debug
```

* Listens for incoming HTTP NTLM authentication
* Captures and parses NTLM negotiation and authentication messages
* Optionally attempts LDAP bind relays
* `--debug` flag enables full packet capture for Wireshark analysis

> ⚠️ Port 8080 is used by default; ensure firewall or other services are not blocking.

---

### 🧪 Ntlm_Type2_Generator.py
Generate NTLM Type 2 challenges (NTLMSSP_CHALLENGE) for lab testing or PCAP crafting.

```powershell
python Ntlm_Type2_Generator.py --target LABHOST --outfile labhost_ntlmchallenge.b64
```

* Creates a standalone NTLMSSP Type 2 blob
* Useful for simulating responses in controlled environments
* Base64 encoded output

> 💡 Combine this with Ntlm_B64_to_Pcap.py to create realistic network captures.

---

### 🧩 Ntlm_B64_to_Pcap.py
Convert a Base64 NTLM blob into a PCAP file compatible with Wireshark or other packet analyzers.

```powershell
python Ntlm_B64_to_Pcap.py --infile labhost_ntlmchallenge.b64 --src-ip 192.168.1.10 --dst-ip 192.168.1.20
```

* Decodes a Base64 NTLMSSP blob
* Wraps it inside a minimal HTTP packet structure
* Saves it as a valid .pcap file
* Great for training, detection engineering, or signature development

> ⚠️ Ensure you match your source/destination IPs logically for analysis clarity.

---

More converted tools coming soon:
- `SMBFinger_Windows.py`
- `Netview_Windows.py`

Original Linux-compatible scripts remain untouched in the parent directory.

> Maintained by [SwampSec](https://github.com/SwampSec) / Ryan Soper — Fork of Laurent Gaffié's [Responder](https://github.com/lgandx/Responder)