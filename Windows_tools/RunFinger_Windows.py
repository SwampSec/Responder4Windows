import argparse
import socket
import ipaddress
import csv
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import epm
from tabulate import tabulate

def is_port_open(ip, port=135, timeout=2):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False
    

def check_rpc(ip):
    try:
        stringbinding = f'ncacn_ip_tcp:{ip}'
        trans = transport.DCERPCTransportFactory(stringbinding)
        trans.set_connect_timeout(3)
        dce = trans.get_dce_rpc()
        dce.connect()
        dce.bind(epm.MSRPC_UUID_PORTMAP)

        entries = epm.hept_lookup(None, dce)

        uuids = set()
        for entry in entries:
            uuids.add(str(entry['Tower']['Floors'][0]['Data']))

        return list(uuids)
    except Exception as e:
        return []


def scan_single_host(ip):
    if not is_port_open(ip, 135):
        print(f"[-] {ip} - Port 135 is closed or filtered")
        return {"ip": ip, "status": "offline", "uuids": []}
    
    uuids = check_rpc(ip)
    if uuids:
        print(f"[+] {ip} is ONLINE - Found {len(uuids)} endpoint(s)")
        return {"ip": ip, "status": "online", "uuids": uuids}
    else:
        print(f"[-] {ip} is ONLINE but no UUIDs found or RPC binding failed")
        return {"ip": ip, "status": "online", "uuids": []}


def parse_ip_input(ip_input):
    hosts = []
    try:
        if "/" in ip_input:
            net = ipaddress.ip_network(ip_input, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
        else:
            with open(ip_input, 'r') as f:
                hosts = [line.strip() for line in f if line.strip()]
    except Exception:
        hosts = [ip_input]
    return hosts


def write_csv(results, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP Address", "Status", "UUIDs"])
        for entry in results:
            writer.writerow([entry["ip"], entry["status"], "; ".join(entry["uuids"])])


def main():
    parser = argparse.ArgumentParser(description="RunFinger_Windows - MSRPC endpoint mapper for Windows")
    parser.add_argument("-i", "--input", required=True, help="IP address, CIDR, or path to IP list file")
    parser.add_argument("--csv", help="Output results to CSV file")

    args = parser.parse_args()
    targets = parse_ip_input(args.input)

    results = []
    print("[*] Starting scan of targets...")
    for ip in targets:
        result = scan_single_host(ip)
        results.append(result)

    print("\n[*] Scan Summary")
    print(tabulate(
        [(r['ip'], r['status'], len(r['uuids'])) for r in results],
        headers=["IP Address", "Status", "# of UUIDs"]
    ))

    if args.csv:
        write_csv(results, args.csv)
        print(f"\n[+] Results saved to: {args.csv}")


if __name__ == "__main__":
    main()
