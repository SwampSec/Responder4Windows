import socket
import argparse
import time
from tabulate import tabulate

def discover_sql_servers(broadcast_ip, timeout=5):
    discovered = []
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)

        print(f"[*] Sending MSSQL discovery to {broadcast_ip}:1434")
        sock.sendto(b'\x02', (broadcast_ip, 1434))

        start_time = time.time()
        while True:
            try:
                data, addr = sock.recvfrom(8092)
                response = data[3:].decode('latin-1', errors='ignore')
                discovered.append((addr[0], response))
            except socket.timeout:
                break
            if time.time() - start_time > timeout:
                break

    except Exception as e:
        print(f"[!] Socket error: {e}")
    finally:
        sock.close()

    return discovered


def parse_response(response):
    fields = response.split(';')
    result = {}
    for i in range(0, len(fields)-1, 2):
        key = fields[i].strip()
        val = fields[i+1].strip()
        result[key] = val
    return result


def main():
    parser = argparse.ArgumentParser(description="FindSQLSrv_Windows - SQL Server Browser scanner for Windows")
    parser.add_argument("--broadcast", required=True, help="Broadcast IP address to scan (e.g., 192.168.1.255)")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout in seconds (default: 5)")
    args = parser.parse_args()

    results = discover_sql_servers(args.broadcast, args.timeout)

    if not results:
        print("[!] No SQL Servers found.")
        return

    print("\n[+] SQL Servers discovered:")
    table = []
    for ip, raw in results:
        info = parse_response(raw)
        table.append([
            ip,
            info.get('ServerName', 'N/A'),
            info.get('InstanceName', 'N/A'),
            info.get('Version', 'N/A'),
            info.get('tcp', 'N/A')
        ])

    print(tabulate(table, headers=["IP", "Server", "Instance", "Version", "TCP Port"]))


if __name__ == '__main__':
    main()
