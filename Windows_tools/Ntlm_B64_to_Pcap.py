import base64
import argparse
from scapy.all import Ether, IP, TCP, Raw, wrpcap


def build_ntlm_pcap(b64_file, out_file, src_ip, dst_ip):
    with open(b64_file, "r") as f:
        ntlm_challenge_b64 = f.read().strip()

    http_response = (
        "HTTP/1.1 401 Unauthorized\r\n"
        f"WWW-Authenticate: NTLM {ntlm_challenge_b64}\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    ).encode()

    pkt = (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ee:dd:cc:bb:aa") /
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=80, dport=12345, seq=1000, ack=1, flags="PA") /
        Raw(load=http_response)
    )

    wrpcap(out_file, [pkt])
    print(f"✅ PCAP saved as: {out_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert base64 NTLM challenge to PCAP")
    parser.add_argument("--b64file", required=True, help="Path to .b64 file (NTLM Type 2 base64)")
    parser.add_argument("--outfile", default="ntlm_challenge_debug.pcap", help="Output PCAP filename")
    parser.add_argument("--src", default="192.168.1.10", help="Source IP (Responder)")
    parser.add_argument("--dst", default="192.168.1.20", help="Destination IP (Victim)")
    args = parser.parse_args()

    build_ntlm_pcap(args.b64file, args.outfile, args.src, args.dst)
