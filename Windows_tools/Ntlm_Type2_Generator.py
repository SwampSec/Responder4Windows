import base64
import os
import random
import struct


def generate_ntlm_type2(target_name="Responder", save_as="fake_ntlm_type2.b64"):
    signature = b"NTLMSSP\x00"
    message_type = struct.pack("<I", 2)

    target_name_bytes = target_name.encode("utf-16le")
    target_name_len = struct.pack("<H", len(target_name_bytes))
    target_name_maxlen = struct.pack("<H", len(target_name_bytes))
    target_name_offset = struct.pack("<I", 64)

    negotiate_flags = struct.pack("<I", 0xE20882B7)

    # Generate a random 8-byte challenge
    server_challenge = os.urandom(8)

    reserved = b"\x00" * 8

    av_pairs = (
        b"\x02\x00" + struct.pack("<H", len(target_name_bytes)) + target_name_bytes +
        b"\x01\x00\x00\x00" +
        b"\x00\x00\x00\x00"
    )
    av_len = struct.pack("<H", len(av_pairs))
    av_maxlen = struct.pack("<H", len(av_pairs))
    av_offset = struct.pack("<I", 64 + len(target_name_bytes))

    version = b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"

    type2_message = (
        signature +
        message_type +
        target_name_len +
        target_name_maxlen +
        target_name_offset +
        negotiate_flags +
        server_challenge +
        reserved +
        av_len +
        av_maxlen +
        av_offset +
        version +
        target_name_bytes +
        av_pairs
    )

    b64_encoded = base64.b64encode(type2_message)

    with open(save_as, "wb") as f:
        f.write(b64_encoded)

    print(f"✅ Fake NTLM Type 2 challenge generated and saved as {save_as}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate Fake NTLM Type 2 Challenge")
    parser.add_argument("--target", default="Responder", help="Target hostname for AV_PAIR (default: Responder)")
    parser.add_argument("--outfile", default="fake_ntlm_type2.b64", help="Filename to save base64 blob")
    args = parser.parse_args()

    generate_ntlm_type2(target_name=args.target, save_as=args.outfile)
