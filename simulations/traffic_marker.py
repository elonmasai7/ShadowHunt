import argparse
import base64
import time
from scapy.all import IP, Raw, UDP, send


def xor_hex(value: bytes) -> bytes:
    return bytes([b ^ 0x23 for b in value]).hex().encode("utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["plain", "base64", "xor"], default="plain")
    args = parser.parse_args()

    base_tags = [b"SHADOWHUNT_T1078_SIM", b"SHADOWHUNT_T1003_SIM", b"SHADOWHUNT_T1021_SIM"]

    for tag in base_tags:
        payload = tag
        if args.mode == "base64":
            payload = base64.b64encode(tag)
        elif args.mode == "xor":
            payload = xor_hex(tag)

        pkt = IP(dst="10.10.0.99") / UDP(dport=9999) / Raw(load=payload)
        send(pkt, verbose=False)
        time.sleep(1)
