#!/usr/bin/env python3
"""Отправить один TCP-фрейм (uint64_be длина + тело) и прочитать ACK (8 байт VACK+code)."""
import socket
import struct
import sys


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: resend_framed.py PACKET.bin HOST PORT", file=sys.stderr)
        return 2
    path, host, port_s = sys.argv[1], sys.argv[2], sys.argv[3]
    port = int(port_s)
    with open(path, "rb") as f:
        body = f.read()
    with socket.create_connection((host, port), timeout=30.0) as s:
        s.sendall(struct.pack(">Q", len(body)) + body)
        ack = b""
        while len(ack) < 8:
            chunk = s.recv(8 - len(ack))
            if not chunk:
                print("no_ack", file=sys.stderr)
                return 3
            ack += chunk
    if ack[:4] != b"VACK":
        print("bad_magic", ack[:4], file=sys.stderr)
        return 4
    code = int.from_bytes(ack[4:8], "big")
    print(code)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
