#!/usr/bin/env python3
"""Small authenticated SOCKS5 CONNECT forwarder for SmolVM acceptance tests."""

import argparse
import ipaddress
import os
import socket
import struct
import threading


def read_exact(stream: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise EOFError("peer closed")
        data.extend(chunk)
    return bytes(data)


def relay(source: socket.socket, destination: socket.socket) -> None:
    try:
        while chunk := source.recv(64 * 1024):
            destination.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client: socket.socket, username: str | None, password: str) -> None:
    upstream = None
    try:
        version, method_count = read_exact(client, 2)
        if version != 5:
            return
        methods = read_exact(client, method_count)
        selected = 2 if username is not None else 0
        if selected not in methods:
            client.sendall(b"\x05\xff")
            return
        client.sendall(bytes([5, selected]))

        if selected == 2:
            auth_version, user_len = read_exact(client, 2)
            user = read_exact(client, user_len).decode("utf-8")
            pass_len = read_exact(client, 1)[0]
            supplied_password = read_exact(client, pass_len).decode("utf-8")
            allowed = (
                auth_version == 1
                and user == username
                and supplied_password == password
            )
            client.sendall(bytes([1, 0 if allowed else 1]))
            if not allowed:
                return

        version, command, reserved, address_type = read_exact(client, 4)
        if version != 5 or command != 1 or reserved != 0:
            return
        if address_type == 1:
            host = str(ipaddress.ip_address(read_exact(client, 4)))
        elif address_type == 3:
            host = read_exact(client, read_exact(client, 1)[0]).decode("idna")
        elif address_type == 4:
            host = str(ipaddress.ip_address(read_exact(client, 16)))
        else:
            client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        port = struct.unpack("!H", read_exact(client, 2))[0]
        print(f"CONNECT {host}:{port}", flush=True)

        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            client.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        upstream.settimeout(None)
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        outgoing = threading.Thread(target=relay, args=(client, upstream), daemon=True)
        incoming = threading.Thread(target=relay, args=(upstream, client), daemon=True)
        outgoing.start()
        incoming.start()
        outgoing.join()
        incoming.join()
    except (EOFError, OSError, UnicodeError):
        pass
    finally:
        client.close()
        if upstream is not None:
            upstream.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    username = os.environ.get("SOCKS5_USERNAME")
    password = os.environ.get("SOCKS5_PASSWORD", "")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.port))
    listener.listen(128)
    print(f"READY 127.0.0.1:{args.port}", flush=True)
    while True:
        client, _ = listener.accept()
        threading.Thread(
            target=handle,
            args=(client, username, password),
            daemon=True,
        ).start()


if __name__ == "__main__":
    main()
