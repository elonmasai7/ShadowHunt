#!/usr/bin/env python3
import argparse
import select
import socket
import threading


def pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client: socket.socket, target_host: str, target_port: int) -> None:
    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.settimeout(15)
    upstream.connect((target_host, target_port))
    upstream.settimeout(None)

    t1 = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
    t2 = threading.Thread(target=pipe, args=(upstream, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    upstream.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple TCP forwarder")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", type=int, required=True)
    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.listen_host, args.listen_port))
    server.listen(200)
    print(
        f"Proxy listening on {args.listen_host}:{args.listen_port} -> "
        f"{args.target_host}:{args.target_port}",
        flush=True,
    )

    try:
        while True:
            client, _ = server.accept()
            threading.Thread(
                target=handle,
                args=(client, args.target_host, args.target_port),
                daemon=True,
            ).start()
    finally:
        server.close()


if __name__ == "__main__":
    main()
