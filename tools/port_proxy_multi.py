#!/usr/bin/env python3
import argparse
import socket
import threading


def pump(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            buf = src.recv(65536)
            if not buf:
                break
            dst.sendall(buf)
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle_client(client: socket.socket, target_host: str, target_port: int) -> None:
    upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    upstream.connect((target_host, target_port))
    t1 = threading.Thread(target=pump, args=(client, upstream), daemon=True)
    t2 = threading.Thread(target=pump, args=(upstream, client), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    client.close()
    upstream.close()


def serve(listen_port: int, target_host: str, target_port: int) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", listen_port))
    server.listen(200)
    print(f"{listen_port} -> {target_host}:{target_port}", flush=True)
    while True:
        client, _ = server.accept()
        threading.Thread(
            target=handle_client,
            args=(client, target_host, target_port),
            daemon=True,
        ).start()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--map",
        action="append",
        required=True,
        help="Format: listen_port:target_host:target_port",
    )
    args = parser.parse_args()

    threads = []
    for mapping in args.map:
        listen_s, host, target_s = mapping.split(":")
        t = threading.Thread(
            target=serve,
            args=(int(listen_s), host, int(target_s)),
            daemon=True,
        )
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
