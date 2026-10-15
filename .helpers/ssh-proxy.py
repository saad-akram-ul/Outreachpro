#!/usr/bin/env python3
"""ProxyCommand helper: HTTP CONNECT tunnel through the authenticated
hatch-egress-proxy, then relay between the socket and stdio.
Usage: ssh-proxy.py <host> <port>"""
import os, sys, socket, base64, select

def main():
    host, port = sys.argv[1], int(sys.argv[2])
    proxy = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or ""
    rest = proxy[len("http://"):]
    auth, _, proxhost = rest.partition("@")
    phost, _, pport = proxhost.partition(":")
    s = socket.create_connection((phost, int(pport or 3128)), timeout=30)
    creds = base64.b64encode(auth.encode()).decode()
    s.sendall((f"CONNECT {host}:{port} HTTP/1.1\r\n"
               f"Host: {host}:{port}\r\n"
               f"Proxy-Authorization: Basic {creds}\r\n\r\n").encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(4096)
        if not chunk:
            sys.exit(f"proxy closed connection: {resp[:200]!r}")
        resp += chunk
    if b" 200 " not in resp.split(b"\r\n", 1)[0]:
        sys.exit(f"proxy CONNECT failed: {resp[:200]!r}")
    s.setblocking(False)
    stdin_fd, stdout_fd = sys.stdin.fileno(), sys.stdout.fileno()
    import fcntl
    for fd in (stdin_fd,):
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
    ss = s.fileno()
    while True:
        r, _, _ = select.select([ss, stdin_fd], [], [], 300)
        if not r:
            break
        if ss in r:
            try:
                data = s.recv(65536)
            except BlockingIOError:
                data = None
            if not data:
                break
            os.write(stdout_fd, data)
        if stdin_fd in r:
            try:
                data = os.read(stdin_fd, 65536)
            except BlockingIOError:
                data = None
            if not data:
                try:
                    s.shutdown(socket.SHUT_WR)
                except Exception:
                    pass
                # keep reading remaining server data briefly
                stdin_fd = -1
                continue
            s.sendall(data)

if __name__ == "__main__":
    main()
