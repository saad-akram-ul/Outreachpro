#!/usr/bin/env python3
"""SMTP relay for OutreachPro: Render blocks outbound SMTP, so the Render app
sends HTTP requests here, and this VM (which CAN reach Hostinger) does SMTP.

Run: python3 smtp-relay.py (listens on 127.0.0.1:8899, use via SSH tunnel or local)
For production: run behind a reverse proxy with the RELAY_SECRET.

Endpoints:
  POST /relay/test   {secret, host, port, email, password, secure} -> {ok, msg}
  POST /relay/send   {secret, host, port, email, password, secure, to, subject, html} -> {ok, msg}
"""
import json, smtplib, ssl, socket, os
from http.server import BaseHTTPRequestHandler, HTTPServer

RELAY_SECRET_FILE = os.path.expanduser("~/workspace/outreach/.relay_secret")
PORT = 8899

def get_secret():
    if not os.path.exists(RELAY_SECRET_FILE):
        import secrets
        s = secrets.token_urlsafe(32)
        with open(RELAY_SECRET_FILE, "w") as f:
            f.write(s)
        os.chmod(RELAY_SECRET_FILE, 0o600)
    return open(RELAY_SECRET_FILE).read().strip()

def smtp_send(host, port, email, password, secure, to_addr, subject, html_body):
    import email.mime.text, email.mime.multipart
    ctx = ssl.create_default_context()
    port = int(port)
    # Force IPv4
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        host_ip = infos[0][4][0] if infos else host
    except socket.gaierror:
        host_ip = host
    use_ssl = (secure or "").lower() == "ssl" or port == 465
    if use_ssl:
        s = smtplib.SMTP_SSL(host_ip, port, context=ctx, timeout=25)
    else:
        s = smtplib.SMTP(host_ip, port, timeout=25)
        s.starttls(context=ctx)
    s.login(email, password)
    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["From"] = email
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.attach(email.mime.text.MIMEText(html_body, "html", "utf-8"))
    s.sendmail(email, [to_addr], msg.as_string())
    s.quit()
    return True

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def _json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            return self._json({"ok": False, "msg": "bad json"}, 400)
        if data.get("secret") != get_secret():
            return self._json({"ok": False, "msg": "unauthorized"}, 403)
        try:
            if self.path == "/relay/test":
                import smtplib as _s
                smtp_send(data["host"], data["port"], data["email"],
                          data["password"], data.get("secure", "ssl"),
                          data["email"], "Relay Test", "<p>ok</p>")
                return self._json({"ok": True, "msg": "Connected! Login kamyab raha."})
            elif self.path == "/relay/send":
                smtp_send(data["host"], data["port"], data["email"],
                          data["password"], data.get("secure", "ssl"),
                          data["to"], data["subject"], data["html"])
                return self._json({"ok": True, "msg": "sent"})
            else:
                return self._json({"ok": False, "msg": "unknown path"}, 404)
        except smtplib.SMTPAuthenticationError:
            return self._json({"ok": False, "msg": "Auth failed: password ghalat hai"})
        except (socket.error, OSError) as e:
            return self._json({"ok": False, "msg": f"Network: {e}"})
        except Exception as e:
            return self._json({"ok": False, "msg": f"Error: {str(e)[:120]}"})

if __name__ == "__main__":
    get_secret()  # ensure exists
    print(f"SMTP relay on 0.0.0.0:{PORT}", flush=True)
    HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
