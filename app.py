"""OutreachPro by Saad Akram - Automated guest-post outreach software."""
import os, functools
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_db, init_db

ADMIN_NAME = "Saad Akram"
ADMIN_EMAIL = "ranasaadakram.gcuf.cs@gmail.com"

app = Flask(__name__, static_folder="public", static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-in-production")


def get_fernet():
    """Fernet for encrypting stored email passwords. Key comes from env.

    Accepts a real Fernet key; if the env value is any other random string
    (e.g. Render's generateValue), derives a valid Fernet key from it
    deterministically so encryption never crashes in production.
    """
    from cryptography.fernet import Fernet
    import hashlib, base64
    key = os.environ.get("FERNET_KEY")
    if not key:
        # dev fallback (DO NOT rely on in production)
        key = Fernet.generate_key().decode()
    kb = key.encode() if isinstance(key, str) else key
    try:
        return Fernet(kb)
    except Exception:
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(kb).digest()))



def log_activity(db, user_id, action, details=""):
    db.execute("INSERT INTO activity_log (user_id, action, details) VALUES (?,?,?)",
               (user_id, action, details))


def is_paused(db, user_id):
    row = db.execute("SELECT sending_paused FROM settings WHERE user_id=?", (user_id,)).fetchone()
    return bool(row and row["sending_paused"])


def login_required(f):
    @functools.wraps(f)
    def w(*a, **k):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*a, **k)
    return w


@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        u, p = request.form.get("username", "").strip(), request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        db.close()
        if user and check_password_hash(user["password_hash"], p):
            session.update(user_id=user["id"], username=user["username"],
                           name=user["name"], role=user["role"])
            db = get_db()
            log_activity(db, user["id"], "login", "User logged in")
            db.commit(); db.close()
            return redirect(url_for("dashboard"))
        flash("Ghalat username ya password. Dobara koshish karein.", "error")
    return render_template("login.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        if not name or not username or len(password) < 6:
            flash("Naam, username aur kam az kam 6 harf ka password zaroori hai.", "error")
        elif db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            flash("Ye username pehle se hai. Koi aur try karo.", "error")
        else:
            db.execute(
                "INSERT INTO users (username,password_hash,name,role) VALUES (?,?,?,'user')",
                (username, generate_password_hash(password), name))
            db.commit()
            uid = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
            log_activity(db, uid, "signup", f"New user registered: {username}")
            db.commit(); db.close()
            flash("Account ban gaya! Ab login karo. 🎉", "success")
            return redirect(url_for("login"))
        db.close()
    return render_template("signup.html")


def admin_required(f):
    @functools.wraps(f)
    def wrapper(*a, **kw):
        if session.get("role") != "admin":
            flash("Sirf admin ke liye hai.", "error")
            return redirect(url_for("dashboard"))
        return f(*a, **kw)
    return wrapper


@app.route("/admin")
@login_required
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute(
        """SELECT u.id, u.username, u.name, u.role, u.created_at,
           (SELECT COUNT(*) FROM email_accounts e WHERE e.user_id=u.id) AS emails,
           (SELECT COUNT(*) FROM prospects p WHERE p.user_id=u.id) AS prospects,
           (SELECT COUNT(*) FROM outbox o WHERE o.user_id=u.id AND o.status='sent') AS sent
           FROM users u ORDER BY u.id""").fetchall()
    db.close()
    return render_template("admin.html", users=users,
                           admin_name=ADMIN_NAME, admin_email=ADMIN_EMAIL)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", admin_name=ADMIN_NAME, admin_email=ADMIN_EMAIL)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if request.method == "POST":
        cur, new, conf = (request.form.get("current_password", ""),
                          request.form.get("new_password", ""),
                          request.form.get("confirm_password", ""))
        if not check_password_hash(user["password_hash"], cur):
            flash("Maujooda password ghalat hai.", "error")
        elif len(new) < 6:
            flash("Naya password kam az kam 6 characters ka ho.", "error")
        elif new != conf:
            flash("Naya password aur confirm password match nahi kar rahe.", "error")
        else:
            db.execute("UPDATE users SET password_hash=? WHERE id=?",
                       (generate_password_hash(new), user["id"]))
            db.commit()
            flash("Password kamyabi se change ho gaya.", "success")
        db.close()
        return redirect(url_for("profile"))
    db.close()
    return render_template("profile.html", user=user,
                           admin_name=ADMIN_NAME, admin_email=ADMIN_EMAIL)


@app.route("/tasks", methods=["GET", "POST"])
@login_required
def tasks():
    from datetime import date
    today = date.today().isoformat()
    db = get_db()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        if title:
            db.execute("INSERT INTO tasks (user_id,title,task_date) VALUES (?,?,?)",
                       (session["user_id"], title, today))
            db.commit()
            flash("Task add ho gaya.", "success")
        return redirect(url_for("tasks"))
    rows = db.execute(
        "SELECT * FROM tasks WHERE user_id=? AND task_date=? ORDER BY done, id DESC",
        (session["user_id"], today)).fetchall()
    done_n = sum(1 for r in rows if r["done"])
    db.close()
    return render_template("tasks.html", tasks=rows, today=today,
                           done_n=done_n, total=len(rows),
                           admin_name=ADMIN_NAME, admin_email=ADMIN_EMAIL)


@app.route("/tasks/<int:tid>/toggle")
@login_required
def task_toggle(tid):
    db = get_db()
    db.execute("UPDATE tasks SET done = 1 - done WHERE id=? AND user_id=?",
               (tid, session["user_id"]))
    db.commit()
    db.close()
    return redirect(url_for("tasks"))


@app.route("/tasks/<int:tid>/delete")
@login_required
def task_delete(tid):
    db = get_db()
    db.execute("DELETE FROM tasks WHERE id=? AND user_id=?", (tid, session["user_id"]))
    db.commit()
    db.close()
    return redirect(url_for("tasks"))


def test_smtp(host, port, email, password):
    """Try SMTP_SSL login. Returns (ok, message)."""
    import smtplib, ssl
    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, int(port), context=ctx, timeout=12) as s:
            s.login(email, password)
        return True, "Connected! Login kamyab raha."
    except Exception as e:
        return False, "Failed: " + str(e)[:140]


# Country -> IANA timezone (for sending at recipient's local morning)
COUNTRY_TZ = {
    "usa": "America/New_York", "united states": "America/New_York", "us": "America/New_York",
    "uk": "Europe/London", "united kingdom": "Europe/London", "england": "Europe/London",
    "canada": "America/Toronto", "australia": "Australia/Sydney",
    "germany": "Europe/Berlin", "france": "Europe/Paris", "netherlands": "Europe/Amsterdam",
    "ireland": "Europe/Dublin", "spain": "Europe/Madrid", "italy": "Europe/Rome",
    "uae": "Asia/Dubai", "united arab emirates": "Asia/Dubai",
    "saudi arabia": "Asia/Riyadh", "india": "Asia/Kolkata", "pakistan": "Asia/Karachi",
    "singapore": "Asia/Singapore", "malaysia": "Asia/Kuala_Lumpur",
    "new zealand": "Pacific/Auckland", "south africa": "Africa/Johannesburg",
    "brazil": "America/Sao_Paulo", "mexico": "America/Mexico_City",
    "japan": "Asia/Tokyo", "china": "Asia/Shanghai", "south korea": "Asia/Seoul",
    "sweden": "Europe/Stockholm", "norway": "Europe/Oslo", "denmark": "Europe/Copenhagen",
    "belgium": "Europe/Brussels", "switzerland": "Europe/Zurich", "austria": "Europe/Vienna",
    "portugal": "Europe/Lisbon", "poland": "Europe/Warsaw", "turkey": "Europe/Istanbul",
    "egypt": "Africa/Cairo", "nigeria": "Africa/Lagos", "kenya": "Africa/Nairobi",
    "philippines": "Asia/Manila", "indonesia": "Asia/Jakarta", "thailand": "Asia/Bangkok",
    "vietnam": "Asia/Ho_Chi_Minh", "bangladesh": "Asia/Dhaka",
}


def prospect_local_hour(prospect):
    """Current hour (0-23) in the prospect's country timezone."""
    from zoneinfo import ZoneInfo
    from datetime import datetime
    tzname = COUNTRY_TZ.get((prospect["country"] or "").strip().lower(), "UTC")
    try:
        return datetime.now(ZoneInfo(tzname)).hour
    except Exception:
        return datetime.utcnow().hour


def render_text(text, prospect):
    return (text.replace("{name}", prospect["name"] or "there")
                .replace("{company}", prospect["company"] or "your company")
                .replace("{email}", prospect["email"]))


def spintax(text):
    """Resolve {option1|option2|option3} variations randomly (innermost first)."""
    import random, re
    text = text or ""
    pat = re.compile(r"\{([^{}]*)\}")
    for _ in range(20):
        m = pat.search(text)
        if not m:
            break
        text = text[:m.start()] + random.choice(m.group(1).split("|")) + text[m.end():]
    return text


def app_base_url():
    """Public base URL for tracking/unsubscribe links (Render provides RENDER_EXTERNAL_URL)."""
    return (os.environ.get("APP_URL") or os.environ.get("RENDER_EXTERNAL_URL") or "").rstrip("/")


def record_event(db, user_id, outbox_id, prospect_id, campaign_id, event_type, detail=""):
    db.execute(
        """INSERT INTO email_events (user_id,outbox_id,prospect_id,campaign_id,event_type,detail)
           VALUES (?,?,?,?,?,?)""",
        (user_id, outbox_id, prospect_id, campaign_id, event_type, detail or None))


def build_tracked_html(plain_body, outbox_id, unsub_url):
    """HTML version of the email: linkified URLs routed via click tracker + open pixel."""
    import re, html as htmllib, urllib.parse
    base = app_base_url()
    esc = htmllib.escape(plain_body or "")

    def _link(m):
        url = m.group(0)
        if base:
            q = urllib.parse.quote(url, safe="")
            return f'<a href="{base}/t/c/{outbox_id}?u={q}">{htmllib.escape(url)}</a>'
        return f'<a href="{htmllib.escape(url)}">{htmllib.escape(url)}</a>'

    html_body = re.sub(r"https?://[^\s<>\"]+", _link, esc).replace("\n", "<br>")
    if base:
        html_body += (f'<br><img src="{base}/t/o/{outbox_id}" width="1" height="1" '
                      f'style="display:none" alt="">')
    if unsub_url:
        html_body += (f'<br><br><span style="font-size:11px;color:#888">'
                      f'Don\'t want these emails? <a href="{htmllib.escape(unsub_url)}">'
                      f'Unsubscribe</a></span>')
    return f"<html><body>{html_body}</body></html>"


def unsub_token(prospect_id, user_id):
    from itsdangerous import URLSafeSerializer
    s = URLSafeSerializer(app.secret_key, salt="unsub-v1")
    return s.dumps({"p": prospect_id, "u": user_id})


def unsub_data(token):
    from itsdangerous import URLSafeSerializer, BadSignature
    s = URLSafeSerializer(app.secret_key, salt="unsub-v1")
    try:
        d = s.loads(token)
        return d if isinstance(d, dict) and "p" in d and "u" in d else None
    except BadSignature:
        return None


def pick_sender(db, user_id):
    """Round-robin: active account with fewest sends today."""
    from datetime import date
    today = date.today().isoformat()
    rows = db.execute(
        """SELECT a.id, COUNT(o.id) AS sent
           FROM email_accounts a
           LEFT JOIN outbox o ON o.account_id=a.id AND o.status='sent' AND date(o.sent_at)=?
           WHERE a.user_id=? AND a.active=1
           GROUP BY a.id ORDER BY sent, a.id""",
        (today, user_id)).fetchall()
    return rows[0]["id"] if rows else None


def send_one_email(db, user_id, account_id, to_email, subject, body, html_body=None, unsub_url=None):
    """Send via stored SMTP account. Returns (ok, error)."""
    import smtplib, ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    acc = db.execute("SELECT * FROM email_accounts WHERE id=? AND user_id=?",
                     (account_id, user_id)).fetchone()
    if not acc:
        return False, "account not found"
    pw = get_fernet().decrypt(acc["password_enc"].encode()).decode()
    try:
        if html_body:
            msg = MIMEMultipart("alternative")
            msg.attach(MIMEText(body, "plain", "utf-8"))
            msg.attach(MIMEText(html_body, "html", "utf-8"))
        else:
            msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = acc["email"]
        msg["To"] = to_email
        if unsub_url:
            msg["List-Unsubscribe"] = f"<{unsub_url}>"
            msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(acc["smtp_host"], int(acc["smtp_port"]), context=ctx, timeout=25) as s:
            s.login(acc["email"], pw)
            s.send_message(msg)
        return True, ""
    except Exception as e:
        return False, str(e)[:200]


REPLY_INTENTS = [
    ("not_interested", ["not interested", "no thanks", "no thank you", "unsubscribe",
                        "stop emailing", "remove me", "don't contact", "do not contact"]),
    ("pricing", ["price", "pricing", "cost", "how much", "rate", "rates", "charge", "fee", "budget"]),
    ("traffic", ["traffic", "visitors", "stats", "statistics", "analytics", "proof",
                 "screenshot", "ahrefs", "semrush", "metrics"]),
    ("timeline", ["how long", "timeline", "duration", "when will", "turnaround", "delivery time"]),
    ("positive", ["interested", "sounds good", "let's do", "let us do", "yes please", "sure",
                  "go ahead", "i'm in", "count me"]),
]


def detect_intent(text):
    t = (text or "").lower()
    for intent, keywords in REPLY_INTENTS:
        if any(k in t for k in keywords):
            return intent
    return "general"


def generate_reply_draft(prospect, inbox_msg, intent):
    """Rule-based professional reply draft (approval mode: never auto-sent)."""
    name = prospect["name"] or "there"
    company = prospect["company"] or "your company"
    if intent == "pricing":
        body = (f"Hi {name},\n\nThank you for asking. Our guest post pricing depends on "
                f"the site's authority and traffic tier — most placements for sites like "
                f"{company}'s niche range between $50 and $150 per post.\n\n"
                f"If you share which site(s) you're considering, I'll send you the exact "
                f"rate card right away.\n\nBest regards,\nSaad Akram")
    elif intent == "traffic":
        body = (f"Hi {name},\n\nGreat question. I can share verified traffic screenshots "
                f"(Google Analytics / Search Console) for any site you're interested in, "
                f"along with its Domain Rating and organic keyword count.\n\n"
                f"Just let me know which site(s) you'd like the data for.\n\nBest regards,\nSaad Akram")
    elif intent == "timeline":
        body = (f"Hi {name},\n\nOur standard turnaround is 3-5 business days from payment "
                f"confirmation — that includes content writing, editorial review, and "
                f"the live link report.\n\nIf you have a tighter deadline, let me know "
                f"and I'll do my best to prioritize it.\n\nBest regards,\nSaad Akram")
    elif intent == "positive":
        body = (f"Hi {name},\n\nWonderful — I'm glad you're interested!\n\n"
                f"Here are the next steps:\n"
                f"1. Confirm the target URL and anchor text you'd like.\n"
                f"2. I'll share the payment details and get the article into production.\n\n"
                f"Looking forward to working with you.\n\nBest regards,\nSaad Akram")
    else:
        body = (f"Hi {name},\n\nThank you for getting back to me — I appreciate it.\n\n"
                f"I'd be happy to discuss how a guest post could work for {company}. "
                f"Let me know if you'd like to see our site list with traffic stats and pricing.\n\n"
                f"Best regards,\nSaad Akram")
    return f"Re: {inbox_msg['subject'] or 'your email'}", body


def is_bounce_message(from_email, subject):
    """Heuristic: is this a delivery-failure notification?"""
    f = (from_email or "").lower()
    if "mailer-daemon" in f or "mail delivery" in f or "postmaster" in f or "maildaemon" in f:
        return True
    s = (subject or "").lower()
    return (s.startswith("undelivered") or "undeliverable" in s
            or "delivery status notification" in s or "delivery failure" in s)


def extract_bounced_email(msg, body):
    """Find the original recipient address from a bounce notification."""
    import re
    pat = r"[\w.+-]+@[\w-]+\.[\w.]+"
    for h in ("X-Failed-Recipients", "X-Actual-Recipient", "Original-Recipient",
              "Final-Recipient"):
        v = msg.get(h, "")
        m = re.search(pat, v)
        if m:
            return m.group(0).lower()
    # common body phrasing: "Delivery to the following recipient failed: <addr>"
    for line in (body or "").splitlines()[:40]:
        if any(k in line.lower() for k in ("recipient", "failed", "undelivered", "original message")):
            m = re.search(pat, line)
            if m:
                return m.group(0).lower()
    return None


def check_inbox_for_user(db, user_id):
    """IMAP unread check for each active account. Returns (new_messages, new_drafts)."""
    import imaplib, email as emaillib
    from email.header import decode_header
    from datetime import datetime
    new_msgs, new_drafts = 0, 0
    accounts = db.execute("SELECT * FROM email_accounts WHERE user_id=? AND active=1",
                          (user_id,)).fetchall()
    for acc in accounts:
        pw = get_fernet().decrypt(acc["password_enc"].encode()).decode()
        imap_host = (acc["imap_host"] or "imap.hostinger.com").strip()
        try:
            m = imaplib.IMAP4_SSL(imap_host, int(acc["imap_port"] or 993))
            m.login(acc["email"], pw)
            m.select("INBOX")
            _, data = m.search(None, "UNSEEN")
        except Exception:
            continue
        for num in data[0].split():
            try:
                _, fdata = m.fetch(num, "(RFC822)")
                msg = emaillib.message_from_bytes(fdata[0][1])
                from_email = emaillib.utils.parseaddr(msg.get("From", ""))[1].lower()
                subj_raw, enc = decode_header(msg.get("Subject", ""))[0]
                subject = subj_raw.decode(enc or "utf-8", "ignore") if isinstance(subj_raw, bytes) else subj_raw
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain" and not part.get("Content-Disposition"):
                            body = part.get_payload(decode=True).decode("utf-8", "ignore")
                            break
                else:
                    body = msg.get_payload(decode=True).decode("utf-8", "ignore") if msg.get_payload(decode=True) else ""
                body = body[:3000]
                uid = f"{num.decode()}-{hash(from_email + subject)}"
                # bounce handling: mark prospect bounced, never email again
                if is_bounce_message(from_email, subject):
                    bounced_email = extract_bounced_email(msg, body)
                    bprosp = None
                    if bounced_email:
                        bprosp = db.execute(
                            "SELECT * FROM prospects WHERE user_id=? AND LOWER(email)=?",
                            (user_id, bounced_email)).fetchone()
                    if bprosp:
                        db.execute("UPDATE prospects SET status='bounced' WHERE id=?",
                                   (bprosp["id"],))
                        # link to the most recent outbox entry for context
                        ob = db.execute(
                            "SELECT id, campaign_id FROM outbox WHERE prospect_id=? ORDER BY id DESC",
                            (bprosp["id"],)).fetchone()
                        record_event(db, user_id, ob["id"] if ob else None, bprosp["id"],
                                     ob["campaign_id"] if ob else None, "bounce", bounced_email)
                        log_activity(db, user_id, "bounce",
                                     f"Bounced email marked: {bounced_email}")
                    try:
                        m.store(num, "+FLAGS", "\\Seen")
                    except Exception:
                        pass
                    db.commit()
                    continue
                # match to a prospect
                prosp = db.execute(
                    "SELECT * FROM prospects WHERE user_id=? AND LOWER(email)=?",
                    (user_id, from_email)).fetchone()
                cur = db.execute(
                    "INSERT OR IGNORE INTO inbox_messages "
                    "(user_id,account_id,prospect_id,from_email,subject,body,received_at,msg_uid) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (user_id, acc["id"], prosp["id"] if prosp else None, from_email,
                     subject, body, datetime.now().isoformat(timespec="seconds"), uid))
                if cur.rowcount:
                    new_msgs += 1
                    inbox_id = cur.lastrowid
                    intent = detect_intent(subject + " " + body)
                    if intent == "not_interested" and prosp:
                        db.execute("UPDATE prospects SET status='not_interested' WHERE id=?",
                                   (prosp["id"],))
                    elif prosp:
                        dsubj, dbody = generate_reply_draft(prosp,
                            {"subject": subject}, intent)
                        db.execute(
                            "INSERT INTO reply_drafts "
                            "(user_id,inbox_id,prospect_id,account_id,subject,body,intent) "
                            "VALUES (?,?,?,?,?,?,?)",
                            (user_id, inbox_id, prosp["id"], acc["id"], dsubj, dbody, intent))
                        new_drafts += 1
                    db.execute("UPDATE inbox_messages SET status='processed' WHERE id=?", (inbox_id,))
                m.store(num, "+FLAGS", "\\Seen")
            except Exception:
                continue
        try:
            m.close(); m.logout()
        except Exception:
            pass
    db.commit()
    return new_msgs, new_drafts


@app.route("/emails", methods=["GET", "POST"])
@login_required
def emails():
    db = get_db()
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        smtp_host = request.form.get("smtp_host", "").strip() or "smtp.hostinger.com"
        smtp_port = request.form.get("smtp_port", "").strip() or "465"
        if email and password:
            # Pehle login verify karo — ghalat password par save hi nahi hoga
            ok, msg = test_smtp(smtp_host, smtp_port, email, password)
            if ok:
                enc = get_fernet().encrypt(password.encode()).decode()
                db.execute(
                    """INSERT INTO email_accounts
                       (user_id,email,password_enc,smtp_host,smtp_port) VALUES (?,?,?,?,?)""",
                    (session["user_id"], email, enc, smtp_host, int(smtp_port)))
                db.commit()
                log_activity(db, session["user_id"], "email_added", f"Email account connected: {email}")
                db.commit()
                flash("Email connect ho gaya! Login verified. ✅", "success")
            else:
                flash("❌ " + msg + " — Account save NAHI hua. Password ya host check karo.", "error")
        else:
            flash("Email aur password dono zaroori hain.", "error")
        db.close()
        return redirect(url_for("emails"))
    rows = db.execute(
        "SELECT id,email,smtp_host,smtp_port,active,last_test,created_at "
        "FROM email_accounts WHERE user_id=? ORDER BY id",
        (session["user_id"],)).fetchall()
    db.close()
    return render_template("emails.html", accounts=rows,
                           admin_name=ADMIN_NAME, admin_email=ADMIN_EMAIL)


@app.route("/emails/<int:aid>/test")
@login_required
def email_test(aid):
    from datetime import datetime
    db = get_db()
    acc = db.execute("SELECT * FROM email_accounts WHERE id=? AND user_id=?",
                     (aid, session["user_id"])).fetchone()
    if acc:
        pw = get_fernet().decrypt(acc["password_enc"].encode()).decode()
        ok, msg = test_smtp(acc["smtp_host"], acc["smtp_port"], acc["email"], pw)
        db.execute("UPDATE email_accounts SET last_test=? WHERE id=?",
                   (("OK " if ok else "FAIL ") + datetime.now().strftime("%Y-%m-%d %H:%M"), aid))
        db.commit()
        flash(("✅ " if ok else "❌ ") + msg, "success" if ok else "error")
    db.close()
    return redirect(url_for("emails"))


@app.route("/emails/<int:aid>/toggle")
@login_required
def email_toggle(aid):
    db = get_db()
    db.execute("UPDATE email_accounts SET active = 1 - active WHERE id=? AND user_id=?",
               (aid, session["user_id"]))
    db.commit()
    db.close()
    return redirect(url_for("emails"))


@app.route("/emails/<int:aid>/delete")
@login_required
def email_delete(aid):
    db = get_db()
    db.execute("DELETE FROM email_accounts WHERE id=? AND user_id=?",
               (aid, session["user_id"]))
    db.commit()
    db.close()
    flash("Email account delete ho gaya.", "success")
    return redirect(url_for("emails"))


@app.route("/prospects", methods=["GET", "POST"])
@login_required
def prospects():
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        company = request.form.get("company", "").strip()
        country = request.form.get("country", "").strip()
        city = request.form.get("city", "").strip()
        if email:
            db.execute(
                "INSERT INTO prospects (user_id,name,email,company,country,city) VALUES (?,?,?,?,?,?)",
                (session["user_id"], name, email, company, country, city))
            db.commit()
            flash("Prospect add ho gaya.", "success")
        else:
            flash("Email zaroori hai.", "error")
        db.close()
        return redirect(url_for("prospects"))
    rows = db.execute(
        "SELECT * FROM prospects WHERE user_id=? ORDER BY id DESC LIMIT 200",
        (session["user_id"],)).fetchall()
    total = db.execute("SELECT COUNT(*) c FROM prospects WHERE user_id=?",
                       (session["user_id"],)).fetchone()["c"]
    db.close()
    return render_template("prospects.html", prospects=rows, total=total,
                           admin_name=ADMIN_NAME, admin_email=ADMIN_EMAIL)


@app.route("/prospects/upload", methods=["POST"])
@login_required
def prospects_upload():
    import csv, io
    f = request.files.get("file")
    added, skipped = 0, 0
    if f and f.filename:
        try:
            text = f.read().decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(text))
            db = get_db()
            for row in reader:
                email = (row.get("email") or "").strip()
                if not email or "@" not in email:
                    skipped += 1
                    continue
                db.execute(
                    "INSERT INTO prospects (user_id,name,email,company,country,city) VALUES (?,?,?,?,?,?)",
                    (session["user_id"],
                     (row.get("name") or "").strip(),
                     email,
                     (row.get("company") or "").strip(),
                     (row.get("country") or "").strip(),
                     (row.get("city") or "").strip()))
                added += 1
            db.commit()
            db.close()
        except Exception as e:
            flash("CSV parhne me error: " + str(e)[:120], "error")
            return redirect(url_for("prospects"))
        flash(f"{added} prospects upload ho gaye." + (f" {skipped} skip hue." if skipped else ""), "success")
    else:
        flash("CSV file select karo.", "error")
    return redirect(url_for("prospects"))


@app.route("/prospects/<int:pid>/delete")
@login_required
def prospect_delete(pid):
    db = get_db()
    db.execute("DELETE FROM prospects WHERE id=? AND user_id=?", (pid, session["user_id"]))
    db.commit()
    db.close()
    return redirect(url_for("prospects"))


SEED_TEMPLATES = [
    ("Initial Outreach", "initial",
     "Guest Posting Collaboration with {company}",
     """Dear {name},

I hope you're doing well.

My name is Saad Akram, an SEO Expert and Full-Stack Web Developer. I operate a portfolio of high-quality content websites, and I am reaching out to explore a potential guest posting collaboration with {company}.

What I offer:

- A professionally written, original article (1,500+ words)
- Natural, contextual placement with dofollow link(s)
- Genuine organic traffic on the publishing website
- Fast turnaround, typically within 3-5 business days

If this aligns with your content strategy, I would be glad to share our website portfolio, traffic statistics, and pricing details.

I look forward to hearing from you.

Best regards,
Saad Akram
SEO Expert & Full-Stack Web Developer"""),
    ("Follow-up 1 (Day 3)", "followup1",
     "Re: Guest Posting Collaboration with {company}",
     """Dear {name},

I hope this message finds you well.

I wanted to follow up on my previous email regarding a guest posting collaboration with {company}. I understand you receive many such messages, so I will keep this brief.

Our websites maintain genuine organic traffic, and we take pride in publishing only high-quality, original content. I would be happy to share traffic proof and samples of previously published work.

Would you be open to a brief discussion this week?

Best regards,
Saad Akram
SEO Expert & Full-Stack Web Developer"""),
    ("Follow-up 2 (Day 7)", "followup2",
     "Closing the loop - {company}",
     """Dear {name},

I will keep this final note brief.

I reached out last week about a guest posting collaboration with {company}. If the timing is not right, I completely understand - please feel free to reach out whenever content partnerships become a priority.

Wishing you continued success.

Best regards,
Saad Akram
SEO Expert & Full-Stack Web Developer"""),
]


def seed_templates(user_id):
    db = get_db()
    n = db.execute("SELECT COUNT(*) c FROM templates WHERE user_id=?", (user_id,)).fetchone()["c"]
    if n == 0:
        for name, kind, subject, body in SEED_TEMPLATES:
            db.execute(
                "INSERT INTO templates (user_id,name,kind,subject,body) VALUES (?,?,?,?,?)",
                (user_id, name, kind, subject, body))
        db.commit()
    db.close()


@app.route("/templates")
@login_required
def templates():
    seed_templates(session["user_id"])
    db = get_db()
    rows = db.execute("SELECT id,name,kind,subject FROM templates WHERE user_id=? ORDER BY id",
                      (session["user_id"],)).fetchall()
    db.close()
    return render_template("templates.html", templates=rows,
                           admin_name=ADMIN_NAME, admin_email=ADMIN_EMAIL)


@app.route("/templates/<int:tid>/edit", methods=["GET", "POST"])
@login_required
def template_edit(tid):
    db = get_db()
    t = db.execute("SELECT * FROM templates WHERE id=? AND user_id=?",
                   (tid, session["user_id"])).fetchone()
    if not t:
        db.close()
        return redirect(url_for("templates"))
    if request.method == "POST":
        db.execute(
            "UPDATE templates SET name=?,subject=?,body=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (request.form.get("name", t["name"]), request.form.get("subject", ""),
             request.form.get("body", ""), tid))
        db.commit()
        db.close()
        flash("Template save ho gaya.", "success")
        return redirect(url_for("templates"))
    db.close()
    return render_template("template_edit.html", t=t,
                           admin_name=ADMIN_NAME, admin_email=ADMIN_EMAIL)


@app.route("/emails/send-test", methods=["POST"])
@login_required
def email_send_test():
    import smtplib, ssl
    from email.mime.text import MIMEText
    aid = request.form.get("account_id", "")
    to = request.form.get("to", "").strip()
    db = get_db()
    acc = db.execute("SELECT * FROM email_accounts WHERE id=? AND user_id=?",
                     (aid, session["user_id"])).fetchone()
    db.close()
    if not acc:
        flash("Pehle koi email account select karo.", "error")
        return redirect(url_for("emails"))
    if not to or "@" not in to:
        flash("Sahi recipient email likho.", "error")
        return redirect(url_for("emails"))
    pw = get_fernet().decrypt(acc["password_enc"].encode()).decode()
    try:
        msg = MIMEText(
            "Ye OutreachPro by Saad Akram se bheja gaya test email hai.\n\n"
            "Agar ye tumhe mil gaya hai to tumhara email account bilkul sahi connect hai.\n\n"
            "Best regards,\nSaad Akram")
        msg["Subject"] = "OutreachPro by Saad Akram - Test Email"
        msg["From"] = acc["email"]
        msg["To"] = to
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(acc["smtp_host"], int(acc["smtp_port"]), context=ctx, timeout=25) as s:
            s.login(acc["email"], pw)
            s.send_message(msg)
        flash(f"Test email {to} par bhej di gayi! Inbox check karo.", "success")
    except Exception as e:
        flash("Bhejne me error: " + str(e)[:160], "error")
    return redirect(url_for("emails"))


@app.route("/campaigns", methods=["GET", "POST"])
@login_required
def campaigns():
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        template_id = request.form.get("template_id") or None
        daily_limit = int(request.form.get("daily_limit") or 20)
        send_hour = int(request.form.get("send_hour") or 9)
        if name and template_id:
            db.execute(
                "INSERT INTO campaigns (user_id,name,template_id,daily_limit,send_hour) VALUES (?,?,?,?,?)",
                (session["user_id"], name, template_id, daily_limit, send_hour))
            db.commit()
            log_activity(db, session["user_id"], "campaign_created",
                         f"Campaign '{name}' (limit {daily_limit}/day, hour {send_hour})")
            db.commit()
            flash("Campaign ban gayi.", "success")
        else:
            flash("Naam aur template zaroori hain.", "error")
        db.close()
        return redirect(url_for("campaigns"))
    camps = db.execute(
        """SELECT c.*, t.name AS tname,
           (SELECT COUNT(*) FROM outbox o WHERE o.campaign_id=c.id AND o.status='sent') AS sent
           FROM campaigns c LEFT JOIN templates t ON t.id=c.template_id
           WHERE c.user_id=? ORDER BY c.id DESC""", (session["user_id"],)).fetchall()
    tmpls = db.execute("SELECT id,name FROM templates WHERE user_id=? AND kind='initial'",
                       (session["user_id"],)).fetchall()
    db.close()
    return render_template("campaigns.html", campaigns=camps, templates=tmpls,
                           admin_name=ADMIN_NAME, admin_email=ADMIN_EMAIL)


@app.route("/campaigns/<int:cid>/toggle")
@login_required
def campaign_toggle(cid):
    db = get_db()
    db.execute("UPDATE campaigns SET active = 1 - active WHERE id=? AND user_id=?",
               (cid, session["user_id"]))
    db.commit()
    db.close()
    return redirect(url_for("campaigns"))


@app.route("/campaigns/<int:cid>/delete")
@login_required
def campaign_delete(cid):
    db = get_db()
    db.execute("DELETE FROM campaigns WHERE id=? AND user_id=?", (cid, session["user_id"]))
    db.commit()
    db.close()
    return redirect(url_for("campaigns"))


@app.route("/outbox")
@login_required
def outbox():
    db = get_db()
    rows = db.execute(
        """SELECT o.*, p.email AS pemail, p.country, a.email AS from_email
           FROM outbox o
           LEFT JOIN prospects p ON p.id=o.prospect_id
           LEFT JOIN email_accounts a ON a.id=o.account_id
           WHERE o.user_id=? ORDER BY o.id DESC LIMIT 200""",
        (session["user_id"],)).fetchall()
    db.close()
    return render_template("outbox.html", rows=rows,
                           admin_name=ADMIN_NAME, admin_email=ADMIN_EMAIL)


@app.route("/api/cron/send-due")
def cron_send_due():
    """Called by scheduler every 30 min. Sends due initial emails."""
    from datetime import datetime, date
    secret = request.args.get("key", "")
    want = os.environ.get("CRON_SECRET", "")
    if not want or secret != want:
        return {"ok": False, "error": "unauthorized"}, 403
    db = get_db()
    sent, skipped, failed = 0, 0, 0
    users = db.execute("SELECT DISTINCT user_id FROM campaigns WHERE active=1").fetchall()
    for u in users:
        uid = u["user_id"]
        if is_paused(db, uid):
            continue
        camps = db.execute("SELECT * FROM campaigns WHERE user_id=? AND active=1", (uid,)).fetchall()
        for camp in camps:
            today = date.today().isoformat()
            sent_today = db.execute(
                "SELECT COUNT(*) c FROM outbox WHERE campaign_id=? AND status='sent' AND date(sent_at)=?",
                (camp["id"], today)).fetchone()["c"]
            if sent_today >= camp["daily_limit"]:
                continue
            tmpl = db.execute("SELECT * FROM templates WHERE id=? AND user_id=?",
                              (camp["template_id"], uid)).fetchone()
            if not tmpl:
                continue
            prospects = db.execute(
                """SELECT * FROM prospects p WHERE p.user_id=? AND p.status='new'
                   AND p.status NOT IN ('bounced','unsubscribed','not_interested')
                   AND NOT EXISTS (SELECT 1 FROM outbox o WHERE o.prospect_id=p.id AND o.campaign_id=?)
                   ORDER BY p.id""", (uid, camp["id"])).fetchall()
            for p in prospects:
                if sent_today >= camp["daily_limit"]:
                    break
                if prospect_local_hour(p) != camp["send_hour"]:
                    skipped += 1
                    continue
                aid = pick_sender(db, uid)
                if not aid:
                    failed += 1
                    continue
                subject = spintax(render_text(tmpl["subject"], p))
                body = spintax(render_text(tmpl["body"], p))
                # insert outbox first to get an id for tracking links
                cur = db.execute(
                    """INSERT INTO outbox
                       (user_id,campaign_id,prospect_id,account_id,kind,subject,body,status)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (uid, camp["id"], p["id"], aid, "initial", subject, body, "queued"))
                oid = cur.lastrowid
                base = app_base_url()
                unsub_url = f"{base}/unsubscribe/{unsub_token(p['id'], uid)}" if base else None
                plain_final = body + (f"\n\n---\nDon't want these emails? Unsubscribe: {unsub_url}"
                                      if unsub_url else "")
                html_body = build_tracked_html(body, oid, unsub_url)
                ok, err = send_one_email(db, uid, aid, p["email"], subject, plain_final,
                                         html_body, unsub_url)
                now = datetime.now().isoformat(timespec="seconds")
                db.execute(
                    "UPDATE outbox SET status=?, sent_at=?, error=?, body=? WHERE id=?",
                    ("sent" if ok else "failed", now if ok else None,
                     err if not ok else None, plain_final, oid))
                if ok:
                    db.execute("UPDATE prospects SET status='contacted' WHERE id=?", (p["id"],))
                    sent += 1
                    sent_today += 1
                else:
                    failed += 1
            db.commit()
    db.close()
    return {"ok": True, "sent": sent, "skipped_not_due": skipped, "failed": failed}


@app.route("/inbox")
@login_required
def inbox():
    db = get_db()
    msgs = db.execute(
        """SELECT i.*, p.name AS pname, p.company
           FROM inbox_messages i LEFT JOIN prospects p ON p.id=i.prospect_id
           WHERE i.user_id=? ORDER BY i.id DESC LIMIT 50""",
        (session["user_id"],)).fetchall()
    drafts = db.execute(
        """SELECT d.*, p.name AS pname, p.email AS pemail
           FROM reply_drafts d LEFT JOIN prospects p ON p.id=d.prospect_id
           WHERE d.user_id=? AND d.status='pending' ORDER BY d.id DESC""",
        (session["user_id"],)).fetchall()
    db.close()
    return render_template("inbox.html", msgs=msgs, drafts=drafts,
                           admin_name=ADMIN_NAME, admin_email=ADMIN_EMAIL)


@app.route("/inbox/check-now")
@login_required
def inbox_check_now():
    db = get_db()
    n_msgs, n_drafts = check_inbox_for_user(db, session["user_id"])
    db.close()
    flash(f"Inbox check ho gaya: {n_msgs} naye replies, {n_drafts} drafts taiyar.",
          "success" if n_msgs else "info")
    return redirect(url_for("inbox"))


@app.route("/drafts/<int:did>/approve", methods=["POST"])
@login_required
def draft_approve(did):
    db = get_db()
    d = db.execute("SELECT * FROM reply_drafts WHERE id=? AND user_id=? AND status='pending'",
                   (did, session["user_id"])).fetchone()
    if not d:
        db.close()
        flash("Draft nahi mila.", "error")
        return redirect(url_for("inbox"))
    body = request.form.get("body", d["body"])
    subject = request.form.get("subject", d["subject"])
    prosp = db.execute("SELECT * FROM prospects WHERE id=?", (d["prospect_id"],)).fetchone()
    ok, err = send_one_email(db, session["user_id"], d["account_id"], prosp["email"], subject, body)
    from datetime import datetime
    if ok:
        db.execute("UPDATE reply_drafts SET status='sent', body=?, subject=? WHERE id=?",
                   (body, subject, did))
        db.execute(
            """INSERT INTO outbox (user_id,prospect_id,account_id,kind,subject,body,status,sent_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (session["user_id"], d["prospect_id"], d["account_id"], "reply", subject, body,
             "sent", datetime.now().isoformat(timespec="seconds")))
        db.execute("UPDATE prospects SET status='replied' WHERE id=?", (d["prospect_id"],))
        log_activity(db, session["user_id"], "reply_sent",
                     f"Approved reply sent to {prosp['email']}")
        flash("Reply bhej diya gaya! ✅", "success")
    else:
        flash("Bhejne me error: " + err[:120], "error")
    db.commit(); db.close()
    return redirect(url_for("inbox"))


@app.route("/drafts/<int:did>/reject")
@login_required
def draft_reject(did):
    db = get_db()
    db.execute("UPDATE reply_drafts SET status='rejected' WHERE id=? AND user_id=?",
               (did, session["user_id"]))
    db.commit(); db.close()
    flash("Draft reject kar diya.", "info")
    return redirect(url_for("inbox"))


@app.route("/settings/pause-toggle")
@login_required
def pause_toggle():
    db = get_db()
    paused = is_paused(db, session["user_id"])
    db.execute("INSERT OR REPLACE INTO settings (user_id, sending_paused) VALUES (?,?)",
               (session["user_id"], 0 if paused else 1))
    log_activity(db, session["user_id"],
                 "sending_resumed" if paused else "sending_paused",
                 "Emergency pause toggled")
    db.commit(); db.close()
    flash("▶️ Sending resume kar di!" if paused else "⏸️ Sending PAUSE kar di — ab koi email nahi jayegi.",
          "success" if paused else "info")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/activity")
@login_required
def activity():
    db = get_db()
    rows = db.execute("SELECT * FROM activity_log WHERE user_id=? ORDER BY id DESC LIMIT 200",
                      (session["user_id"],)).fetchall()
    paused = is_paused(db, session["user_id"])
    db.close()
    return render_template("activity.html", rows=rows, paused=paused,
                           admin_name=ADMIN_NAME, admin_email=ADMIN_EMAIL)


@app.route("/api/cron/check-inbox")
def cron_check_inbox():
    secret = request.args.get("key", "")
    want = os.environ.get("CRON_SECRET", "")
    if not want or secret != want:
        return {"ok": False, "error": "unauthorized"}, 403
    db = get_db()
    total_msgs, total_drafts = 0, 0
    for u in db.execute("SELECT DISTINCT user_id FROM email_accounts WHERE active=1").fetchall():
        nm, nd = check_inbox_for_user(db, u["user_id"])
        total_msgs += nm; total_drafts += nd
    db.close()
    return {"ok": True, "new_replies": total_msgs, "new_drafts": total_drafts}


@app.route("/logs")
@login_required
def logs():
    return render_template("soon.html", title="Activity Log",
                           admin_name=ADMIN_NAME, admin_email=ADMIN_EMAIL)


# ---- Tracking pixel / click redirect (public, no login) ----
_PIXEL = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff"
          b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00"
          b"\x00\x02\x02D\x01\x00;")


@app.route("/t/o/<int:oid>")
def track_open(oid):
    from flask import Response
    db = get_db()
    o = db.execute("SELECT user_id,prospect_id,campaign_id FROM outbox WHERE id=?", (oid,)).fetchone()
    if o:
        exists = db.execute(
            "SELECT id FROM email_events WHERE outbox_id=? AND event_type='open'", (oid,)).fetchone()
        if not exists:
            record_event(db, o["user_id"], oid, o["prospect_id"], o["campaign_id"], "open")
            db.commit()
    db.close()
    return Response(_PIXEL, mimetype="image/gif")


@app.route("/t/c/<int:oid>")
def track_click(oid):
    import urllib.parse
    from flask import redirect
    url = request.args.get("u", "")
    db = get_db()
    o = db.execute("SELECT user_id,prospect_id,campaign_id FROM outbox WHERE id=?", (oid,)).fetchone()
    if o and url.startswith(("http://", "https://")):
        record_event(db, o["user_id"], oid, o["prospect_id"], o["campaign_id"], "click", url[:300])
        db.commit()
    db.close()
    if url.startswith(("http://", "https://")):
        return redirect(url)
    return "Invalid link", 400


# ---- One-click unsubscribe (public, signed token) ----
@app.route("/unsubscribe/<token>", methods=["GET", "POST"])
def unsubscribe(token):
    data = unsub_data(token)
    if not data:
        return "Invalid unsubscribe link.", 400
    db = get_db()
    p = db.execute("SELECT id,email,name FROM prospects WHERE id=? AND user_id=?",
                   (data["p"], data["u"])).fetchone()
    if not p:
        db.close()
        return "Invalid unsubscribe link.", 400
    if request.method == "POST":
        db.execute("UPDATE prospects SET status='unsubscribed' WHERE id=?", (p["id"],))
        record_event(db, data["u"], None, p["id"], None, "unsubscribe", p["email"])
        db.commit()
        db.close()
        return render_template("unsubscribed.html", email=p["email"])
    db.close()
    return render_template("unsubscribe.html", email=p["email"], name=p["name"] or "there")


# ---- Analytics dashboard ----
@app.route("/analytics")
@login_required
def analytics():
    db = get_db()
    uid = session["user_id"]
    camps = db.execute("SELECT id,name FROM campaigns WHERE user_id=? ORDER BY id", (uid,)).fetchall()
    stats = []
    for c in camps:
        cid = c["id"]
        sent = db.execute(
            "SELECT COUNT(*) n FROM outbox WHERE campaign_id=? AND status='sent'", (cid,)).fetchone()["n"]
        opens = db.execute(
            "SELECT COUNT(DISTINCT outbox_id) n FROM email_events WHERE campaign_id=? AND event_type='open'",
            (cid,)).fetchone()["n"]
        clicks = db.execute(
            "SELECT COUNT(DISTINCT outbox_id) n FROM email_events WHERE campaign_id=? AND event_type='click'",
            (cid,)).fetchone()["n"]
        replies = db.execute(
            "SELECT COUNT(*) n FROM outbox WHERE campaign_id=? AND kind='reply' AND status='sent'",
            (cid,)).fetchone()["n"]
        # replies also come via inbox drafts; count replied prospects touched by this campaign
        bounced = db.execute(
            "SELECT COUNT(DISTINCT prospect_id) n FROM email_events WHERE campaign_id=? AND event_type='bounce'",
            (cid,)).fetchone()["n"]
        unsubs = db.execute(
            "SELECT COUNT(DISTINCT prospect_id) n FROM email_events WHERE campaign_id=? AND event_type='unsubscribe'",
            (cid,)).fetchone()["n"]
        stats.append({
            "name": c["name"], "sent": sent, "opens": opens, "clicks": clicks,
            "replies": replies, "bounced": bounced, "unsubs": unsubs,
            "open_rate": round(opens / sent * 100, 1) if sent else 0,
            "click_rate": round(clicks / sent * 100, 1) if sent else 0,
            "reply_rate": round(replies / sent * 100, 1) if sent else 0,
        })
    db.close()
    return render_template("analytics.html", stats=stats)


# Idempotent: creates tables + seeds admin on every host
# (local dev, Vercel serverless, Render/gunicorn). Must run at import time
# because gunicorn never executes the __main__ block below.
init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=False)
