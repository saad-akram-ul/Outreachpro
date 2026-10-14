"""DB layer for OutreachPro.

- Local dev / Vercel : SQLite (unchanged behaviour).
- Render            : Postgres when DATABASE_URL is set.

The Postgres path is a drop-in compatibility wrapper: it translates
`?` placeholders to `%s`, maps INSERT OR IGNORE / OR REPLACE to
ON CONFLICT, and emulates cursor.lastrowid via RETURNING id.
Rows are dict-like (row["col"]) on both backends.
"""
import os
import re

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
USE_PG = bool(DATABASE_URL)

_QMARK = re.compile(r"\?")


if USE_PG:
    import psycopg2
    import psycopg2.extras

    def _translate(sql):
        s = sql.strip()
        up = s.upper()
        if up.startswith("INSERT OR IGNORE"):
            s = re.sub(r"(?i)^INSERT\s+OR\s+IGNORE\s+INTO", "INSERT INTO", s, count=1)
            s = s.rstrip(";") + " ON CONFLICT DO NOTHING RETURNING id"
        elif up.startswith("INSERT OR REPLACE"):
            s = re.sub(r"(?i)^INSERT\s+OR\s+REPLACE\s+INTO", "INSERT INTO", s, count=1)
            # only used for the settings upsert (user_id, sending_paused)
            s = (s.rstrip(";") + " ON CONFLICT (user_id) DO UPDATE "
                 "SET sending_paused=EXCLUDED.sending_paused")
        elif up.startswith("INSERT"):
            s = s.rstrip(";") + " RETURNING id"
        return _QMARK.sub("%s", s)

    class _Cursor:
        def __init__(self, cur):
            self._c = cur
            self.lastrowid = None

        def execute(self, sql, params=()):
            translated = _translate(sql)
            self._c.execute(translated, params or ())
            if sql.strip().upper().startswith("INSERT") and "RETURNING" in translated.upper():
                row = self._c.fetchone()
                self.lastrowid = row["id"] if row else None
            return self

        @property
        def rowcount(self):
            return self._c.rowcount

        def fetchone(self):
            return self._c.fetchone()

        def fetchall(self):
            return self._c.fetchall()

        def __iter__(self):
            return iter(self._c)

    class _Conn:
        def __init__(self):
            self._c = psycopg2.connect(
                DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

        def execute(self, sql, params=()):
            return _Cursor(self._c.cursor()).execute(sql, params)

        def commit(self):
            self._c.commit()

        def close(self):
            self._c.close()

    def get_db():
        return _Conn()

else:
    import sqlite3

    BASE = os.path.dirname(os.path.abspath(__file__))
    # Vercel serverless: filesystem is read-only except /tmp
    DB = os.path.join("/tmp" if os.environ.get("VERCEL") else BASE, "outreach.db")

    def get_db():
        db = sqlite3.connect(DB)
        db.row_factory = sqlite3.Row
        return db


def init_db():
    from werkzeug.security import generate_password_hash

    db = get_db()
    auto = "SERIAL PRIMARY KEY" if USE_PG else "INTEGER PRIMARY KEY AUTOINCREMENT"
    db.execute(f"""CREATE TABLE IF NOT EXISTS users (
        id {auto},
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT, email TEXT, role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    if not db.execute("SELECT id FROM users WHERE username='admin'").fetchone():
        db.execute(
            "INSERT INTO users (username,password_hash,name,email,role) VALUES (?,?,?,?,?)",
            ("admin", generate_password_hash("admin123"),
             "Saad Akram", "ranasaadakram.gcuf.cs@gmail.com", "admin"))
    db.execute(f"""CREATE TABLE IF NOT EXISTS tasks (
        id {auto},
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        task_date TEXT NOT NULL,
        done INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    db.execute(f"""CREATE TABLE IF NOT EXISTS email_accounts (
        id {auto},
        user_id INTEGER NOT NULL,
        email TEXT NOT NULL,
        password_enc TEXT NOT NULL,
        smtp_host TEXT DEFAULT 'smtp.hostinger.com',
        smtp_port INTEGER DEFAULT 465,
        imap_host TEXT DEFAULT 'imap.hostinger.com',
        imap_port INTEGER DEFAULT 993,
        active INTEGER DEFAULT 1,
        last_test TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    db.execute(f"""CREATE TABLE IF NOT EXISTS prospects (
        id {auto},
        user_id INTEGER NOT NULL,
        name TEXT,
        email TEXT NOT NULL,
        company TEXT,
        country TEXT,
        city TEXT,
        status TEXT DEFAULT 'new',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    db.execute(f"""CREATE TABLE IF NOT EXISTS templates (
        id {auto},
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        kind TEXT NOT NULL,
        subject TEXT NOT NULL,
        body TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    db.execute(f"""CREATE TABLE IF NOT EXISTS campaigns (
        id {auto},
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        template_id INTEGER,
        daily_limit INTEGER DEFAULT 20,
        send_hour INTEGER DEFAULT 9,
        active INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    db.execute(f"""CREATE TABLE IF NOT EXISTS outbox (
        id {auto},
        user_id INTEGER NOT NULL,
        campaign_id INTEGER,
        prospect_id INTEGER,
        account_id INTEGER,
        kind TEXT DEFAULT 'initial',
        subject TEXT,
        body TEXT,
        status TEXT DEFAULT 'queued',
        scheduled_for TEXT,
        sent_at TEXT,
        error TEXT)""")
    db.execute(f"""CREATE TABLE IF NOT EXISTS inbox_messages (
        id {auto},
        user_id INTEGER NOT NULL,
        account_id INTEGER,
        prospect_id INTEGER,
        from_email TEXT,
        subject TEXT,
        body TEXT,
        received_at TEXT,
        msg_uid TEXT,
        status TEXT DEFAULT 'new',
        UNIQUE(user_id, account_id, msg_uid))""")
    db.execute(f"""CREATE TABLE IF NOT EXISTS reply_drafts (
        id {auto},
        user_id INTEGER NOT NULL,
        inbox_id INTEGER,
        prospect_id INTEGER,
        account_id INTEGER,
        subject TEXT,
        body TEXT,
        intent TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    db.execute(f"""CREATE TABLE IF NOT EXISTS activity_log (
        id {auto},
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    db.execute(f"""CREATE TABLE IF NOT EXISTS email_events (
        id {auto},
        user_id INTEGER NOT NULL,
        outbox_id INTEGER,
        prospect_id INTEGER,
        campaign_id INTEGER,
        event_type TEXT NOT NULL,
        detail TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    db.execute("""CREATE TABLE IF NOT EXISTS settings (
        user_id INTEGER PRIMARY KEY,
        sending_paused INTEGER DEFAULT 0)""")
    # Migration: smtp_secure column for STARTTLS (Gmail etc.) support
    try:
        cols = [c[1] for c in db.execute("PRAGMA table_info(email_accounts)").fetchall()]
        if "smtp_secure" not in cols:
            db.execute("ALTER TABLE email_accounts ADD COLUMN smtp_secure TEXT DEFAULT 'ssl'")
    except Exception:
        pass
    db.commit()
    db.close()
