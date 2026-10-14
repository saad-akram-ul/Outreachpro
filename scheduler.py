#!/usr/bin/env python3
"""OutreachPro scheduler trigger - hits the send-due endpoint every 30 min.
Run: nohup ./venv/bin/python scheduler.py > scheduler.out 2>&1 &
Logs: ~/workspace/outreach/cron.log
"""
import time
import urllib.request
import datetime
import os

HOME = os.path.expanduser("~")
KEY = open(os.path.join(HOME, "workspace/outreach/.cron_key")).read().strip()
BASE = "https://outreachpro-saad-9034.vercel.app"
URLS = [
    f"{BASE}/api/cron/send-due?key={KEY}",
    f"{BASE}/api/cron/check-inbox?key={KEY}",
]
LOG = os.path.join(HOME, "workspace/outreach/cron.log")
INTERVAL = 1800  # 30 minutes


def tick():
    results = []
    for url in URLS:
        try:
            with urllib.request.urlopen(url, timeout=120) as r:
                results.append(f"OK {r.read().decode()[:200]}")
        except Exception as e:
            results.append(f"ERR {e}")
    return " | ".join(results)


if __name__ == "__main__":
    while True:
        line = f"{datetime.datetime.now().isoformat()} {tick()}\n"
        with open(LOG, "a") as f:
            f.write(line)
        time.sleep(INTERVAL)
