#!/bin/bash
# Re-install the OutreachPro scheduler trigger (run after VM replacement)
KEY=$(cat ~/workspace/outreach/.cron_key)
CRON="*/30 * * * * curl -s \"https://outreachpro-saad-9034.vercel.app/api/cron/send-due?key=$KEY\" >> ~/workspace/outreach/cron.log 2>&1"
(crontab -l 2>/dev/null | grep -v "api/cron/send-due"; echo "$CRON") | crontab -
echo "cron installed:"; crontab -l | grep "api/cron/send-due"
