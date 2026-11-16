#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

echo "=== apt ==="
apt-get update -qq
apt-get install -y -qq postgresql python3-pip python3-venv \
    fonts-liberation libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 \
    libxfixes3 libxrandr2 libgbm1 libasound2 libpangocairo-1.0-0 \
    libpango-1.0-0 libcairo2 libatspi2.0-0 libx11-6 libxcb1 \
    libxext6 libxi6 libxtst6 libglib2.0-0 libxss1 2>&1 | tail -2

echo "=== postgres user/db ==="
DBPW="Sc4n$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
su - postgres -c "psql -tc \"SELECT 1 FROM pg_roles WHERE rolname='scan'\"" | grep -q 1 \
    || su - postgres -c "psql -c \"CREATE USER scan WITH PASSWORD '$DBPW';\""
su - postgres -c "psql -lqt" | cut -d'|' -f1 | grep -qw scan \
    || su - postgres -c "createdb -O scan scan"
echo "$DBPW" > /root/.scan_dbpw
chmod 600 /root/.scan_dbpw
echo "DBPW=$DBPW"

echo "=== venv ==="
mkdir -p /opt/scan
cd /opt/scan
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt 2>&1 | tail -3

echo "=== playwright ==="
.venv/bin/playwright install chromium 2>&1 | tail -3

echo "=== systemd ==="
cat > /etc/systemd/system/scan.service <<EOF
[Unit]
Description=scan fingerprint platform
After=network.target postgresql.service

[Service]
WorkingDirectory=/opt/scan
Environment=SCAN_DB_URL=postgres://scan:${DBPW}@127.0.0.1:5432/scan
ExecStart=/opt/scan/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now scan
sleep 3
systemctl is-active scan
curl -s -o /dev/null -w "local http: %{http_code}\n" http://127.0.0.1:8000/
echo "=== DONE ==="
