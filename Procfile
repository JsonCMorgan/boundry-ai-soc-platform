# --workers 1 is required: SIEM, Splunk forwarder, and VPN-monitor background threads assume a single-process app.
web: gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120 --max-requests 1000 --max-requests-jitter 100
