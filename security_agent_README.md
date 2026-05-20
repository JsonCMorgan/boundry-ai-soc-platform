# Boundry.AI Security Log Analyst

Automated threat detection and AI-powered incident reporting for web applications.

## What It Does

1. Reads your application's security log
2. Detects brute force login attacks and SQL injection attempts
3. Generates a plain-English incident report using AI
4. Saves timestamped reports to `docs/reports/`

## Detections

| Threat | Logic |
|---|---|
| Brute Force | 3+ failed logins for the same username |
| Compromised Account | Brute force followed by successful login |
| SQL Injection | Search queries containing `' OR`, `' AND`, `--`, `'=` patterns |

## Setup

```bash
# Install dependencies
pip install anthropic

# Set your API key
export ANTHROPIC_API_KEY=your_key_here

# Run against the default log
python security_agent.py

# Run against a custom log file
python security_agent.py --log /path/to/your/app.log

# Run detection only (no AI report)
python security_agent.py --no-ai
```

## Log Format

The agent expects log lines in this format:

```
2026-05-09T00:01:28 WARNING LOGIN_FAILED username=admin ip=127.0.0.1
2026-05-09T00:01:29 INFO LOGIN_SUCCESS username=admin ip=127.0.0.1
2026-05-09T00:01:29 INFO SEARCH username=admin query='alice' ip=127.0.0.1
```

To add this logging to a Flask app, use the pattern in `app.py`.

## Output

Reports are saved to `docs/reports/incident_report_YYYY-MM-DD_HH-MM.md`

See `docs/reports/SAMPLE_INCIDENT_REPORT.md` for an example.

## Pricing

See `docs/BOUNDRY_AI_SERVICE.md` for service tiers and pricing.

---

*Built by Boundry.AI — Security that speaks your language.*
