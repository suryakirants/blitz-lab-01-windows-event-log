# BLITZ SOC Lab 01 — Windows Event Log Investigation

Standalone Flask SOC investigation lab for Blitz Academy.

## Run locally

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000

## Lab flow

1. Welcome screen
2. Start Lab
3. Investigate the Windows Security event dataset
4. Use Event ID, IP, account, severity and keyword filters
5. Open individual events for full details
6. Confirm the malicious source IP in Investigation Action
7. Correct IOC unlocks the BLITZ{} flag

## Creator testing

The intentionally malicious source IP is `185.71.67.24`.
The target account is `administrator` on `WIN-SOC-01`.
The attack is represented by repeated Event ID 4625 failures followed by Event ID 4624, then privileged/suspicious activity.

## Production note

For public deployment, set a strong `SECRET_KEY` environment variable and do not expose the creator answer sheet.
