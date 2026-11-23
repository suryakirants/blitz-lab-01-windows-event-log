# BLITZ Web Attack & SOC Monitoring Lab 02

A static, browser-based CTF simulation for students to practice SQL injection, cross-site scripting (XSS), and brute-force detection while observing corresponding events in a SOC dashboard.

## Pages
- `index.html` — Northstar Commerce training application (attack surface).
- `soc.html` — SOC monitoring dashboard (live event stream).

## GitHub Pages
This lab is stored in the `web-threat-hunt/` folder of the `blitz-lab-01-windows-event-log` repository.

If GitHub Pages is enabled for the repository from **Settings → Pages** and the deployment source is the `main` branch / root, open:

`https://suryakirants.github.io/blitz-lab-01-windows-event-log/web-threat-hunt/`

SOC dashboard:

`https://suryakirants.github.io/blitz-lab-01-windows-event-log/web-threat-hunt/soc.html`

If Pages is not enabled, enable it in repository Settings → Pages. No build framework is required.

## Student workflow
1. Open the training application and SOC dashboard in two tabs in the same browser profile.
2. Perform the three attack simulations against the fictional application.
3. Watch the event stream update and select rows to inspect complete event fields.
4. Record the flags shown by the application and the relevant telemetry details in the instructor's separate worksheet.

## Important technical scope
GitHub Pages is static hosting; it cannot run a backend, database, server-side authentication service, or shared telemetry collector. Therefore this lab safely simulates vulnerable application behavior in the browser. The SOC dashboard receives events in near real time through browser localStorage, the storage event, and BroadcastChannel. Both pages must be opened in the same browser profile/device for live event sharing. Events do not synchronize across different students' devices.

No real credentials are validated or transmitted. XSS-like input is treated as inert text and never executed. The source IPs are documentation-only TEST-NET addresses. The lab is designed for authorized classroom practice, not production security testing.

## Event reference
| Exercise | Event type | Source IP | Endpoint | Detection rule |
|---|---|---|---|---|
| SQL injection | SQL_INJECTION | 198.51.100.23 | /api/catalog/search | WEB-SQLI-01 |
| XSS | XSS_ATTEMPT | 203.0.113.77 | /support/comments | WEB-XSS-02 |
| Brute force | AUTH_FAILURE / BRUTE_FORCE_DETECTED | 192.0.2.44 | /auth/session | AUTH-FAIL-01 / AUTH-BRUTE-05 |

Event codes: WEB-1001 (SQLi), WEB-1002 (XSS), AUTH-2001 (authentication failure), AUTH-2005 (threshold/lockout alert).
