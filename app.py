from flask import Flask, render_template, request, jsonify, session
import json, os, math

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "blitz-lab01-dev-secret")

DATA_FILE = os.path.join(os.path.dirname(__file__), "data", "windows_security_events.json")
with open(DATA_FILE, encoding="utf-8") as f:
    EVENTS = json.load(f)

FLAG = "BLITZ{WINDOWS_EVENT_CORRELATION_4625_185_71_67_24}"

@app.route("/")
def index():
    return render_template("welcome.html")

@app.route("/lab")
def lab():
    session["started"] = True
    return render_template("lab.html", total=len(EVENTS))

@app.route("/api/events")
def api_events():
    if not session.get("started"):
        return jsonify({"error": "Lab not started"}), 403

    q = request.args.get("q", "").strip().lower()
    event_id = request.args.get("event_id", "").strip()
    source_ip = request.args.get("source_ip", "").strip().lower()
    account = request.args.get("account", "").strip().lower()
    hostname = request.args.get("hostname", "").strip().lower()
    level = request.args.get("level", "").strip().lower()
    page = max(int(request.args.get("page", 1)), 1)
    per_page = 25

    filtered = EVENTS
    if q:
        filtered = [e for e in filtered if q in json.dumps(e).lower()]
    if event_id:
        filtered = [e for e in filtered if str(e["event_id"]) == event_id]
    if source_ip:
        filtered = [e for e in filtered if source_ip in e["source_ip"].lower()]
    if account:
        filtered = [e for e in filtered if account in e["account"].lower()]
    if hostname:
        filtered = [e for e in filtered if hostname in e["hostname"].lower()]
    if level:
        filtered = [e for e in filtered if level == e["level"].lower()]

    # newest first
    filtered = list(reversed(filtered))
    total = len(filtered)
    start = (page - 1) * per_page
    return jsonify({
        "events": filtered[start:start+per_page],
        "total": total,
        "page": page,
        "pages": max(1, math.ceil(total/per_page))
    })

@app.route("/api/stats")
def stats():
    if not session.get("started"):
        return jsonify({"error": "Lab not started"}), 403
    return jsonify({
        "total": len(EVENTS),
        "failed_logons": sum(1 for e in EVENTS if e["event_id"] == 4625),
        "successful_logons": sum(1 for e in EVENTS if e["event_id"] == 4624),
        "warnings": sum(1 for e in EVENTS if e["level"] == "Warning"),
        "unique_ips": len(set(e["source_ip"] for e in EVENTS))
    })

@app.post("/api/confirm-ioc")
def confirm_ioc():
    if not session.get("started"):
        return jsonify({"success": False, "message": "Start the lab first."}), 403
    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()
    if ip == "185.71.67.24":
        session["flag_unlocked"] = True
        return jsonify({"success": True, "flag": FLAG})
    return jsonify({"success": False, "message": "The submitted IP is not the confirmed malicious source IP. Continue correlating the events."})

@app.route("/api/status")
def status():
    return jsonify({"unlocked": bool(session.get("flag_unlocked")), "flag": FLAG if session.get("flag_unlocked") else None})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
