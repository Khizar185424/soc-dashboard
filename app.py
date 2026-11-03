import csv, os, re
from collections import defaultdict
from flask import Flask, jsonify, render_template

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))

# reports from project 1 and project 2. the first path that exists gets used,
# so if your folders are somewhere else, change the first path in each list.
THREAT_CSV = [
    r"C:\Users\Khizar\network-threat-classifier\network-threat-classifier\threat_report.csv",
    os.path.join(BASE, "data", "threat_report.csv"),
]
PHISH_TXT = [
    r"C:\Users\Khizar\phishing-email-analyzer\phishing_report.txt",
    os.path.join(BASE, "data", "phishing_report.txt"),
]

LOG_RE = re.compile(r"^(\S+ \S+) (\w+) (\S+) (.*)$")   # date time LEVEL ip message
HEAD_RE = re.compile(r"(EMAIL \d+)\s+\S+\s+(PHISHING|SUSPICIOUS|SAFE)\s+\(Score:\s*(\d+)")


def pick(paths):
    return next((p for p in paths if os.path.exists(p)), None)


def load_events(path):
    events = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            m = LOG_RE.match(row["log"])
            time, level, ip, msg = m.groups() if m else ("", "", row["ip"], row["log"])
            events.append({"time": time, "ip": row["ip"], "msg": msg,
                           "cls": row["classification"], "severity": int(row["severity"])})
    return events


def load_emails(path):
    emails, cur = [], None
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            m = HEAD_RE.search(s)
            if m:
                cur = {"id": m.group(1), "cls": m.group(2), "score": int(m.group(3)),
                       "from": "", "subject": "", "flags": []}
                emails.append(cur)
            elif cur is None:
                continue
            elif s.startswith("From"):
                cur["from"] = s.split(":", 1)[1].strip()
            elif s.startswith("Subject"):
                cur["subject"] = s.split(":", 1)[1].strip()
            elif s.startswith("\u26a1"):
                cur["flags"].append(s.lstrip("\u26a1").strip())
    return emails


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/data")
def data():
    tp, pp = pick(THREAT_CSV), pick(PHISH_TXT)
    events = load_events(tp) if tp else []
    emails = load_emails(pp) if pp else []

    alerts = sorted([e for e in events if e["cls"] != "NORMAL"], key=lambda e: -e["severity"])
    ips = defaultdict(lambda: {"threats": 0, "max_severity": 0})
    for a in alerts:
        ips[a["ip"]]["threats"] += 1
        ips[a["ip"]]["max_severity"] = max(ips[a["ip"]]["max_severity"], a["severity"])
    top_ips = sorted(({"ip": ip, **v} for ip, v in ips.items()),
                     key=lambda x: (-x["max_severity"], -x["threats"]))[:6]

    count = lambda items, c: sum(1 for i in items if i["cls"] == c)
    return jsonify({
        "totals": {"events": len(events), "malicious": count(events, "MALICIOUS"),
                   "suspicious": count(events, "SUSPICIOUS"), "normal": count(events, "NORMAL"),
                   "phishing": count(emails, "PHISHING")},
        "alerts": alerts, "top_ips": top_ips, "emails": emails,
        "using_sample": any(p and p.startswith(os.path.join(BASE, "data")) for p in (tp, pp)),
        "missing": [n for n, p in (("threat_report.csv", tp), ("phishing_report.txt", pp)) if not p],
    })


if __name__ == "__main__":
    app.run(debug=True)
