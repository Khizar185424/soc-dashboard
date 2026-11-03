# SOC Dashboard

A small Flask web dashboard that pulls the output of my two other cybersecurity projects into one SOC-style view.

![SOC Dashboard](dashboard.png)

## What it shows

- Summary cards: total events, malicious events, suspicious events and phishing emails
- A doughnut chart of the event breakdown
- A bar chart of the top threat IPs by maximum severity
- An alert feed sorted with the highest severity first
- A phishing table with each email's result, score and top indicators
- Auto-refresh every 10 seconds, so re-running the other projects updates the page

## How it fits together

| Project | What it produces |
|---|---|
| [Network Threat Classifier](https://github.com/Khizar185424/network-threat-classifier) | `threat_report.csv` |
| [Phishing Email Analyzer](https://github.com/Khizar185424/phishing-email-analyzer) | `phishing_report.txt` |
| This dashboard | Reads both files and displays them |

## How to run

1. Clone this repository
2. Install Flask: `pip install -r requirements.txt`
3. Start the app: `python app.py`
4. Open `http://127.0.0.1:5000` in your browser

The dashboard looks for the reports from the two projects above (paths are at the top of `app.py`). If it can't find them, it falls back to the sample files in the `data` folder and shows a banner saying so.

## Tech used

Python, Flask, Chart.js, HTML and CSS

## Limitations and next steps

- It reads saved report files, not a live log stream
- The phishing report is parsed from text; exporting it as JSON would be more reliable
- No login, so it is meant for local use only
- Ideas: send alerts to Splunk, enrich IPs with VirusTotal, add a severity-over-time chart

## Author

Khizar Malik
[LinkedIn](https://linkedin.com/in/khizar-malik-s10) | [GitHub](https://github.com/Khizar185424)