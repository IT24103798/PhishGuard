# PhishGuard - Phishing Awareness Analyzer

PhishGuard is a Python Flask web application for Cybersecurity Project 3. It analyzes pasted emails or messages, identifies suspicious links and keywords, lists red flags, and explains why the content may be unsafe.

## Assignment requirements covered

- Identifies suspicious URLs and phishing keywords
- Lists detected red flags with exact evidence
- Explains why each indicator is unsafe
- Produces a transparent 0-100 risk score
- Recommends safe actions for the recipient

## Technology

- Python and Flask: backend and analysis rules
- HTML: interface structure
- CSS: responsive cybersecurity design
- JavaScript: API request and safe result rendering

## Run in VS Code on Windows

1. Open the project root folder: `PhishGuard-Project-3` in VS Code.
2. Open **Terminal > New Terminal**.
3. Run `cd PhishGuard` to enter the app folder.
4. Run `python -m venv .venv`.
5. Run `.\.venv\Scripts\Activate.ps1`.
6. Run `pip install -r requirements.txt`.
7. Run `python app.py`.
8. Open `http://127.0.0.1:5000`.

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and then activate again:

```powershell
.\.venv\Scripts\Activate.ps1
```

If the app is launched from outside the `PhishGuard` folder, use:

```powershell
cd "C:\Users\prawe\Downloads\Cyber Projecet\PhishGuard-Project-3"
.\.venv\Scripts\Activate.ps1
python .\PhishGuard\app.py
```

## Test

```bash
python -m unittest discover -s tests
```

## How the system works

1. The user pastes a sender, subject, and message into the webpage.
2. JavaScript sends this text to Flask as JSON.
3. Python checks keyword groups, message style, sender format, and URLs.
4. Every rule adds an explainable red flag and weighted score.
5. Flask returns a JSON report and JavaScript displays it safely using `textContent`.

The analyzer never opens or visits detected links. This prevents the project from interacting with a potentially malicious website.

## Example phishing indicators

- Urgent language designed to create pressure
- Requests for passwords, OTPs, or payment details
- IP addresses instead of domain names
- URL shorteners that hide destinations
- HTTP links, suspicious domains, punycode, and brand lookalikes
- Generic greetings and unexpected attachment instructions

## Important limitation

This is an educational, rule-based awareness tool. A low score does not prove that a message is legitimate, and a high score does not replace professional investigation. Do not paste passwords, OTPs, financial information, or confidential organizational data.
