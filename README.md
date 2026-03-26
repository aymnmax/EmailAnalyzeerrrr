# MailTrace — SOC Email Header Analyser

A fully in-house, client-side email header analysis tool built for SOC teams. No external dependencies, no data leaves the browser.

## Features

- **SPF / DKIM / DMARC / ARC** parsing and validation
- **Phishing indicators** — Reply-To mismatch, domain spoofing, missing headers
- **Hop-by-hop routing analysis** — full Received chain with timing
- **Risk scoring** — 0–100 composite risk score with breakdown
- **100% private** — everything runs client-side, no API calls

## Project Structure

```
eml-analyser/
├── index.html      ← Main page structure
├── style.css       ← All styling (dark theme, responsive)
├── analyser.js     ← All parsing + analysis logic
└── README.md
```

## Running in GitHub Codespaces

### Option 1 — Open directly
Since this is plain HTML/CSS/JS with no build step, just open `index.html` via the Live Preview extension or serve it:

```bash
# Install a simple server (if needed)
npx serve .

# Or with Python
python3 -m http.server 8080
```

Then open the forwarded port URL in your browser.

### Option 2 — VS Code Live Server
1. Install the **Live Server** extension in Codespace
2. Right-click `index.html` → **Open with Live Server**

## Usage

1. Copy raw email headers from your email client or mail server logs
2. Paste into the text area
3. Click **Analyse Headers**
4. Review findings across the Overview, Authentication, Routing, and Findings tabs

### Getting raw headers

| Client | How to get headers |
|---|---|
| Gmail | Open email → ⋮ menu → Show original |
| Outlook | File → Properties → Internet headers |
| Thunderbird | View → Message Source |
| Apple Mail | View → Message → Raw Source |

## Checks Performed

| Check | Description |
|---|---|
| SPF | Verifies sending server is authorised by domain |
| DKIM | Validates cryptographic signature |
| DMARC | Checks domain alignment policy |
| ARC | Authenticated Received Chain (forwarding) |
| Reply-To mismatch | Detects domain differences between From and Reply-To |
| Return-Path mismatch | Compares envelope sender vs From domain |
| DKIM alignment | Compares signing domain vs From domain |
| Hop analysis | Parses Received chain, detects unusual relays |
| Timestamp checks | Detects future-dated or missing timestamps |
| Spam headers | Reads X-Spam-Status headers |

## Adding to Your SOC Portal

Since this is pure HTML/CSS/JS, you can embed it in any intranet:
- Drop the 3 files into any web server
- Embed `index.html` in an iframe within your portal
- No backend, database, or authentication required

## Roadmap Ideas

- [ ] URL extraction and safe preview
- [ ] Attachment indicator detection
- [ ] Bulk EML file upload (drag & drop)
- [ ] Export findings as PDF/JSON
- [ ] IP reputation API integration (optional, toggle-able)
- [ ] YARA rule-based pattern matching
