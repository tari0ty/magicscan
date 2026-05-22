# 🔬 MagicScan — File Type Validator

> A cybersecurity desktop tool that identifies files by their 
> raw byte signatures (magic numbers) — not by trusting filenames.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-green)


---

## What it does

Most operating systems trust a file's extension to determine 
its type. MagicScan doesn't. It reads the raw bytes at the 
start of every file and compares them against 70+ known 
cryptographic signatures — the same technique used by 
professional forensic analysts.

---

## Features

| Feature | Description |
|---|---|
| Magic Number Detection | Identifies 70+ file types from raw bytes |
| Spoofing Detection | Flags files whose extension doesn't match their true type |
| Malware Hash Check | Generates MD5, SHA-1, SHA-256 and queries VirusTotal |
| Probability Matching | Scores multiple potential file types by confidence % |
| Metadata Extraction | Extracts EXIF, audio tags, and video stream info |
| Screenshot/Recording Detection | Identifies screenshots and screen recordings from metadata |
| File Preview | In-app preview for images, text, and PDF files |
| Drag & Drop | Drop files or entire folders for instant scanning |
| Export Report | Generates a self-contained HTML forensic report |
| Offline Capable | Full functionality without internet — magic DB is local |
| VirusTotal Integration | Optional live malware check via VirusTotal API |

---

## Screenshots

<!-- Add screenshots here after uploading to GitHub -->

---

## Installation

```bash
# Clone the repo
git clone https://github.com/YOURUSERNAME/magicscan.git
cd magicscan

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
sudo apt install libmediainfo0v5

# Run
python3 gui.py
```

---

## VirusTotal Integration (Optional)

1. Sign up free at [virustotal.com](https://virustotal.com)
2. Go to your profile → API Key
3. Open the app → click ⚙ Settings → paste your key

Your key is stored locally in `~/.magicscan_settings.json` 
and never hardcoded or shared.

---

## Tech Stack

- **Python 3** — core language
- **Tkinter + tkinterdnd2** — GUI and drag & drop
- **Pillow** — image processing and EXIF extraction
- **mutagen** — audio metadata
- **pymediainfo** — video stream analysis
- **pypdf** — PDF text extraction
- **requests** — VirusTotal API calls
- **hashlib** — cryptographic hashing (built-in)
- **threading** — non-blocking background scanning

---

## Project Structure
magicscan/
├── magic_db.py     # 70+ magic number signatures database
├── scanner.py      # Core scanning and analysis engine
├── gui.py          # Desktop GUI (Tkinter)
├── main.py         # Terminal/CLI interface
└── requirements.txt
