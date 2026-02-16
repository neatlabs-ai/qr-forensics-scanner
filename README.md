# 🔍 QR Code Forensic Scanner
### Enterprise QR Analysis • Payload Forensics • Threat Detection

**NeatLabs™ — Bringing Context to Chaos**

---

## Overview

**QR Code Forensic Scanner** is an enterprise-grade digital forensics and threat analysis tool designed for cybersecurity professionals, investigators, and security researchers.

The platform performs deep inspection of QR codes including payload classification, phishing detection, structural QR analysis, image manipulation detection, steganography indicators, and automated threat scoring.

It provides both a full graphical interface and command-line workflow with professional standalone HTML reporting.

---

## 🚀 Key Capabilities

### Multi-Engine QR / Barcode Decoding
- OpenCV QR detection engine
- libzbar decoding support
- Enhanced detection fallback modes
- Multi-QR detection
- QR overlay / poisoning detection

### Payload Intelligence & Classification
- URL threat analysis
- WiFi credential analysis
- Cryptocurrency wallet detection
- vCard parsing
- Email / SMS / phone payload extraction
- OTP / MFA secret detection
- Plaintext and encoded payload analysis

### Threat Detection Engine
- 50+ phishing heuristic indicators
- URL obfuscation detection
- Redirect chain detection
- Homograph attack detection
- Script injection detection
- IOC extraction
- Risk scoring engine (0–100)

### QR Structural Analysis
- Finder pattern detection
- QR version estimation
- Error correction level estimation
- Quiet zone validation
- Rotation detection
- Overlay attack indicators

### Image Forensics
- EXIF metadata extraction
- File hashing (MD5 / SHA1 / SHA256)
- Steganography indicators (LSB analysis)
- Entropy analysis
- Image manipulation detection

### Professional Reporting
- Standalone HTML forensic reports
- JSON export
- Batch scanning support
- GUI dashboard interface

---

## 🖥 Interface Options

### Graphical Interface
- Dark themed forensic dashboard
- Image preview
- Threat visualization
- IOC extraction display
- Real-time scan logs

### Command Line Interface
- Single file scanning
- Directory batch scanning
- Report generation
- JSON output

---

## 📦 Installation

### Requirements

- Python 3.9+
- NumPy
- OpenCV
- Pillow

Install dependencies:

```bash
pip install -r requirements.txt
```

Optional (recommended for additional decoding support):

```bash
sudo apt install libzbar0
```

---

## ⚡ Usage

### Launch GUI

```bash
python qr_forensic_scanner.py
```

---

### Scan Single Image

```bash
python qr_forensic_scanner.py image.png
```

---

### Batch Scan Directory

```bash
python qr_forensic_scanner.py images/
```

---

### Generate HTML Report

```bash
python qr_forensic_scanner.py image.png --report output.html
```

---

### JSON Output

```bash
python qr_forensic_scanner.py image.png --json
```

---

### Generate Demo Dataset

```bash
python qr_forensic_scanner.py --demo
```

---

## 📁 Supported Image Formats

- PNG
- JPG
- JPEG
- BMP
- GIF
- TIFF
- WEBP

---

## 🧠 Architecture

```
QR Decoder Engine
    ↓
Payload Analyzer
    ↓
Threat Detection Engine
    ↓
QR Structural Analyzer
    ↓
Image Forensic Analyzer
    ↓
Report Generator
```

---

## 🎯 Use Cases

- Digital forensics investigations
- Phishing analysis
- Incident response workflows
- QR poisoning detection
- Security research
- OSINT analysis
- Threat intelligence enrichment
- Malware delivery vector analysis

---

## 🔐 Security Notes

This tool performs automated analysis and should not replace expert validation.

Always:
- Validate findings independently
- Execute in controlled environments
- Treat decoded payloads as untrusted input

---

## 🗺 Roadmap

- Machine learning threat classification
- SIEM integration
- YARA rule support
- REST API mode
- Cloud analysis pipeline
- Multi-user investigation workspace

---

## 👤 Author

**NeatLabs™**  
https://neatlabs.ai

---

## 📜 License

Proprietary — All Rights Reserved  
Copyright © 2026 NeatLabs™

Unauthorized copying, distribution, or modification is prohibited.

---

## ⭐ About NeatLabs™

NeatLabs builds advanced cybersecurity, AI, and information integrity platforms designed to bring clarity, context, and actionable intelligence to complex digital environments.
