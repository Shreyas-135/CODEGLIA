# 🚀 CodeGlia – Intelligent Vulnerability Scanner

CodeGlia is an **AI-augmented static analysis tool** that integrates **Semgrep**, **Bandit**, and **Google Gemini API** to detect and explain vulnerabilities across multiple programming languages.

---

## 🧠 Overview

CodeGlia provides **real-time vulnerability scanning** through an interactive Flask-based dashboard.  
It allows developers to upload entire projects (ZIP or folder), scans the source code for potential security issues, and generates **AI-enriched reports** explaining the findings.

---

## 🧩 Features

- 🔍 Multi-language static analysis (Python, Java, C, C#, PHP, JavaScript)
- 🤖 AI-powered vulnerability explanation and severity labeling
- 📊 Trust Score computation and visual trend tracking
- 🌐 Flask-based web dashboard with live scan progress
- 🧱 Dockerized for fast deployment and consistency
- ⚙️ Supports local Semgrep rule packs for offline scanning

---

## 🖥️ Tech Stack

| Layer | Technology |
|-------|-------------|
| **Frontend** | HTML, CSS (custom dark theme), JS |
| **Backend** | Python (Flask) |
| **AI Integration** | Google Gemini API |
| **Security Analysis** | Semgrep, Bandit |
| **Packaging & Deployment** | Docker |
| **Data Handling** | JSON, Pandas (for parsing reports) |

---

## 🧪 How to Run Locally

### **Option 1 – Using Python**
```bash
git clone https://github.com/Shreyas-135/CODEGLIA.git
cd CODEGLIA
pip install -r requirements.txt
flask run
```

### **Option 2 – Using Docker**
```bash
docker build -t codeglia .
docker run -p 5050:5050 --env-file .env codeglia
```

Then open your browser at:  
👉 [http://localhost:5050](http://localhost:5050)

---

## ⚙️ Environment Variables

Create a file named `.env` in the project root with the following content:
```
GEMINI_API_KEY=your_api_key_here
FLASK_APP=app.py
FLASK_RUN_HOST=0.0.0.0
```

---

## 📊 Output

After scanning, reports are generated in the `output/` folder:
- `scan_report.json` – Raw vulnerability data
- `scan_report.html` – Human-readable HTML report
- `performance.json` – Metrics on scan time & lines analyzed

---

## 🧱 Folder Structure

```
CodeGlia/
│
├── app.py                # Flask backend
├── run_scan.py           # Handles Semgrep + Bandit scanning
├── parse_results.py      # AI-driven report parsing
├── requirements.txt      # Dependencies
├── Dockerfile            # Docker configuration
│
├── static/               # CSS, JS, icons
├── templates/            # HTML templates (Flask views)
└── output/               # Generated reports
```

---

## 🌍 Deployment

CodeGlia can be deployed easily on:
- Render
- Railway
- Oracle Cloud (OCI)
- Azure App Service
- Amazon Web Services

Each instance supports `.env` for secure API key handling.

 
> — CodeGlia Team
