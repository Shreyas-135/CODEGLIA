# 🚀 CodeGlia – Intelligent Vulnerability Scanner

CodeGlia is an **AI-augmented static analysis tool** that integrates **Semgrep**, **Bandit**, and **LLM-based scanning** (Google Gemini, OpenAI GPT-4, or Ollama) to detect and explain vulnerabilities across multiple programming languages.

---

## 🧠 Overview

CodeGlia provides **real-time vulnerability scanning** through an interactive Flask-based dashboard.  
It allows developers to upload entire projects (ZIP or folder), scans the source code for potential security issues, and generates **AI-enriched reports** with performance comparison metrics.

---

## 🧩 Features

- 🔍 Multi-language static analysis (Python, Java, C, C#, PHP, JavaScript)
- 🤖 AI-powered vulnerability explanation and severity labeling
- 🚨 **NEW: LLM-based vulnerability detection** with multiple backend support
- 📊 **Performance comparison** between static and LLM analysis
- 📈 Trust Score computation and visual trend tracking
- 🌐 Flask-based web dashboard with live scan progress
- 🧱 Dockerized for fast deployment and consistency
- ⚙️ Supports local Semgrep rule packs for offline scanning

---

## 🤖 LLM Scanner Features

### Supported Backends
- **Google Gemini** (default) - Fast and efficient with gemini-2.0-flash-exp
- **OpenAI GPT-4** - High-quality analysis (requires API key)
- **Ollama** - Local models (CodeLlama, Mistral) for offline scanning

### Capabilities
- Scans multiple file types: `.py`, `.js`, `.java`, `.php`, `.c`, `.cpp`, `.rb`, etc.
- Detects: SQL injection, command injection, XSS, path traversal, hardcoded secrets, weak crypto, and more
- Maps findings to CWE/CVE using existing infrastructure
- Implements caching to avoid re-analyzing identical code
- Provides detailed explanations and secure fix recommendations

### Performance Metrics
The scanner tracks and compares:
- Individual timing for each scanner (Bandit, Semgrep, LLM)
- Throughput metrics (lines/second)
- Total static vs LLM analysis time
- Time difference and speedup/slowdown factors

---

## 🖥️ Tech Stack

| Layer | Technology |
|-------|-------------|
| **Frontend** | HTML, CSS (custom dark theme), JS |
| **Backend** | Python (Flask) |
| **AI Integration** | Google Gemini API, OpenAI (optional), Ollama (optional) |
| **Security Analysis** | Semgrep, Bandit, LLM Scanner |
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
# Flask configuration
FLASK_APP=app.py
FLASK_RUN_HOST=0.0.0.0

# AI Configuration
GEMINI_API_KEY=your_api_key_here

# LLM Scanner Configuration (optional)
LLM_ENABLED=false                    # Set to true to enable LLM scanning
LLM_BACKEND=gemini                   # Options: gemini, openai, ollama
LLM_MODEL=gemini-2.0-flash-exp       # Model name (optional, uses defaults)

# Optional: OpenAI Configuration
# OPENAI_API_KEY=your_openai_key_here

# Optional: Ollama Configuration (for local models)
# OLLAMA_BASE_URL=http://localhost:11434
```

---

## 🚀 CLI Usage

### Basic Scan (Static Analysis Only - Default)
```bash
python run_scan.py datasets/
```

### Enable LLM Scanning
```bash
python run_scan.py datasets/ --enable-llm
```

### Run with Specific LLM Backend
```bash
python run_scan.py datasets/ --enable-llm --llm-backend gemini --llm-model gemini-2.0-flash-exp
```

### Compare All Scanners
```bash
python run_scan.py datasets/ --compare
```

### Static Analysis Only (Bandit + Semgrep)
```bash
python run_scan.py datasets/ --static-only
```

### LLM Scanner Only (for testing)
```bash
python run_scan.py datasets/ --llm-only --llm-backend gemini
```

### CLI Options
- `--enable-llm` - Enable LLM scanning
- `--llm-backend [gemini|openai|ollama]` - Choose LLM backend
- `--llm-model <model-name>` - Specify model
- `--static-only` - Run only static analyzers (default for backward compatibility)
- `--llm-only` - Run only LLM scanner (for testing)
- `--compare` - Run all scanners and generate comparison report

---

## 📊 Output

After scanning, reports are generated in the `output/` folder:
- `scan_report.json` – Raw vulnerability data
- `scan_report.html` – Human-readable HTML report with performance comparison
- `performance.json` – Detailed metrics on scan time, throughput, and comparisons

### Example Performance Output
```
===== Starting CodeGlia Workflow =====
📁 Using target dataset directory: datasets
🤖 LLM scanning enabled (backend: gemini, model: gemini-2.0-flash-exp)

🚀 Running Bandit Scan (Python)...
✅ Bandit completed in 2.5s (5 vulnerabilities found)

🚀 Running Semgrep Scan (Multi-language)...
✅ Semgrep completed in 8.3s (12 vulnerabilities found)

🚀 Running LLM Scan (gemini/gemini-2.0-flash-exp)...
📊 Processing files in datasets...
✅ LLM completed in 45.2s (8 vulnerabilities found)

📊 Performance Comparison:
   Static Analysis Total: 10.8s
   LLM Analysis Total: 45.2s
   LLM is 4.2x slower (+34.4s)
   
   Throughput:
   - Bandit: 494 lines/sec
   - Semgrep: 149 lines/sec
   - LLM: 27 lines/sec

✅ Total scan time: 56.0s
```

---

## 🧱 Folder Structure

```
CodeGlia/
│
├── app.py                # Flask backend
├── run_scan.py           # Handles Semgrep + Bandit + LLM scanning
├── parse_results.py      # AI-driven report parsing
├── llm_scanner.py        # LLM-based vulnerability scanner module
├── requirements.txt      # Dependencies
├── Dockerfile            # Docker configuration
│
├── static/               # CSS, JS, icons
├── templates/            # HTML templates (Flask views)
└── output/               # Generated reports
```

---

## 🌟 LLM Model Selection Best Practices

### For Speed
- **Gemini 2.0 Flash** - Fast, cost-effective, good accuracy
- **Ollama with CodeLlama 7B** - Local, fast, no API costs

### For Accuracy
- **GPT-4** - Best accuracy, slower, higher cost
- **Gemini Pro** - Good balance of speed and accuracy

### For Offline/Privacy
- **Ollama with Mistral** - Run locally, no internet required
- **Ollama with CodeLlama** - Optimized for code analysis

---

## 🔒 Security Considerations

- LLM scanner is **disabled by default** to maintain backward compatibility
- API keys are never logged or stored in scan results
- Cache files use content hashes, not source code
- All scanners can run independently if one fails

---

## 🌍 Deployment

CodeGlia can be deployed easily on:
- Render
- Railway
- Oracle Cloud (OCI)
- Azure App Service
- Amazon Web Services

Each instance supports `.env` for secure API key handling.