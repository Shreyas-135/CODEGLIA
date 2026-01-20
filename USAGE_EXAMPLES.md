# LLM Scanner Usage Examples

This document provides practical examples for using the LLM-based vulnerability scanner.

## Prerequisites

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Set Up API Keys

Create a `.env` file in the project root:

```env
# Required for AI analysis (existing feature)
GEMINI_API_KEY=your_gemini_api_key_here

# Optional: LLM Scanner Configuration
LLM_ENABLED=false                    # Set to 'true' to enable LLM scanning
LLM_BACKEND=gemini                   # Options: gemini, openai, ollama
LLM_MODEL=gemini-2.0-flash-exp       # Model name (optional, uses defaults)

# Optional: OpenAI Configuration (if using OpenAI backend)
# OPENAI_API_KEY=your_openai_key_here

# Optional: Ollama Configuration (for local models)
# OLLAMA_BASE_URL=http://localhost:11434
```

## Basic Usage

### 1. Default Scan (Bandit + Semgrep Only)
```bash
python run_scan.py datasets/
```

This runs the traditional static analysis tools without LLM scanning, maintaining backward compatibility.

### 2. Enable LLM Scanning
```bash
python run_scan.py datasets/ --enable-llm
```

Runs all scanners (Bandit, Semgrep, and LLM) and generates a comprehensive report.

### 3. Compare All Scanners
```bash
python run_scan.py datasets/ --compare
```

Runs all scanners and generates detailed performance comparison metrics.

## Advanced Usage

### 1. Static Analysis Only
```bash
python run_scan.py datasets/ --static-only
```

Forces only Bandit and Semgrep to run, even if LLM is enabled in `.env`.

### 2. LLM Scanner Only
```bash
python run_scan.py datasets/ --llm-only
```

Runs only the LLM scanner (useful for testing).

### 3. Custom LLM Backend

#### Using Google Gemini (Default)
```bash
python run_scan.py datasets/ --enable-llm --llm-backend gemini --llm-model gemini-2.0-flash-exp
```

#### Using OpenAI GPT-4
```bash
export OPENAI_API_KEY=your_openai_key
python run_scan.py datasets/ --enable-llm --llm-backend openai --llm-model gpt-4
```

#### Using Ollama (Local)
```bash
# Start Ollama server first
ollama pull codellama
python run_scan.py datasets/ --enable-llm --llm-backend ollama --llm-model codellama
```

## Understanding the Output

### Performance Metrics

When running with `--compare` or `--enable-llm`, you'll see performance metrics:

```
📊 Performance Comparison:
   Static Analysis Total: 10.8s
   LLM Analysis Total: 45.2s
   LLM is 4.2x slower (+34.4s)
   
   Throughput:
   - Bandit: 494 lines/sec
   - Semgrep: 149 lines/sec
   - LLM: 27 lines/sec
```

### Output Files

All reports are saved in the `output/` directory:

1. **scan_report.html** - Human-readable HTML report with:
   - Performance comparison charts
   - Scanner badges for each vulnerability
   - Visual time comparison bars
   - Detailed vulnerability explanations

2. **scan_report.json** - Machine-readable JSON report with:
   - All vulnerabilities from all scanners
   - Complete metadata
   - Trust score calculations

3. **performance.json** - Detailed performance metrics:
```json
{
  "total_lines_of_code": 1234,
  "scanners": {
    "bandit": {
      "time_seconds": 2.5,
      "vulnerabilities_found": 5,
      "lines_per_second": 493.6
    },
    "semgrep": {
      "time_seconds": 8.3,
      "vulnerabilities_found": 12,
      "lines_per_second": 148.7
    },
    "llm": {
      "time_seconds": 45.2,
      "vulnerabilities_found": 8,
      "lines_per_second": 27.3,
      "model": "gemini-2.0-flash-exp",
      "files_analyzed": 15
    }
  },
  "comparison": {
    "static_total_time": 10.8,
    "llm_total_time": 45.2,
    "llm_slower_by_factor": 4.19,
    "llm_slower_by_seconds": 34.4
  },
  "elapsed_scan_time_seconds": 56.0
}
```

## Best Practices

### 1. Model Selection

**For Speed:**
- Gemini 2.0 Flash (`gemini-2.0-flash-exp`) - Fast, cost-effective, good accuracy
- Ollama with CodeLlama 7B - Local, fast, no API costs

**For Accuracy:**
- GPT-4 (`gpt-4`) - Best accuracy, slower, higher cost
- Gemini Pro - Good balance of speed and accuracy

**For Offline/Privacy:**
- Ollama with Mistral - Run locally, no internet required
- Ollama with CodeLlama - Optimized for code analysis

### 2. When to Use LLM Scanner

**Use LLM Scanner When:**
- You need deeper context understanding
- Looking for business logic vulnerabilities
- Want AI-generated fix recommendations
- Analyzing complex security patterns

**Use Static Analysis When:**
- You need fast scans
- Working with CI/CD pipelines (time-sensitive)
- Looking for known vulnerability patterns
- Cost is a concern (API usage)

### 3. Hybrid Approach (Recommended)

For best results, use both:
```bash
python run_scan.py datasets/ --compare
```

This provides:
- Fast detection from static tools
- Deep analysis from LLM
- Comprehensive coverage
- Performance comparison data

## Troubleshooting

### LLM Scanner Not Working

1. **Check API Key:**
```bash
echo $GEMINI_API_KEY  # Should show your key
```

2. **Test LLM Module:**
```bash
python test_llm_scanner.py
```

3. **Check Dependencies:**
```bash
pip install google-generativeai>=0.3.0
```

### Performance Issues

1. **Large Codebases:**
   - LLM scanner chunks files >4000 lines
   - Consider using `--static-only` for CI/CD
   - Use LLM scanner on critical files only

2. **API Rate Limits:**
   - Implement delays between requests (built-in)
   - Use caching (enabled by default)
   - Consider local models (Ollama)

### Cache Issues

Clear cache if needed:
```bash
rm .llm_scan_cache.json
```

## Integration Examples

### CI/CD Pipeline (GitHub Actions)

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run static analysis
        run: python run_scan.py src/ --static-only
      
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: scan-reports
          path: output/
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

python run_scan.py src/ --static-only --quiet
if [ $? -ne 0 ]; then
    echo "Security scan failed! Fix issues before committing."
    exit 1
fi
```

## Support

For issues or questions:
- Check the [README.md](README.md) for general information
- Review [SECURITY_SUMMARY.md](SECURITY_SUMMARY.md) for security details
- Open an issue on GitHub with detailed error messages
