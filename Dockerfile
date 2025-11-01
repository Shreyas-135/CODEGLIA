FROM python:3.10-slim

WORKDIR /app

# Install multi-language dependencies for Semgrep rules
RUN apt-get update && apt-get install -y \
    gcc g++ openjdk-21-jre-headless php-cli nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install semgrep

# Copy all project files (including semgrep-rules)
COPY . .
COPY semgrep-rules /app/semgrep-rules

# Environment setup
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

EXPOSE 8080

# Default command to run the Flask app
CMD ["python", "app.py"]