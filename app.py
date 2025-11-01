from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, abort
from werkzeug.utils import safe_join
import os
import subprocess
import datetime
import zipfile
import shutil

app = Flask(__name__)
app.secret_key = "glia-secret"  # needed for flash messages

UPLOAD_FOLDER = "datasets"
OUTPUT_FOLDER = "output"
SCANS_FOLDER = "scans"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("No file part in request")
        return redirect(url_for("index"))

    file = request.files["file"]
    if file.filename == "":
        flash("No selected file")
        return redirect(url_for("index"))

    if file and file.filename.endswith(".zip"):
        # Cleanup previous datasets, scans, and output
        for folder in [UPLOAD_FOLDER, SCANS_FOLDER, OUTPUT_FOLDER]:
            if os.path.exists(folder):
                shutil.rmtree(folder)
            os.makedirs(folder, exist_ok=True)

        upload_path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(upload_path)

        # Create a subfolder for extracted content
        extract_path = os.path.join(UPLOAD_FOLDER, "uploaded_project")
        if os.path.exists(extract_path):
            shutil.rmtree(extract_path)
        os.makedirs(extract_path, exist_ok=True)

        # Extract ZIP
        with zipfile.ZipFile(upload_path, "r") as zip_ref:
            zip_ref.extractall(extract_path)

        # Remove uploaded zip after extraction
        os.remove(upload_path)

        # Trigger scan via run_scan.py on extracted project
        cmd = ["python3", "run_scan.py"]
        subprocess.Popen(cmd)
        flash("⏳ Scan started. It may take a few minutes...")
        return redirect(url_for("progress"))
    else:
        flash("❌ Please upload a ZIP file containing your project.")
        return redirect(url_for("index"))

@app.route("/progress")
def progress():
    report_path = os.path.join(OUTPUT_FOLDER, "scan_report.html")
    if os.path.exists(report_path):
        flash("✅ Scan completed successfully!")
        return redirect(url_for("results"))
    return render_template("progress.html", timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route("/results")
def results():
    report_path = os.path.join(OUTPUT_FOLDER, "scan_report.html")
    perf_path = os.path.join(OUTPUT_FOLDER, "performance.json")

    report_exists = os.path.exists(report_path)
    perf_exists = os.path.exists(perf_path)
    return render_template("results.html",
                           report_exists=report_exists,
                           perf_exists=perf_exists,
                           timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route("/view-report")
def view_report():
    return send_from_directory(OUTPUT_FOLDER, "scan_report.html")

@app.route("/download/<filename>")
def download_file(filename):
    allowed_files = ["scan_report.html", "scan_report.json"]
    if filename not in allowed_files:
        abort(404, description="File not found.")
    try:
        safe_path = safe_join(OUTPUT_FOLDER, filename)
    except:
        abort(404, description="Invalid file path.")
    if not os.path.exists(safe_path):
        abort(404, description="File not found.")
    return send_from_directory(OUTPUT_FOLDER, filename, as_attachment=True)

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5050))  # default to 5050 if not set
    app.run(host="0.0.0.0", port=port)