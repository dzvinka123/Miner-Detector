import subprocess
from urllib import response
from flask import Flask, jsonify, request, redirect, url_for, render_template_string
from datetime import datetime
import os
from dotenv import load_dotenv

from flask_cors import CORS

app = Flask(__name__)
CORS(app)

reports = []
load_dotenv()

HIGHLIGHT_WORDS = os.getenv("SUSPICIOUS_KEYWORDS", "")


@app.route("/report", methods=["POST"])
def report() -> str:
    """
    Receive and store a suspicious report with a timestamp.

    Args:
        None

    Returns:
        str: A confirmation message indicating the report was received.
    """
    content = request.get_data(as_text=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reports.append((timestamp, content))
    return "Report received", 200


@app.route("/")
def index() -> str:
    """
    Render the index page displaying suspicious reports.

    Args:
        None

    Returns:
        str: The rendered HTML string for the index page.
    """
    return render_template_string(
        """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Suspicious Reports</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body class="bg-light">
        <div class="container mt-4">
            <h1 class="mb-4">Suspicious Reports</h1>
            <form action="{{ url_for('clear') }}" method="post">
                <button type="submit" class="btn btn-danger mb-3">Clear all reports</button>
            </form>
            {% if reports %}
                {% for time, report in reports|reverse %}
                    <div class="card mb-3 shadow-sm">
                        <div class="card-header fw-bold text-primary">
                            Received: {{ time }}
                        </div>
                        <div class="card-body">
                            <pre style="white-space: pre-wrap;">{{ report | safe }}</pre>
                        </div>
                    </div>
                {% endfor %}
            {% else %}
                <div class="alert alert-secondary">No reports to present at this time</div>
            {% endif %}
        </div>
    </body>
    </html>
    """,
        reports=reports,
    )


@app.route("/clear", methods=["POST"])
def clear() -> str:
    """
    Clear all stored suspicious reports.

    Args:
        None

    Returns:
        str: A redirect to the index page after clearing the reports.
    """
    reports.clear()
    return redirect(url_for("index"))


@app.route("/extention/scan", methods=["POST", "OPTIONS"])
def scan():
    if request.method == "OPTIONS":
        response = jsonify({"message": "Preflight check OK"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        return response

    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"message": "URL not provided"}), 400

    result = subprocess.run(
        ["cli-scanner", "scan", "--_dev_mode", url],
        capture_output=True,
        text=True,
    )

    response = jsonify({
        "message": "Scan started",
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode
    })
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

if __name__ == "main":
    app.run(host="localhost", port=5555, debug=True)
