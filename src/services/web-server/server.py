from flask import Flask, request, redirect, url_for, render_template_string
from datetime import datetime
import os
from dotenv import load_dotenv

app = Flask(__name__)
reports = []
load_dotenv()

HIGHLIGHT_WORDS = os.getenv("SUSPICIOUS_KEYWORDS", "")


@app.route("/report", methods=["POST"])
def report():
    content = request.get_data(as_text=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    reports.append((timestamp, content))
    return "Report received", 200


@app.route("/")
def index():
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
def clear():
    reports.clear()
    return redirect(url_for("index"))


if __name__ == "main":
    app.run(host="localhost", port=5555, debug=True)
