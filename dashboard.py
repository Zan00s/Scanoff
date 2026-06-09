from flask import Flask, render_template_string
import sqlite3

app = Flask(__name__)

DB_PATH = "workspace/scan.db"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><title>Recon Dashboard</title></head>
<body>
<h1>Recon-Workbench Dashboard</h1>
<h2>Hosts</h2>
<table border="1">
<tr><th>IP</th><th>Port</th><th>Service</th><th>Version</th><th>First Seen</th><th>Last Seen</th></tr>
{% for row in hosts %}
<tr><td>{{ row[0] }}</td><td>{{ row[1] }}</td><td>{{ row[2] }}</td><td>{{ row[3] }}</td><td>{{ row[4] }}</td><td>{{ row[5] }}</td></tr>
{% endfor %}
</table>
<h2>Technologies</h2>
<table border="1">
<tr><th>IP</th><th>Port</th><th>Technology</th><th>Version</th></tr>
{% for row in techs %}
<tr><td>{{ row[0] }}</td><td>{{ row[1] }}</td><td>{{ row[2] }}</td><td>{{ row[3] }}</td></tr>
{% endfor %}
</table>
<h2>Endpoints (latest 50)</h2>
<ul>
{% for row in endpoints %}
<li>{{ row[2] }}</li>
{% endfor %}
</ul>
</body>
</html>
"""

@app.route("/")
def index():
    conn = sqlite3.connect(DB_PATH)
    hosts = conn.execute("SELECT ip,port,service,version,first_seen,last_seen FROM hosts ORDER BY last_seen DESC").fetchall()
    techs = conn.execute("SELECT ip,port,technology,version FROM technologies ORDER BY last_seen DESC").fetchall()
    endpoints = conn.execute("SELECT ip,port,url FROM endpoints ORDER BY last_seen DESC LIMIT 50").fetchall()
    conn.close()
    return render_template_string(HTML_TEMPLATE, hosts=hosts, techs=techs, endpoints=endpoints)

def run_dashboard(host="127.0.0.1", port=5000):
    app.run(host=host, port=port, debug=False)
