from flask import Flask, render_template, jsonify
import json
import os

app = Flask(__name__)

# File to store/read alerts
ALERTS_FILE = "alerts.json"

def get_alerts():
    alerts = []
    if os.path.exists(ALERTS_FILE):
        try:
            with open(ALERTS_FILE, "r") as f:
                for line in f:
                    if line.strip():
                        alerts.append(json.loads(line))
        except Exception as e:
            print(f"Error reading file: {e}")
    return alerts

@app.route('/')
def index():
    alerts = get_alerts()
    # Limit to last 50 alerts
    return render_template('index.html', alerts=alerts[-50:])

@app.route('/api/alerts')
def api_alerts():
    alerts = get_alerts()
    return jsonify(alerts[-50:])

if __name__ == '__main__':
    app.run(debug=True, port=5000)
