from flask import Flask, render_template, request, jsonify
from scanner import XSSScanner

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    target_url = data.get('url', '').strip()

    if not target_url:
        return jsonify({'error': 'URL is required'}), 400

    if not target_url.startswith('http://') and not target_url.startswith('https://'):
        target_url = 'http://' + target_url

    scanner = XSSScanner(target_url)
    results = scanner.scan()

    return jsonify({'results': results})