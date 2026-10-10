import asyncio
import json
import threading
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, render_template, request
from flask_socketio import SocketIO

from database import get_history, save_scan
from payloads import parse_wordlist_text
from scanner import VulnerabilityScanner

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sec-audit-pro-secret'

socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')


def run_scan_thread(url: str, auth_type: str, auth_value: str,
                    payload_mode: str, custom_wordlist) -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        scanner = VulnerabilityScanner(
            url, socketio,
            auth_type=auth_type, auth_value=auth_value,
            payload_mode=payload_mode, custom_wordlist=custom_wordlist,
        )
        scan_data = loop.run_until_complete(scanner.run_scan())

        vuln_count = len([r for r in scan_data['results'] if r['type'] == 'vulnerability'])
        save_scan(url, scan_data['duration'], vuln_count, scan_data['tech_stack'], scan_data['results'])

        socketio.emit('scan_complete', scan_data)
    except Exception as exc:
        socketio.emit('scan_log', {'msg': f"Critical engine error: {exc}", 'level': 'error'})
        socketio.emit('scan_complete', {
            'results': [{'type': 'error', 'title': 'Engine Error', 'description': str(exc),
                         'category': 'network', 'cvss': 'N/A', 'severity': 'High',
                         'remediation': 'Restart the scanner engine.', 'references': []}],
            'tech_stack': [], 'duration': 0,
        })
    finally:
        loop.close()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/history')
def history():
    return jsonify(get_history())


@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    auth_type = data.get('auth_type', 'none')
    auth_value = data.get('auth_value', '')
    payload_mode = data.get('payload_mode', 'standard')
    raw_wordlist = data.get('custom_wordlist')

    wordlist = parse_wordlist_text(raw_wordlist) if isinstance(raw_wordlist, str) and raw_wordlist.strip() else None

    if not url:
        return jsonify({'error': 'URL is required'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    threading.Thread(
        target=run_scan_thread,
        args=(url, auth_type, auth_value, payload_mode, wordlist),
        daemon=True,
    ).start()
    return jsonify({'status': 'started'})


@app.route('/api/export/json', methods=['POST'])
def export_json():
    data = request.get_json(silent=True) or {}
    report = {
        'tool': 'SecAudit Pro',
        'version': '1.5.0',
        'author': 'mucahidbalci',
        'target': data.get('target_url'),
        'generated_at': datetime.now(timezone.utc).isoformat(),
        'findings': data.get('results', []),
    }
    return Response(
        json.dumps(report, indent=4),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment;filename=secaudit_report.json'},
    )


@socketio.on('connect')
def handle_connect():
    socketio.emit('scan_log', {'msg': 'WebSocket channel established.', 'level': 'success'})


if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=5000, debug=False)