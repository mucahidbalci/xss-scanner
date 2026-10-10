import json
import sqlite3
from datetime import datetime

DB_NAME = 'secaudit_history.db'


def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                duration REAL,
                total_vulns INTEGER,
                tech_stack TEXT,
                results_json TEXT
            )
        ''')


def save_scan(target_url, duration, total_vulns, tech_stack, results):
    init_db()
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute('''
            INSERT INTO scans (target_url, scan_date, duration, total_vulns, tech_stack, results_json)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (target_url, datetime.now().isoformat(), duration, total_vulns,
              json.dumps(tech_stack), json.dumps(results)))


def get_history():
    init_db()
    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            'SELECT target_url, scan_date, duration, total_vulns, tech_stack '
            'FROM scans ORDER BY id DESC LIMIT 20'
        )
        return [dict(row) for row in cursor]