import sqlite3
import json
import os

DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = '/tmp/database.db'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR, exist_ok=True)
        
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            input_content TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            summary TEXT NOT NULL,
            explanations TEXT NOT NULL,
            evidence_tags TEXT NOT NULL,
            recommendations TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

def save_scan(scan_type, input_content, risk_score, risk_level, summary, explanations, evidence_tags, recommendations):
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    
    explanations_json = json.dumps(explanations)
    evidence_tags_json = json.dumps(evidence_tags)
    recommendations_json = json.dumps(recommendations)
    
    cursor.execute('''
        INSERT INTO scans (scan_type, input_content, risk_score, risk_level, summary, explanations, evidence_tags, recommendations)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (scan_type, input_content, risk_score, risk_level, summary, explanations_json, evidence_tags_json, recommendations_json))
    
    scan_id = cursor.lastrowid
    conn.commit()
    
    cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    return format_scan_row(row)

def get_all_scans(limit=100):
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scans ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [format_scan_row(row) for row in rows]

def get_dashboard_stats():
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as total FROM scans")
    total = cursor.fetchone()['total']
    
    cursor.execute("SELECT COUNT(*) as high_risk FROM scans WHERE risk_level = 'HIGH RISK'")
    high_risk = cursor.fetchone()['high_risk']

    cursor.execute("SELECT COUNT(*) as suspicious FROM scans WHERE risk_level = 'SUSPICIOUS'")
    suspicious = cursor.fetchone()['suspicious']
    
    cursor.execute("SELECT COUNT(*) as safe_scans FROM scans WHERE risk_level = 'SAFE'")
    safe_scans = cursor.fetchone()['safe_scans']

    conn.close()
    
    return {
        'total_scans': total,
        'high_risk_scans': high_risk,
        'suspicious_scans': suspicious,
        'safe_scans': safe_scans
    }

def delete_scan(scan_id):
    init_db()
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    return affected > 0

def format_scan_row(row):
    if not row:
        return None
    try:
        explanations = json.loads(row['explanations'])
    except Exception:
        explanations = []

    try:
        evidence_tags = json.loads(row['evidence_tags'])
    except Exception:
        evidence_tags = []
        
    try:
        recommendations = json.loads(row['recommendations'])
    except Exception:
        recommendations = []

    return {
        'id': row['id'],
        'scan_type': row['scan_type'],
        'input_content': row['input_content'],
        'risk_score': row['risk_score'],
        'risk_level': row['risk_level'],
        'summary': row['summary'] if 'summary' in row.keys() else '',
        'explanations': explanations,
        'evidence_tags': evidence_tags,
        'recommendations': recommendations,
        'created_at': row['created_at']
    }

if __name__ == '__main__':
    init_db()
    print("Database db_manager initialization complete.")
