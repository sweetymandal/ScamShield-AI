from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from models.scam_model import ScamModel
import database.db_manager as db_manager

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# Initialize AI/ML model engine & SQLite Database
scam_model = ScamModel()
db_manager.init_db()

@app.route('/')
def index():
    """Page 1: Landing Page"""
    return render_template('index.html')

@app.route('/analyzer')
def analyzer():
    """Page 2 & Page 3: Scan Analyzer & Result UI"""
    return render_template('analyzer.html')

@app.route('/dashboard')
def dashboard():
    """Page 4: Analytics Dashboard"""
    return render_template('dashboard.html')

@app.route('/guide')
def guide():
    """Page 5: Educational Safety Guide"""
    return render_template('guide.html')

# REST API Endpoints
@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    data = request.get_json() or {}
    scan_type = data.get('type', 'message')
    content = data.get('content', '').strip()

    if not content:
        return jsonify({
            'status': 'error',
            'message': 'Please provide text or a URL to analyze.'
        }), 400

    # Run AI/ML & Explainable Risk Engine
    analysis_res = scam_model.analyze(scan_type, content)

    # Save to SQLite Database
    saved_scan = db_manager.save_scan(
        scan_type=scan_type,
        input_content=content,
        risk_score=analysis_res['risk_score'],
        risk_level=analysis_res['risk_level'],
        summary=analysis_res['summary'],
        explanations=analysis_res['explanations'],
        evidence_tags=analysis_res['evidence_tags'],
        recommendations=analysis_res['recommendations']
    )

    return jsonify({
        'status': 'success',
        'data': saved_scan
    })

@app.route('/api/history', methods=['GET'])
def api_get_history():
    scans = db_manager.get_all_scans(limit=100)
    return jsonify({
        'status': 'success',
        'data': scans
    })

@app.route('/api/stats', methods=['GET'])
def api_get_stats():
    stats = db_manager.get_dashboard_stats()
    return jsonify({
        'status': 'success',
        'data': stats
    })

@app.route('/api/history/<int:scan_id>', methods=['DELETE'])
def api_delete_history(scan_id):
    success = db_manager.delete_scan(scan_id)
    if success:
        return jsonify({'status': 'success', 'message': f'Scan #{scan_id} deleted.'})
    return jsonify({'status': 'error', 'message': f'Scan #{scan_id} not found.'}), 404

if __name__ == '__main__':
    print("Starting ScamShield AI Engine Server on http://127.0.0.1:5000 ...")
    app.run(debug=True, port=5000)
