#!/usr/bin/env python3
"""
Pentester Analysis Tool - Main Application

A comprehensive tool for security professionals that analyzes scan outputs,
categorizes vulnerabilities, and provides exploitation guidance.
"""
import os
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
import json
import logging
from dotenv import load_dotenv
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import unified analyzer module
from analyzer import PentesterAnalyzer

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("pentester_tool.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24).hex())
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Initialize analyzer
analyzer = PentesterAnalyzer()

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'txt', 'log', 'xml', 'json', 'csv', 'nmap', 'gnmap', 'xml'}

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Render the main application page"""
    # Force browser to use the new CSS by adding a version parameter
    version = int(datetime.now().timestamp())
    return render_template('index.html', version=version)

@app.route('/analyze', methods=['POST'])
def analyze():
    """Handle scan data analysis requests"""
    try:
        # Check if the post request has the file part
        scan_data = ""
        session_id = str(uuid.uuid4())
        result_file = os.path.join(app.config['UPLOAD_FOLDER'], f"{session_id}_results.json")
        
        if 'scan_files' in request.files:
            files = request.files.getlist('scan_files')
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)
                    with open(file_path, 'r') as f:
                        scan_data += f.read() + "\n\n"
            
        # Check if there's direct input
        if 'scan_input' in request.form and request.form['scan_input'].strip():
            scan_data += request.form['scan_input'].strip()
            
        if not scan_data:
            flash('No valid input provided. Please upload a file or paste scan output.')
            return redirect(url_for('index'))
            
        # Get scan title if provided
        scan_title = request.form.get('scan_title', 'Untitled Scan')
        
        # Get analysis options
        deep_analysis = request.form.get('deep_analysis') == 'on'
        analysis_type = request.form.get('analysis_type', 'general')
        
        # Get selected content types
        content_types = request.form.getlist('content_types[]')
        
        # Process the data with unified analyzer
        logger.info(f"Starting analysis with type: {analysis_type}, deep analysis: {deep_analysis}, content types: {content_types}")
        analysis_results = analyzer.analyze(
            scan_data=scan_data, 
            analysis_type=analysis_type,
            deep_analysis=deep_analysis,
            content_types=content_types,
            enrich_cve=True
        )
        
        # Add metadata
        analysis_results['metadata'] = {
            'scan_title': scan_title,
            'timestamp': datetime.now().isoformat(),
            'session_id': session_id,
            'analysis_type': analysis_type,
            'deep_analysis': deep_analysis,
            'content_types': content_types
        }
        
        # Save results
        with open(result_file, 'w') as f:
            json.dump(analysis_results, f, indent=2)
            
        # Store session ID for retrieval
        session['last_analysis'] = session_id
        
        return redirect(url_for('results', session_id=session_id))
    
    except Exception as e:
        logger.error(f"Error in analyze route: {str(e)}")
        flash(f"An error occurred during analysis: {str(e)}")
        return redirect(url_for('index'))

@app.route('/results/<session_id>')
def results(session_id):
    """Display analysis results"""
    try:
        result_file = os.path.join(app.config['UPLOAD_FOLDER'], f"{session_id}_results.json")
        
        if not os.path.exists(result_file):
            flash('Analysis results not found.')
            return redirect(url_for('index'))
            
        with open(result_file, 'r') as f:
            analysis_results = json.load(f)
        
        # Debug the AI analysis content when loading results
        if 'ai_analysis' in analysis_results:
            logger.info(f"Results page - AI analysis type: {type(analysis_results['ai_analysis'])}")
            logger.info(f"Results page - AI analysis content preview: {str(analysis_results['ai_analysis'])[:100]}...")
            with open('/tmp/results_page_ai_analysis.txt', 'w') as f:
                f.write(str(analysis_results['ai_analysis']))
        
        # Force browser to use the new CSS by adding a version parameter
        version = int(datetime.now().timestamp())
        return render_template('results.html', results=analysis_results, version=version)
    
    except Exception as e:
        logger.error(f"Error in results route: {str(e)}")
        flash(f"An error occurred while loading results: {str(e)}")
        return redirect(url_for('index'))

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for scan analysis"""
    try:
        data = request.json
        if not data or 'scan_data' not in data:
            return jsonify({"error": "No scan data provided"}), 400
            
        analysis_type = data.get('analysis_type', 'general')
        deep_analysis = data.get('deep_analysis', False)
        content_types = data.get('content_types', None)
        
        analysis_results = analyzer.analyze(
            scan_data=data['scan_data'],
            analysis_type=analysis_type,
            deep_analysis=deep_analysis,
            content_types=content_types
        )
        return jsonify(analysis_results)
    
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/lookup/cve/<cve_id>', methods=['GET'])
def api_lookup_cve(cve_id):
    """API endpoint for CVE lookup"""
    try:
        cve_data = analyzer.lookup_cve(cve_id)
        return jsonify(cve_data)
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/check_api_key')
def check_api_key():
    """Check if API key is set"""
    has_key = bool(os.getenv('OPENAI_API_KEY'))
    return jsonify({"has_key": has_key})

@app.route('/update_api_key', methods=['POST'])
def update_api_key():
    """Update API key in .env file"""
    try:
        data = request.json
        if not data or 'api_key' not in data:
            return jsonify({"error": "No API key provided"}), 400
            
        api_key = data['api_key']
        
        # Read current .env file content
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
        
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                lines = f.readlines()
                
            # Update or add OPENAI_API_KEY
            key_exists = False
            for i, line in enumerate(lines):
                if line.startswith('OPENAI_API_KEY='):
                    lines[i] = f'OPENAI_API_KEY={api_key}\n'
                    key_exists = True
                    break
                    
            if not key_exists:
                lines.append(f'OPENAI_API_KEY={api_key}\n')
                
            # Write updated content back to .env file
            with open(env_path, 'w') as f:
                f.writelines(lines)
        else:
            # Create new .env file if it doesn't exist
            with open(env_path, 'w') as f:
                f.write(f'OPENAI_API_KEY={api_key}\n')
                
        # Update environment variable in current process
        os.environ['OPENAI_API_KEY'] = api_key
        
        # Re-initialize analyzer with new API key
        analyzer._init_openai_client()
        
        # Log success for debugging
        logger.info(f"API key updated successfully - length: {len(api_key)}")
        
        return jsonify({"success": True, "message": "API key updated successfully"})
    
    except Exception as e:
        logger.error(f"Error updating API key: {str(e)}")
        return jsonify({"error": str(e), "success": False}), 500

@app.route('/history')
def history():
    """Show analysis history"""
    try:
        history_data = []
        uploads_dir = app.config['UPLOAD_FOLDER']
        
        for filename in os.listdir(uploads_dir):
            if filename.endswith('_results.json'):
                file_path = os.path.join(uploads_dir, filename)
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        session_id = filename.split('_results.json')[0]
                        history_data.append({
                            'session_id': session_id,
                            'title': data.get('metadata', {}).get('scan_title', 'Untitled'),
                            'timestamp': data.get('metadata', {}).get('timestamp', 'Unknown'),
                            'analysis_type': data.get('metadata', {}).get('analysis_type', 'general')
                        })
                except:
                    continue
        
        # Sort by timestamp, newest first
        history_data.sort(key=lambda x: x['timestamp'], reverse=True)
        return render_template('history.html', history=history_data)
    
    except Exception as e:
        logger.error(f"Error in history route: {str(e)}")
        flash(f"An error occurred while loading history: {str(e)}")
        return redirect(url_for('index'))

@app.route('/delete_history/<session_id>', methods=['POST'])
def delete_history(session_id):
    """Delete a specific history item"""
    try:
        result_file = os.path.join(app.config['UPLOAD_FOLDER'], f"{session_id}_results.json")
        
        if os.path.exists(result_file):
            os.remove(result_file)
            return jsonify({"success": True})
        else:
            return jsonify({"error": "File not found"}), 404
    except Exception as e:
        logger.error(f"Error deleting history: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/clear_history', methods=['POST'])
def clear_history():
    """Clear all history items"""
    try:
        uploads_dir = app.config['UPLOAD_FOLDER']
        
        count = 0
        for filename in os.listdir(uploads_dir):
            if filename.endswith('_results.json'):
                file_path = os.path.join(uploads_dir, filename)
                os.remove(file_path)
                count += 1
        
        return jsonify({"success": True, "count": count})
    except Exception as e:
        logger.error(f"Error clearing history: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Run the Pentester Analysis Tool')
    parser.add_argument('--port', type=int, default=5000, help='Port to run the application on')
    args = parser.parse_args()

    app.run(host='0.0.0.0', port=args.port, debug=True)