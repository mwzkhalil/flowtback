"""
Upload routes for FlowTrack application.
Handles file uploads, processing, and bulk transaction imports.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import current_user
from src.models import db, Transaction
from routes.middleware import login_required, rate_limit, validate_csrf_token
from src.upload_handler import process_upload
from src.transaction_security import get_accessible_transactions
import secrets
import os
from werkzeug.utils import secure_filename
from datetime import datetime

upload_bp = Blueprint('upload', __name__)

def generate_upload_token():
    """Generate a secure random token for file uploads."""
    return secrets.token_urlsafe(32)

def save_temp_file(file, token):
    """Save uploaded file to temporary storage with token."""
    temp_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(temp_dir, f"{token}_{filename}")
    file.save(file_path)
    return file_path

def get_temp_file(token):
    """Retrieve temporary file by token."""
    temp_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'temp')
    for filename in os.listdir(temp_dir):
        if filename.startswith(f"{token}_"):
            return os.path.join(temp_dir, filename)
    return None

def cleanup_temp_file(token):
    """Clean up temporary file by token."""
    temp_dir = os.path.join(current_app.config['UPLOAD_FOLDER'], 'temp')
    for filename in os.listdir(temp_dir):
        if filename.startswith(f"{token}_"):
            try:
                os.remove(os.path.join(temp_dir, filename))
            except Exception:
                pass

@upload_bp.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """Upload page for bulk transaction imports."""
    if request.method == 'POST':
        try:
            # Check if file was uploaded
            if 'file' not in request.files:
                flash('No file selected', 'error')
                return render_template('upload.html')
            
            file = request.files['file']
            
            if file.filename == '':
                flash('No file selected', 'error')
                return render_template('upload.html')
            
            if file:
                # Generate upload token
                token = generate_upload_token()
                
                # Save file temporarily
                file_path = save_temp_file(file, token)
                
                # Process upload
                result = process_upload(file_path, current_user.id)
                
                # Clean up temporary file
                cleanup_temp_file(token)
                
                if result['success']:
                    flash(f'Successfully imported {result["imported_count"]} transactions', 'success')
                    if result['errors']:
                        flash(f'Some transactions had errors: {len(result["errors"])}', 'warning')
                else:
                    flash(f'Upload failed: {result["error"]}', 'error')
                
                return redirect(url_for('upload.upload'))
        
        except Exception as e:
            flash(f'Error processing upload: {str(e)}', 'error')
            return render_template('upload.html')
    
    return render_template('upload.html')

@upload_bp.route('/upload/preview', methods=['POST'])
@login_required
@rate_limit(max_requests=10, window_seconds=60)
def upload_preview():
    """Preview uploaded file before processing."""
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file:
            # Generate upload token
            token = generate_upload_token()
            
            # Save file temporarily
            file_path = save_temp_file(file, token)
            
            # Preview file content
            result = process_upload(file_path, current_user.id, preview_only=True)
            
            # Clean up temporary file
            cleanup_temp_file(token)
            
            if result['success']:
                return jsonify({
                    'success': True,
                    'preview_data': result.get('preview_data', []),
                    'total_rows': result.get('total_rows', 0),
                    'valid_rows': result.get('valid_rows', 0),
                    'errors': result.get('errors', [])
                })
            else:
                return jsonify({'error': result['error']}), 400
        
        return jsonify({'error': 'No file uploaded'}), 400
        
    except Exception as e:
        return jsonify({'error': f'Error previewing file: {str(e)}'}), 500

@upload_bp.route('/upload/suggestions', methods=['POST'])
@login_required
@rate_limit(max_requests=20, window_seconds=60)
def upload_suggestions():
    """Get suggestions for uploaded data."""
    try:
        data = request.get_json()
        
        if not data or 'preview_data' not in data:
            return jsonify({'error': 'Preview data is required'}), 400
        
        preview_data = data['preview_data']
        
        # Generate suggestions for categories, descriptions, etc.
        suggestions = {
            'categories': [],
            'descriptions': [],
            'mapping_suggestions': []
        }
        
        # Analyze preview data to generate suggestions
        if preview_data:
            # Extract unique values for suggestions
            categories = set()
            descriptions = set()
            
            for row in preview_data:
                if 'category' in row and row['category']:
                    categories.add(row['category'])
                if 'description' in row and row['description']:
                    descriptions.add(row['description'])
            
            suggestions['categories'] = list(categories)
            suggestions['descriptions'] = list(descriptions)
        
        return jsonify({
            'success': True,
            'suggestions': suggestions
        })
        
    except Exception as e:
        return jsonify({'error': f'Error generating suggestions: {str(e)}'}), 500

@upload_bp.route('/upload/process', methods=['POST'])
@login_required
@rate_limit(max_requests=5, window_seconds=60)
def upload_process():
    """Process uploaded file and import transactions."""
    try:
        data = request.get_json()
        
        if not data or 'file_token' not in data:
            return jsonify({'error': 'File token is required'}), 400
        
        file_token = data['file_token']
        mapping = data.get('mapping', {})
        options = data.get('options', {})
        
        # Get temporary file
        file_path = get_temp_file(file_token)
        
        if not file_path:
            return jsonify({'error': 'File not found or expired'}), 400
        
        # Process upload with mapping and options
        result = process_upload(file_path, current_user.id, mapping=mapping, options=options)
        
        # Clean up temporary file
        cleanup_temp_file(file_token)
        
        if result['success']:
            return jsonify({
                'success': True,
                'imported_count': result['imported_count'],
                'errors': result.get('errors', []),
                'message': f'Successfully imported {result["imported_count"]} transactions'
            })
        else:
            return jsonify({'error': result['error']}), 400
        
    except Exception as e:
        return jsonify({'error': f'Error processing upload: {str(e)}'}), 500

@upload_bp.route('/save_transactions', methods=['POST'])
@login_required
@validate_csrf_token
def save_transactions():
    """Save transactions from upload preview."""
    try:
        data = request.get_json()
        
        if not data or 'transactions' not in data:
            return jsonify({'error': 'Transaction data is required'}), 400
        
        transactions_data = data['transactions']
        imported_count = 0
        errors = []
        
        for transaction_data in transactions_data:
            try:
                # Create transaction
                transaction = Transaction(
                    description=transaction_data.get('description', ''),
                    amount=float(transaction_data.get('amount', 0)),
                    category=transaction_data.get('category'),
                    date=datetime.strptime(transaction_data.get('date'), '%Y-%m-%d').date(),
                    user_id=current_user.id
                )
                
                db.session.add(transaction)
                imported_count += 1
                
            except Exception as e:
                errors.append(f"Row {transaction_data.get('row_number', 'unknown')}: {str(e)}")
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'imported_count': imported_count,
            'errors': errors,
            'message': f'Successfully imported {imported_count} transactions'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Error saving transactions: {str(e)}'}), 500
