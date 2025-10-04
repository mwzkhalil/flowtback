"""
Bank routes for FlowTrack application.
Handles bank connections, imports, and synchronization.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user
from src.models import db, BankConnection, Transaction
from routes.middleware import login_required, admin_required, validate_csrf_token, rate_limit
from src.bank_service import BankService
import logging

bank_bp = Blueprint('bank', __name__, url_prefix='/bank')

@bank_bp.route('/connections', methods=['GET'])
@login_required
def connections():
    """List user's bank connections."""
    try:
        connections = BankConnection.query.filter_by(user_id=current_user.id).all()
        
        return render_template('bank_connections.html', connections=connections)
        
    except Exception as e:
        flash(f'Error loading bank connections: {str(e)}', 'error')
        return redirect(url_for('dashboard.home'))

@bank_bp.route('/import', methods=['POST'])
@login_required
@rate_limit(max_requests=10, window_seconds=60)
def import_all():
    """Import transactions from all connected banks."""
    try:
        bank_service = BankService()
        
        # Get user's bank connections
        connections = BankConnection.query.filter_by(user_id=current_user.id).all()
        
        if not connections:
            return jsonify({'error': 'No bank connections found'}), 400
        
        total_imported = 0
        errors = []
        
        for connection in connections:
            try:
                result = bank_service.import_transactions(connection.id)
                if result['success']:
                    total_imported += result['imported_count']
                else:
                    errors.append(f"Connection {connection.name}: {result['error']}")
            except Exception as e:
                errors.append(f"Connection {connection.name}: {str(e)}")
        
        return jsonify({
            'success': True,
            'total_imported': total_imported,
            'errors': errors,
            'message': f'Successfully imported {total_imported} transactions'
        })
        
    except Exception as e:
        return jsonify({'error': f'Error importing transactions: {str(e)}'}), 500

@bank_bp.route('/import/<int:connection_id>', methods=['POST'])
@login_required
@rate_limit(max_requests=20, window_seconds=60)
def import_connection(connection_id):
    """Import transactions from a specific bank connection."""
    try:
        # Verify connection belongs to user
        connection = BankConnection.query.filter_by(
            id=connection_id, 
            user_id=current_user.id
        ).first()
        
        if not connection:
            return jsonify({'error': 'Bank connection not found'}), 404
        
        bank_service = BankService()
        result = bank_service.import_transactions(connection_id)
        
        if result['success']:
            return jsonify({
                'success': True,
                'imported_count': result['imported_count'],
                'message': f'Successfully imported {result["imported_count"]} transactions'
            })
        else:
            return jsonify({'error': result['error']}), 400
        
    except Exception as e:
        return jsonify({'error': f'Error importing transactions: {str(e)}'}), 500

@bank_bp.route('/sync-status/<int:connection_id>', methods=['GET'])
@login_required
def sync_status(connection_id):
    """Get sync status for a bank connection."""
    try:
        # Verify connection belongs to user
        connection = BankConnection.query.filter_by(
            id=connection_id, 
            user_id=current_user.id
        ).first()
        
        if not connection:
            return jsonify({'error': 'Bank connection not found'}), 404
        
        bank_service = BankService()
        status = bank_service.get_sync_status(connection_id)
        
        return jsonify({
            'success': True,
            'status': status
        })
        
    except Exception as e:
        return jsonify({'error': f'Error getting sync status: {str(e)}'}), 500

@bank_bp.route('/disconnect/<int:connection_id>', methods=['POST'])
@login_required
@validate_csrf_token
def disconnect(connection_id):
    """Disconnect a bank connection."""
    try:
        # Verify connection belongs to user
        connection = BankConnection.query.filter_by(
            id=connection_id, 
            user_id=current_user.id
        ).first()
        
        if not connection:
            return jsonify({'error': 'Bank connection not found'}), 404
        
        bank_service = BankService()
        result = bank_service.disconnect(connection_id)
        
        if result['success']:
            # Delete connection from database
            db.session.delete(connection)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Bank connection disconnected successfully'
            })
        else:
            return jsonify({'error': result['error']}), 400
        
    except Exception as e:
        return jsonify({'error': f'Error disconnecting bank: {str(e)}'}), 500

@bank_bp.route('/connections/link-token', methods=['POST'])
@login_required
@rate_limit(max_requests=5, window_seconds=60)
def link_token():
    """Generate link token for bank connection."""
    try:
        data = request.get_json()
        
        if not data or 'institution_id' not in data:
            return jsonify({'error': 'Institution ID is required'}), 400
        
        institution_id = data['institution_id']
        
        bank_service = BankService()
        result = bank_service.create_link_token(current_user.id, institution_id)
        
        if result['success']:
            return jsonify({
                'success': True,
                'link_token': result['link_token'],
                'expires_at': result['expires_at']
            })
        else:
            return jsonify({'error': result['error']}), 400
        
    except Exception as e:
        return jsonify({'error': f'Error creating link token: {str(e)}'}), 500

@bank_bp.route('/connections/exchange', methods=['POST'])
@login_required
@rate_limit(max_requests=10, window_seconds=60)
def exchange_token():
    """Exchange public token for access token."""
    try:
        data = request.get_json()
        
        if not data or 'public_token' not in data:
            return jsonify({'error': 'Public token is required'}), 400
        
        public_token = data['public_token']
        
        bank_service = BankService()
        result = bank_service.exchange_public_token(current_user.id, public_token)
        
        if result['success']:
            return jsonify({
                'success': True,
                'connection_id': result['connection_id'],
                'message': 'Bank connection established successfully'
            })
        else:
            return jsonify({'error': result['error']}), 400
        
    except Exception as e:
        return jsonify({'error': f'Error exchanging token: {str(e)}'}), 500

# Admin routes for bank management
@bank_bp.route('/admin/banks', methods=['GET'])
@admin_required
def admin_banks():
    """Admin page for bank management."""
    try:
        # Get all bank connections
        connections = BankConnection.query.all()
        
        # Get bank statistics
        total_connections = len(connections)
        active_connections = len([c for c in connections if c.is_active])
        total_transactions = Transaction.query.filter(
            Transaction.bank_connection_id.isnot(None)
        ).count()
        
        return render_template('admin/banks.html',
                             connections=connections,
                             total_connections=total_connections,
                             active_connections=active_connections,
                             total_transactions=total_transactions)
        
    except Exception as e:
        flash(f'Error loading bank management: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard'))

@bank_bp.route('/admin/banks/sync-all', methods=['POST'])
@admin_required
@validate_csrf_token
def admin_sync_all():
    """Sync all bank connections (Admin only)."""
    try:
        bank_service = BankService()
        
        # Get all active connections
        connections = BankConnection.query.filter_by(is_active=True).all()
        
        total_imported = 0
        errors = []
        
        for connection in connections:
            try:
                result = bank_service.import_transactions(connection.id)
                if result['success']:
                    total_imported += result['imported_count']
                else:
                    errors.append(f"Connection {connection.name}: {result['error']}")
            except Exception as e:
                errors.append(f"Connection {connection.name}: {str(e)}")
        
        flash(f'Bank sync completed. Imported {total_imported} transactions.', 'success')
        
        if errors:
            flash(f'Some connections had errors: {len(errors)}', 'warning')
        
        return redirect(url_for('bank.admin_banks'))
        
    except Exception as e:
        flash(f'Error syncing banks: {str(e)}', 'error')
        return redirect(url_for('bank.admin_banks'))

@bank_bp.route('/admin/banks/logs', methods=['GET'])
@admin_required
def admin_logs():
    """Bank sync logs page (Admin only)."""
    try:
        # Get recent bank sync logs
        # This would typically come from a BankSyncLog model
        logs = []  # Placeholder for actual log data
        
        return render_template('admin/bank_logs.html', logs=logs)
        
    except Exception as e:
        flash(f'Error loading bank logs: {str(e)}', 'error')
        return redirect(url_for('bank.admin_banks'))
