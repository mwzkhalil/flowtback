"""
API routes for FlowTrack application.
Handles REST API endpoints for external integrations and AJAX requests.
"""

from flask import Blueprint, request, jsonify, current_app
from flask_login import current_user
from src.models import db, Transaction, User
from routes.middleware import login_required, validate_json, rate_limit
from src.transaction_security import get_accessible_transactions
from src.currency_service import get_currency_service
import logging

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/errors', methods=['POST'])
def report_error():
    """Report client-side errors."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        error_info = {
            'message': data.get('message', ''),
            'stack': data.get('stack', ''),
            'url': data.get('url', ''),
            'user_agent': request.headers.get('User-Agent', ''),
            'user_id': current_user.id if current_user.is_authenticated else None
        }
        
        # Log the error
        logging.error(f"Client-side error: {error_info}")
        
        return jsonify({'success': True, 'message': 'Error reported successfully'})
        
    except Exception as e:
        return jsonify({'error': f'Error reporting error: {str(e)}'}), 500

@api_bp.route('/performance', methods=['POST'])
def report_performance():
    """Report performance metrics."""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        performance_info = {
            'page_load_time': data.get('page_load_time', 0),
            'api_response_time': data.get('api_response_time', 0),
            'memory_usage': data.get('memory_usage', 0),
            'user_id': current_user.id if current_user.is_authenticated else None
        }
        
        # Log performance metrics
        logging.info(f"Performance metrics: {performance_info}")
        
        return jsonify({'success': True, 'message': 'Performance metrics reported successfully'})
        
    except Exception as e:
        return jsonify({'error': f'Error reporting performance: {str(e)}'}), 500

@api_bp.route('/currency/rates', methods=['GET'])
@login_required
def get_currency_rates():
    """Get current currency exchange rates."""
    try:
        currency_service = get_currency_service()
        
        if not currency_service:
            return jsonify({'error': 'Currency service unavailable'}), 503
        
        rates = currency_service.get_current_rates()
        
        return jsonify({
            'success': True,
            'rates': rates,
            'last_updated': currency_service.get_last_update_time()
        })
        
    except Exception as e:
        return jsonify({'error': f'Error getting currency rates: {str(e)}'}), 500

@api_bp.route('/currency/refresh', methods=['POST'])
@login_required
@rate_limit(max_requests=10, window_seconds=60)
def refresh_currency_rates():
    """Refresh currency exchange rates."""
    try:
        currency_service = get_currency_service()
        
        if not currency_service:
            return jsonify({'error': 'Currency service unavailable'}), 503
        
        success = currency_service.refresh_rates()
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Currency rates refreshed successfully'
            })
        else:
            return jsonify({'error': 'Failed to refresh currency rates'}), 500
        
    except Exception as e:
        return jsonify({'error': f'Error refreshing currency rates: {str(e)}'}), 500

@api_bp.route('/currency/convert', methods=['POST'])
@login_required
@validate_json
def convert_currency():
    """Convert currency amount."""
    try:
        data = request.get_json()
        
        required_fields = ['amount', 'from_currency', 'to_currency']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        amount = float(data['amount'])
        from_currency = data['from_currency'].upper()
        to_currency = data['to_currency'].upper()
        
        currency_service = get_currency_service()
        
        if not currency_service:
            return jsonify({'error': 'Currency service unavailable'}), 503
        
        converted_amount = currency_service.convert(amount, from_currency, to_currency)
        
        if converted_amount is None:
            return jsonify({'error': 'Currency conversion failed'}), 400
        
        return jsonify({
            'success': True,
            'original_amount': amount,
            'from_currency': from_currency,
            'to_currency': to_currency,
            'converted_amount': converted_amount,
            'exchange_rate': currency_service.get_rate(from_currency, to_currency)
        })
        
    except ValueError:
        return jsonify({'error': 'Invalid amount format'}), 400
    except Exception as e:
        return jsonify({'error': f'Error converting currency: {str(e)}'}), 500

@api_bp.route('/transactions', methods=['GET'])
@login_required
def get_transactions():
    """Get user's transactions via API."""
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        category = request.args.get('category')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Get user's transactions
        transactions_query = get_accessible_transactions(current_user.id)
        
        # Apply filters
        if category:
            transactions_query = transactions_query.filter(Transaction.category == category)
        
        if start_date:
            transactions_query = transactions_query.filter(Transaction.date >= start_date)
        
        if end_date:
            transactions_query = transactions_query.filter(Transaction.date <= end_date)
        
        # Paginate
        transactions = transactions_query.order_by(Transaction.date.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        # Format response
        transaction_list = []
        for t in transactions.items:
            transaction_list.append({
                'id': t.id,
                'description': t.description,
                'amount': float(t.amount),
                'category': t.category,
                'date': t.date.isoformat(),
                'created_at': t.created_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'transactions': transaction_list,
            'pagination': {
                'page': transactions.page,
                'pages': transactions.pages,
                'per_page': transactions.per_page,
                'total': transactions.total
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'Error getting transactions: {str(e)}'}), 500

@api_bp.route('/transactions/<int:transaction_id>', methods=['GET'])
@login_required
def get_transaction(transaction_id):
    """Get a specific transaction via API."""
    try:
        transaction = get_accessible_transactions(current_user.id).filter(
            Transaction.id == transaction_id
        ).first()
        
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        return jsonify({
            'success': True,
            'transaction': {
                'id': transaction.id,
                'description': transaction.description,
                'amount': float(transaction.amount),
                'category': transaction.category,
                'date': transaction.date.isoformat(),
                'created_at': transaction.created_at.isoformat()
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'Error getting transaction: {str(e)}'}), 500

@api_bp.route('/transactions/<int:transaction_id>', methods=['PUT'])
@login_required
@validate_json
def update_transaction(transaction_id):
    """Update a transaction via API."""
    try:
        transaction = get_accessible_transactions(current_user.id).filter(
            Transaction.id == transaction_id
        ).first()
        
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        data = request.get_json()
        
        # Update fields
        if 'description' in data:
            transaction.description = data['description']
        
        if 'amount' in data:
            transaction.amount = float(data['amount'])
        
        if 'category' in data:
            transaction.category = data['category']
        
        if 'date' in data:
            from datetime import datetime
            transaction.date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Transaction updated successfully'
        })
        
    except ValueError:
        return jsonify({'error': 'Invalid data format'}), 400
    except Exception as e:
        return jsonify({'error': f'Error updating transaction: {str(e)}'}), 500

@api_bp.route('/transactions/<int:transaction_id>', methods=['DELETE'])
@login_required
def delete_transaction(transaction_id):
    """Delete a transaction via API."""
    try:
        transaction = get_accessible_transactions(current_user.id).filter(
            Transaction.id == transaction_id
        ).first()
        
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        db.session.delete(transaction)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Transaction deleted successfully'
        })
        
    except Exception as e:
        return jsonify({'error': f'Error deleting transaction: {str(e)}'}), 500

@api_bp.route('/categories', methods=['GET'])
@login_required
def get_categories():
    """Get available transaction categories."""
    try:
        # Get unique categories from user's transactions
        transactions = get_accessible_transactions(current_user.id)
        categories = db.session.query(Transaction.category).filter(
            Transaction.category.isnot(None)
        ).distinct().all()
        
        category_list = [cat[0] for cat in categories if cat[0]]
        
        return jsonify({
            'success': True,
            'categories': category_list
        })
        
    except Exception as e:
        return jsonify({'error': f'Error getting categories: {str(e)}'}), 500

@api_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    """Get user's financial statistics."""
    try:
        transactions = get_accessible_transactions(current_user.id)
        
        # Calculate basic stats
        total_income = transactions.filter(Transaction.amount > 0).with_entities(
            db.func.sum(Transaction.amount)
        ).scalar() or 0
        
        total_expenses = abs(transactions.filter(Transaction.amount < 0).with_entities(
            db.func.sum(Transaction.amount)
        ).scalar() or 0)
        
        transaction_count = transactions.count()
        
        # Get category breakdown
        category_stats = db.session.query(
            Transaction.category,
            db.func.sum(Transaction.amount).label('total')
        ).filter(
            Transaction.user_id == current_user.id,
            Transaction.category.isnot(None)
        ).group_by(Transaction.category).all()
        
        category_breakdown = {
            cat: float(total) for cat, total in category_stats
        }
        
        return jsonify({
            'success': True,
            'stats': {
                'total_income': float(total_income),
                'total_expenses': float(total_expenses),
                'net_balance': float(total_income - total_expenses),
                'transaction_count': transaction_count,
                'category_breakdown': category_breakdown
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'Error getting stats: {str(e)}'}), 500
