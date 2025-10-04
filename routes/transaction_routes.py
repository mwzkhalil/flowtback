"""
Transaction routes for FlowTrack application.
Handles transaction CRUD operations, editing, and management.
"""

from flask import Blueprint, request, jsonify
from flask_login import current_user
from src.models import db, Transaction, InitialBalance
from routes.middleware import login_required, validate_csrf_token, transaction_owner_or_admin_required
from src.transaction_security import get_accessible_transactions
from src.utils import calculate_totals
from datetime import datetime

transaction_bp = Blueprint('transaction', __name__)

@transaction_bp.route('/transactions', methods=['POST'])
@login_required
def create_transaction():
    """Create a new transaction - API endpoint."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request data'}), 400
        
        # Get form data
        description = data.get('description')
        amount = data.get('amount')
        transaction_type = data.get('type')
        category = data.get('category')
        date = data.get('date')
        
        # Validate required fields
        if not all([description, amount, transaction_type, date]):
            return jsonify({'error': 'All fields are required'}), 400
        
        # Convert amount to float
        try:
            amount = float(amount)
        except ValueError:
            return jsonify({'error': 'Invalid amount format'}), 400
        
        # Adjust amount based on type
        if transaction_type == 'expense':
            amount = -abs(amount)
        else:
            amount = abs(amount)
        
        # Parse date
        try:
            date = datetime.strptime(date, '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400
        
        # Create transaction
        transaction = Transaction(
            description=description,
            amount=amount,
            category=category,
            date=date,
            user_id=current_user.id
        )
        
        db.session.add(transaction)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Transaction created successfully',
            'data': {
                'id': transaction.id,
                'description': transaction.description,
                'amount': float(transaction.amount),
                'type': 'expense' if transaction.amount < 0 else 'income',
                'category': transaction.category,
                'date': transaction.date.isoformat() if transaction.date else None,
                'created_at': transaction.created_at.isoformat() if transaction.created_at else None
            }
        }), 201
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error creating transaction: {str(e)}'
        }), 500

@transaction_bp.route('/transactions', methods=['GET'])
@login_required
def get_transactions():
    """Get all transactions for the current user - API endpoint."""
    try:
        transactions = get_accessible_transactions(current_user.id)
        
        # Get query parameters for filtering
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        category = request.args.get('category')
        transaction_type = request.args.get('type')
        
        # Apply filters
        if category:
            transactions = transactions.filter(Transaction.category == category)
        if transaction_type:
            if transaction_type == 'income':
                transactions = transactions.filter(Transaction.amount > 0)
            elif transaction_type == 'expense':
                transactions = transactions.filter(Transaction.amount < 0)
        
        # Pagination
        transactions = transactions.order_by(Transaction.date.desc())
        paginated_transactions = transactions.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'success': True,
            'data': {
                'transactions': [
                    {
                        'id': t.id,
                        'description': t.description,
                        'amount': float(t.amount),
                        'type': 'expense' if t.amount < 0 else 'income',
                        'category': t.category,
                        'date': t.date.isoformat() if t.date else None,
                        'created_at': t.created_at.isoformat() if t.created_at else None,
                        'updated_at': t.updated_at.isoformat() if t.updated_at else None
                    } for t in paginated_transactions.items
                ],
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': paginated_transactions.total,
                    'pages': paginated_transactions.pages,
                    'has_next': paginated_transactions.has_next,
                    'has_prev': paginated_transactions.has_prev
                }
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching transactions: {str(e)}'
        }), 500

@transaction_bp.route('/transactions/<int:transaction_id>', methods=['GET'])
@login_required
@transaction_owner_or_admin_required('transaction_id')
def get_transaction(transaction_id):
    """Get a specific transaction - API endpoint."""
    try:
        transaction = Transaction.query.get_or_404(transaction_id)
        
        return jsonify({
            'success': True,
            'data': {
                'id': transaction.id,
                'description': transaction.description,
                'amount': float(transaction.amount),
                'type': 'expense' if transaction.amount < 0 else 'income',
                'category': transaction.category,
                'date': transaction.date.isoformat() if transaction.date else None,
                'created_at': transaction.created_at.isoformat() if transaction.created_at else None,
                'updated_at': transaction.updated_at.isoformat() if transaction.updated_at else None
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching transaction: {str(e)}'
        }), 500

@transaction_bp.route('/transactions/<int:transaction_id>', methods=['PUT'])
@login_required
@transaction_owner_or_admin_required('transaction_id')
def update_transaction(transaction_id):
    """Update a transaction - API endpoint."""
    try:
        transaction = Transaction.query.get_or_404(transaction_id)
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Invalid request data'}), 400
        
        # Validate required fields
        required_fields = ['description', 'amount', 'type', 'date']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Convert amount to float
        try:
            amount = float(data['amount'])
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid amount format'}), 400
        
        # Adjust amount based on type
        if data['type'] == 'expense':
            amount = -abs(amount)
        else:
            amount = abs(amount)
        
        # Parse date
        try:
            date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400
        
        # Update transaction
        transaction.description = data['description']
        transaction.amount = amount
        transaction.category = data.get('category')
        transaction.date = date
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Transaction updated successfully',
            'data': {
                'id': transaction.id,
                'description': transaction.description,
                'amount': float(transaction.amount),
                'type': 'expense' if transaction.amount < 0 else 'income',
                'category': transaction.category,
                'date': transaction.date.isoformat() if transaction.date else None,
                'updated_at': transaction.updated_at.isoformat() if transaction.updated_at else None
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error updating transaction: {str(e)}'
        }), 500

@transaction_bp.route('/transactions/<int:transaction_id>', methods=['DELETE'])
@login_required
@transaction_owner_or_admin_required('transaction_id')
def delete_transaction(transaction_id):
    """Delete a transaction - API endpoint."""
    try:
        transaction = Transaction.query.get_or_404(transaction_id)
        
        db.session.delete(transaction)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Transaction deleted successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error deleting transaction: {str(e)}'
        }), 500

# Legacy template routes removed - using API endpoints instead

@transaction_bp.route('/balance-by-date', methods=['POST'])
@login_required
def balance_by_date():
    """Get balance for a specific date."""
    try:
        data = request.get_json()
        
        if not data or 'date' not in data:
            return jsonify({'error': 'Date is required'}), 400
        
        # Parse date
        try:
            target_date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400
        
        # Get initial balance
        initial_balance = InitialBalance.query.filter_by(user_id=current_user.id).first()
        balance = initial_balance.amount if initial_balance else 0.0
        
        # Get transactions up to target date
        transactions = get_accessible_transactions(current_user.id).filter(
            Transaction.date <= target_date
        ).all()
        
        # Calculate balance
        for transaction in transactions:
            balance += transaction.amount
        
        return jsonify({
            'success': True,
            'balance': balance,
            'date': target_date.isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': f'Error calculating balance: {str(e)}'}), 500

# Template-based routes removed - using API endpoints instead
