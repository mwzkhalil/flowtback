"""
Dashboard routes for FlowTrack application.
Handles main dashboard, cash overview, and analytics views.
"""

from flask import Blueprint, request, jsonify
from flask_login import current_user
from src.models import db, User, Transaction, InitialBalance
from routes.middleware import login_required, validate_csrf_token
from src.utils import calculate_totals, calculate_burn_rate, calculate_runway
from src.transaction_security import get_accessible_transactions
import matplotlib.pyplot as plt
import io
import base64
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib.dates import MonthLocator, DateFormatter
import matplotlib.ticker as ticker
from datetime import datetime, timedelta
import calendar

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@dashboard_bp.route('/home')
@login_required
def home():
    """Main dashboard page."""
    try:
        # Get user's transactions
        transactions = get_accessible_transactions(current_user.id)
        
        # Calculate totals
        totals = calculate_totals(transactions)
        
        # Get initial balance
        initial_balance = InitialBalance.query.filter_by(user_id=current_user.id).first()
        
        # Calculate burn rate and runway
        burn_rate = calculate_burn_rate(transactions)
        runway = calculate_runway(totals['balance'], burn_rate)
        
        # Get recent transactions
        recent_transactions = transactions.order_by(Transaction.date.desc()).limit(10).all()
        
        return jsonify({
            'success': True,
            'data': {
                'totals': totals,
                'initial_balance': {
                    'amount': initial_balance.amount if initial_balance else 0,
                    'currency': initial_balance.currency if initial_balance else 'USD'
                } if initial_balance else None,
                'burn_rate': burn_rate,
                'runway': runway,
                'recent_transactions': [
                    {
                        'id': t.id,
                        'description': t.description,
                        'amount': float(t.amount),
                        'type': t.type,
                        'category': t.category,
                        'date': t.date.isoformat() if t.date else None,
                        'created_at': t.created_at.isoformat() if t.created_at else None
                    } for t in recent_transactions
                ]
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error loading dashboard: {str(e)}'
        }), 500

@dashboard_bp.route('/stats')
@login_required
def stats():
    """Dashboard statistics API endpoint."""
    try:
        # Get user's transactions
        transactions = get_accessible_transactions(current_user.id)
        
        # Calculate totals
        totals = calculate_totals(transactions)
        
        # Get initial balance
        initial_balance = InitialBalance.query.filter_by(user_id=current_user.id).first()
        
        # Calculate burn rate and runway
        burn_rate = calculate_burn_rate(transactions)
        runway = calculate_runway(totals['balance'], burn_rate)
        
        # Get transaction count by category
        category_stats = {}
        for transaction in transactions:
            category = transaction.category or 'Uncategorized'
            if category not in category_stats:
                category_stats[category] = {'count': 0, 'total': 0}
            category_stats[category]['count'] += 1
            category_stats[category]['total'] += float(transaction.amount)
        
        return jsonify({
            'success': True,
            'data': {
                'totals': totals,
                'initial_balance': {
                    'amount': initial_balance.amount if initial_balance else 0,
                    'currency': initial_balance.currency if initial_balance else 'USD'
                } if initial_balance else None,
                'burn_rate': burn_rate,
                'runway': runway,
                'category_stats': category_stats,
                'transaction_count': transactions.count()
            }
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error loading dashboard stats: {str(e)}'
        }), 500

# Template-based routes removed - using API endpoints instead

# All template-based routes removed - using API endpoints instead

def get_monthly_balance_data(transactions, initial_amount):
    """Get monthly balance data for charts."""
    monthly_data = {}
    current_balance = initial_amount
    
    # Sort transactions by date
    sorted_transactions = transactions.order_by(Transaction.date).all()
    
    for transaction in sorted_transactions:
        month_key = transaction.date.strftime('%Y-%m')
        
        if month_key not in monthly_data:
            monthly_data[month_key] = {
                'balance': current_balance,
                'income': 0,
                'expense': 0
            }
        
        if transaction.amount > 0:
            monthly_data[month_key]['income'] += transaction.amount
        else:
            monthly_data[month_key]['expense'] += abs(transaction.amount)
        
        current_balance += transaction.amount
        monthly_data[month_key]['balance'] = current_balance
    
    return monthly_data

def generate_monthly_balance_chart(transactions, initial_amount):
    """Generate monthly balance chart."""
    try:
        # Get monthly data
        monthly_data = get_monthly_balance_data(transactions, initial_amount)
        
        if not monthly_data:
            return None
        
        # Prepare data for chart
        months = sorted(monthly_data.keys())
        balances = [monthly_data[month]['balance'] for month in months]
        
        # Create chart
        fig = Figure(figsize=(12, 6))
        ax = fig.add_subplot(111)
        
        ax.plot(months, balances, marker='o', linewidth=2, markersize=6)
        ax.set_title('Monthly Balance Trend', fontsize=16, fontweight='bold')
        ax.set_xlabel('Month', fontsize=12)
        ax.set_ylabel('Balance', fontsize=12)
        ax.grid(True, alpha=0.3)
        
        # Format y-axis as currency
        def currency_formatter(x, p):
            return f'${x:,.0f}'
        
        ax.yaxis.set_major_formatter(ticker.FuncFormatter(currency_formatter))
        
        # Rotate x-axis labels
        fig.autofmt_xdate()
        
        # Convert to base64 string
        img = io.BytesIO()
        fig.savefig(img, format='png', dpi=300, bbox_inches='tight')
        img.seek(0)
        
        chart_url = base64.b64encode(img.getvalue()).decode()
        
        return f"data:image/png;base64,{chart_url}"
        
    except Exception as e:
        print(f"Error generating chart: {str(e)}")
        return None
