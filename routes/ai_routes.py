"""
AI routes for FlowTrack application.
Handles AI-powered analysis, forecasting, and insights.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user
from src.models import db, Transaction
from routes.middleware import login_required, super_admin_required, rate_limit, validate_csrf_token
from src.ai_utils import ai_rate_limit, monitor_ai_performance
from src.anthropic_service import FinancialAnalytics
from src.transaction_security import get_accessible_transactions
import json

ai_bp = Blueprint('ai', __name__, url_prefix='/ai')

@ai_bp.route('/analysis')
@login_required
def analysis():
    """AI analysis dashboard."""
    try:
        # Check if user has transaction data
        transactions = get_accessible_transactions(current_user.id)
        
        if not transactions.count():
            flash('No transaction data available for analysis', 'info')
            return render_template('ai_analysis.html', analysis_data=None)
        
        # Get recent transactions for analysis
        recent_transactions = transactions.order_by(Transaction.date.desc()).limit(50).all()
        
        # Prepare data for AI analysis
        transaction_data = []
        for t in recent_transactions:
            transaction_data.append({
                'date': t.date.isoformat(),
                'amount': float(t.amount),
                'description': t.description,
                'category': t.category or 'Uncategorized'
            })
        
        return render_template('ai_analysis.html', 
                             analysis_data=transaction_data,
                             transaction_count=transactions.count())
        
    except Exception as e:
        flash(f'Error loading AI analysis: {str(e)}', 'error')
        return render_template('ai_analysis.html', analysis_data=None)

@ai_bp.route('/analysis/generate')
@login_required
def generate_analysis():
    """Generate AI analysis."""
    try:
        # Check if user has transaction data
        transactions = get_accessible_transactions(current_user.id)
        
        if not transactions.count():
            return jsonify({'error': 'No transaction data available'}), 400
        
        # Get transaction data
        transaction_data = []
        for t in transactions.limit(100):
            transaction_data.append({
                'date': t.date.isoformat(),
                'amount': float(t.amount),
                'description': t.description,
                'category': t.category or 'Uncategorized'
            })
        
        # Generate AI analysis
        analytics = FinancialAnalytics()
        analysis_result = analytics.analyze_financial_data(transaction_data)
        
        return jsonify({
            'success': True,
            'analysis': analysis_result
        })
        
    except Exception as e:
        return jsonify({'error': f'Error generating analysis: {str(e)}'}), 500

@ai_bp.route('/analysis/cashflow')
@login_required
def cashflow_analysis():
    """AI cashflow analysis."""
    try:
        transactions = get_accessible_transactions(current_user.id)
        
        if not transactions.count():
            flash('No transaction data available for cashflow analysis', 'info')
            return render_template('ai_analysis_cashflow.html', analysis_data=None)
        
        # Get transaction data for cashflow analysis
        transaction_data = []
        for t in transactions.order_by(Transaction.date):
            transaction_data.append({
                'date': t.date.isoformat(),
                'amount': float(t.amount),
                'description': t.description,
                'category': t.category or 'Uncategorized'
            })
        
        return render_template('ai_analysis_cashflow.html', 
                             analysis_data=transaction_data)
        
    except Exception as e:
        flash(f'Error loading cashflow analysis: {str(e)}', 'error')
        return render_template('ai_analysis_cashflow.html', analysis_data=None)

@ai_bp.route('/analysis/risk')
@login_required
def risk_analysis():
    """AI risk assessment."""
    try:
        transactions = get_accessible_transactions(current_user.id)
        
        if not transactions.count():
            flash('No transaction data available for risk analysis', 'info')
            return render_template('ai_analysis_risk.html', analysis_data=None)
        
        # Get transaction data for risk analysis
        transaction_data = []
        for t in transactions:
            transaction_data.append({
                'date': t.date.isoformat(),
                'amount': float(t.amount),
                'description': t.description,
                'category': t.category or 'Uncategorized'
            })
        
        return render_template('ai_analysis_risk.html', 
                             analysis_data=transaction_data)
        
    except Exception as e:
        flash(f'Error loading risk analysis: {str(e)}', 'error')
        return render_template('ai_analysis_risk.html', analysis_data=None)

@ai_bp.route('/analysis/anomaly')
@login_required
def anomaly_detection():
    """AI anomaly detection."""
    try:
        transactions = get_accessible_transactions(current_user.id)
        
        if not transactions.count():
            flash('No transaction data available for anomaly detection', 'info')
            return render_template('ai_analysis_anomaly.html', analysis_data=None)
        
        # Get transaction data for anomaly detection
        transaction_data = []
        for t in transactions:
            transaction_data.append({
                'date': t.date.isoformat(),
                'amount': float(t.amount),
                'description': t.description,
                'category': t.category or 'Uncategorized'
            })
        
        return render_template('ai_analysis_anomaly.html', 
                             analysis_data=transaction_data)
        
    except Exception as e:
        flash(f'Error loading anomaly detection: {str(e)}', 'error')
        return render_template('ai_analysis_anomaly.html', analysis_data=None)

@ai_bp.route('/analysis/forecast')
@login_required
def forecast_analysis():
    """AI forecasting analysis."""
    try:
        transactions = get_accessible_transactions(current_user.id)
        
        if not transactions.count():
            flash('No transaction data available for forecasting', 'info')
            return render_template('ai_analysis_forecast.html', analysis_data=None)
        
        # Get transaction data for forecasting
        transaction_data = []
        for t in transactions.order_by(Transaction.date):
            transaction_data.append({
                'date': t.date.isoformat(),
                'amount': float(t.amount),
                'description': t.description,
                'category': t.category or 'Uncategorized'
            })
        
        return render_template('ai_analysis_forecast.html', 
                             analysis_data=transaction_data)
        
    except Exception as e:
        flash(f'Error loading forecast analysis: {str(e)}', 'error')
        return render_template('ai_analysis_forecast.html', analysis_data=None)

@ai_bp.route('/analysis/dashboard')
@login_required
def dashboard_analysis():
    """AI dashboard with comprehensive analysis."""
    try:
        transactions = get_accessible_transactions(current_user.id)
        
        if not transactions.count():
            flash('No transaction data available for AI dashboard', 'info')
            return render_template('ai_analysis_dashboard.html', analysis_data=None)
        
        # Get comprehensive transaction data
        transaction_data = []
        for t in transactions:
            transaction_data.append({
                'date': t.date.isoformat(),
                'amount': float(t.amount),
                'description': t.description,
                'category': t.category or 'Uncategorized'
            })
        
        return render_template('ai_analysis_dashboard.html', 
                             analysis_data=transaction_data)
        
    except Exception as e:
        flash(f'Error loading AI dashboard: {str(e)}', 'error')
        return render_template('ai_analysis_dashboard.html', analysis_data=None)

@ai_bp.route('/analysis/assistant')
@login_required
def assistant():
    """AI assistant for financial queries."""
    try:
        transactions = get_accessible_transactions(current_user.id)
        
        if not transactions.count():
            flash('No transaction data available for AI assistant', 'info')
            return render_template('ai_analysis_assistant.html', analysis_data=None)
        
        # Get transaction data for AI assistant
        transaction_data = []
        for t in transactions:
            transaction_data.append({
                'date': t.date.isoformat(),
                'amount': float(t.amount),
                'description': t.description,
                'category': t.category or 'Uncategorized'
            })
        
        return render_template('ai_analysis_assistant.html', 
                             analysis_data=transaction_data)
        
    except Exception as e:
        flash(f'Error loading AI assistant: {str(e)}', 'error')
        return render_template('ai_analysis_assistant.html', analysis_data=None)

@ai_bp.route('/categorize-transactions', methods=['POST'])
@super_admin_required
@ai_rate_limit('categorization')
@monitor_ai_performance('categorization')
def categorize_transactions():
    """AI-powered transaction categorization."""
    try:
        data = request.get_json()
        
        if not data or 'transactions' not in data:
            return jsonify({'error': 'Transaction data is required'}), 400
        
        transactions = data['transactions']
        
        # Use AI to categorize transactions
        analytics = FinancialAnalytics()
        categorized = analytics.categorize_transactions(transactions)
        
        return jsonify({
            'success': True,
            'categorized_transactions': categorized
        })
        
    except Exception as e:
        return jsonify({'error': f'Error categorizing transactions: {str(e)}'}), 500

@ai_bp.route('/risk-assessment', methods=['GET', 'POST'])
@super_admin_required
@ai_rate_limit('risk_assessment')
@monitor_ai_performance('risk_assessment')
def risk_assessment():
    """AI risk assessment."""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            if not data or 'transactions' not in data:
                return jsonify({'error': 'Transaction data is required'}), 400
            
            transactions = data['transactions']
            
            # Use AI for risk assessment
            analytics = FinancialAnalytics()
            risk_analysis = analytics.assess_risk(transactions)
            
            return jsonify({
                'success': True,
                'risk_assessment': risk_analysis
            })
            
        except Exception as e:
            return jsonify({'error': f'Error assessing risk: {str(e)}'}), 500
    
    return render_template('ai_risk_assessment.html')

@ai_bp.route('/anomaly-detection', methods=['GET', 'POST'])
@super_admin_required
@ai_rate_limit('anomaly_detection')
@monitor_ai_performance('anomaly_detection')
def anomaly_detection_api():
    """AI anomaly detection."""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            if not data or 'transactions' not in data:
                return jsonify({'error': 'Transaction data is required'}), 400
            
            transactions = data['transactions']
            
            # Use AI for anomaly detection
            analytics = FinancialAnalytics()
            anomalies = analytics.detect_anomalies(transactions)
            
            return jsonify({
                'success': True,
                'anomalies': anomalies
            })
            
        except Exception as e:
            return jsonify({'error': f'Error detecting anomalies: {str(e)}'}), 500
    
    return render_template('ai_anomaly_detection.html')

@ai_bp.route('/advanced-forecast', methods=['GET', 'POST'])
@super_admin_required
@ai_rate_limit('advanced_forecast')
@monitor_ai_performance('advanced_forecast')
def advanced_forecast():
    """AI advanced forecasting."""
    if request.method == 'POST':
        try:
            data = request.get_json()
            
            if not data or 'transactions' not in data:
                return jsonify({'error': 'Transaction data is required'}), 400
            
            transactions = data['transactions']
            forecast_period = data.get('forecast_period', 12)  # months
            
            # Use AI for advanced forecasting
            analytics = FinancialAnalytics()
            forecast = analytics.advanced_forecast(transactions, forecast_period)
            
            return jsonify({
                'success': True,
                'forecast': forecast
            })
            
        except Exception as e:
            return jsonify({'error': f'Error generating forecast: {str(e)}'}), 500
    
    return render_template('ai_advanced_forecast.html')

@ai_bp.route('/custom-insights', methods=['POST'])
@super_admin_required
@ai_rate_limit('custom_insights')
@monitor_ai_performance('custom_insights')
def custom_insights():
    """AI custom insights generation."""
    try:
        data = request.get_json()
        
        if not data or 'transactions' not in data:
            return jsonify({'error': 'Transaction data is required'}), 400
        
        transactions = data['transactions']
        query = data.get('query', '')
        
        # Use AI for custom insights
        analytics = FinancialAnalytics()
        insights = analytics.generate_custom_insights(transactions, query)
        
        return jsonify({
            'success': True,
            'insights': insights
        })
        
    except Exception as e:
        return jsonify({'error': f'Error generating insights: {str(e)}'}), 500

@ai_bp.route('/dashboard')
@super_admin_required
def dashboard():
    """AI dashboard for SuperAdmin."""
    try:
        # Get system-wide transaction data for AI dashboard
        transactions = Transaction.query.order_by(Transaction.date.desc()).limit(1000).all()
        
        transaction_data = []
        for t in transactions:
            transaction_data.append({
                'date': t.date.isoformat(),
                'amount': float(t.amount),
                'description': t.description,
                'category': t.category or 'Uncategorized',
                'user_id': t.user_id
            })
        
        return render_template('ai_dashboard.html', 
                             analysis_data=transaction_data)
        
    except Exception as e:
        flash(f'Error loading AI dashboard: {str(e)}', 'error')
        return render_template('ai_dashboard.html', analysis_data=None)

@ai_bp.route('/results')
@super_admin_required
def results():
    """AI results page."""
    try:
        # Get AI analysis results
        return render_template('ai_results.html')
        
    except Exception as e:
        flash(f'Error loading AI results: {str(e)}', 'error')
        return render_template('ai_results.html')

@ai_bp.route('/health-check')
@login_required
def health_check():
    """AI service health check."""
    try:
        analytics = FinancialAnalytics()
        health_status = analytics.health_check()
        
        return jsonify({
            'success': True,
            'status': health_status
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'AI service unavailable: {str(e)}'
        }), 503
