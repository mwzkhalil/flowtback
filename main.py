import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, current_app, session, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from typing_extensions import Annotated
from src.models import db, User, Transaction, InitialBalance, UserPreferences
from src.forms import LoginForm, RegistrationForm, CreateUserForm
from src.anthropic_service import FinancialAnalytics
from src.upload_handler import process_upload
from src.utils import calculate_totals, calculate_burn_rate, calculate_runway
from src.rbac import assign_default_role, assign_role, remove_role, get_user_roles, update_user_preferences_on_role_change
from src.auth_decorators import (
    super_admin_required, admin_required, admin_or_super_admin_required,
    transaction_owner_or_admin_required, authenticated_only, admin_rate_limit
)
from src.transaction_security import (
    get_accessible_transactions, prepare_export_data, log_data_access
)
from src.ai_utils import ai_rate_limit, monitor_ai_performance
from src.config import Config
import pandas as pd
from io import BytesIO
from dotenv import load_dotenv
import traceback
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
import matplotlib.pyplot as plt
import io
import base64
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib.dates import MonthLocator, DateFormatter
import matplotlib.ticker as ticker
from datetime import datetime
import calendar
from flask_migrate import Migrate
from flask_babel import Babel
import time
from functools import wraps
from datetime import datetime, timedelta
from src.admin_utils import (
    get_users_with_roles,
    get_user_statistics,
    get_user_transaction_summary,
    validate_role_assignment,
    log_admin_action,
    get_user_role_history,
    export_user_data,
    get_available_roles_for_admin
)
from sqlalchemy.exc import SQLAlchemyError

# Load .env file explicitly at the start
load_dotenv()

# Ensure instance folder exists
instance_path = os.path.join(os.path.dirname(__file__),'instance')
os.makedirs(instance_path, exist_ok=True)

upload_path = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(upload_path, exist_ok=True)

app = Flask(__name__,
            template_folder='templates',
            static_folder='static')
app.config.from_object(Config)

db.init_app(app)

migrate = Migrate(app, db)


login_manager = LoginManager(app)
login_manager.login_view = 'login'

babel = Babel()

# Consistent role context across templates
@app.context_processor
def inject_role_context():
    try:
        roles = [role.name for role in current_user.roles] if current_user.is_authenticated and hasattr(current_user, 'roles') else []
    except Exception:
        roles = []
    return {
        'user_roles': roles,
        'is_super_admin': 'super_admin' in roles,
        'is_admin': 'admin' in roles,
        'is_user': ('admin' not in roles and 'super_admin' not in roles)
    }

def get_locale():
    # Debug print
    print(f"get_locale called, session: {session}")
    
    # First check if a language is stored in the session
    if 'language' in session:
        lang = session['language']
        print(f"Using language from session: {lang}")
        return lang
        
    # Otherwise fallback to browser preference
    browser_lang = request.accept_languages.best_match(['en', 'es', 'ja', 'ar', 'ru', 'zh'])
    print(f"Using browser language: {browser_lang}")
    return browser_lang

# Initialize babel with the locale selector function
babel.init_app(app, locale_selector=get_locale)

@app.template_filter('datetimeformat')
def datetimeformat(value, fmt='%Y-%m-%d %H:%M'):
    """Jinja filter to format datetime or datetime-like strings safely."""
    try:
        if value is None or value == '':
            return ''
        if isinstance(value, str):
            # Try ISO format first
            try:
                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            except Exception:
                # Fallback to common formats
                for pattern in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
                    try:
                        dt = datetime.strptime(value, pattern)
                        break
                    except Exception:
                        dt = None
                if dt is None:
                    return value
        elif hasattr(value, 'strftime'):
            dt = value
        else:
            return value
        return dt.strftime(fmt)
    except Exception:
        return value

def validate_csrf_header_if_enabled() -> bool:
    """Validates X-CSRFToken header only when CSRF is enabled and a session token exists."""
    try:
        if not current_app.config.get('WTF_CSRF_ENABLED'):
            return True
        token_in_session = session.get('csrf_token')
        if not token_in_session:
            # No session token to validate against; skip strict validation
            return True
        header_token = request.headers.get('X-CSRFToken') or request.headers.get('X-CSRF-Token')
        if not header_token:
            return False
        return header_token == token_in_session
    except Exception:
        return False

@app.route('/set-language/<language>')
def set_language(language):
    # Store language in session
    session['language'] = language
    print(f"Setting language to: {language}")
    print(f"Session contains: {session}")
    # Debug response to confirm language setting
    flash(f'Language set to: {language}', 'info')
    # Redirect back to the referring page or home page
    return redirect(request.referrer or url_for('home'))

@login_manager.user_loader
def load_user(user_id):
    #return User.query.get(int(user_id))
    return db.session.get(User, int(user_id))

#All routes in app
@app.route('/',methods=['GET','POST'])
@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    user_status = "Logged In"
    page = request.args.get('page', 1, type=int)
    per_page = 8

    if request.method == 'POST':
        # Handle adding transactions
        new_transaction = Transaction(
            user_id=current_user.id,
            date=request.form.get('date'),
            description=request.form.get('description'),
            amount=float(request.form.get('amount')),
            type=request.form.get('type')
        )
        db.session.add(new_transaction)
        db.session.commit()
        flash('Transaction added successfully', 'success')
        return redirect(url_for('home'))

    # Filter transactions by current user
    paginated_transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).paginate(page=page, per_page=per_page)
    all_transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    
    # Get initial balance for current user
    initial_balance_record = InitialBalance.query.filter_by(user_id=current_user.id).first()
    initial_balance = initial_balance_record.balance if initial_balance_record else 0.0

    total_cfo, total_cfi, total_cff = calculate_totals(all_transactions)
    balance = initial_balance + total_cfo + total_cfi + total_cff

    return render_template('home.html', transactions=paginated_transactions, balance=balance, initial_balance=initial_balance,
                           total_cfo=total_cfo, total_cfi=total_cfi, total_cff=total_cff, user=current_user, status=user_status)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        # Optional OTP support
        otp_code = request.form.get('otp')
        # If 2FA is enforced in settings in future, validate otp_code here
        if user and check_password_hash(user.password, form.password.data):
            # Update last_login timestamp before logging in
            try:
                user.last_login = datetime.utcnow()
                db.session.commit()
            except Exception:
                db.session.rollback()
            login_user(user, remember=True)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register',methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if not current_app.config.get('PUBLIC_SIGNUP_ENABLED', True):
        abort(403)
    form = RegistrationForm()
    if form.validate_on_submit():
        user_exists = User.query.filter_by(username=form.username.data).first()
        if user_exists:
            flash('Username already exists. Please choose a different one.', 'danger')
        else:
            hashed_password = generate_password_hash(form.password.data)
            new_user = User(
                username=form.username.data,
                email=getattr(form, 'email', None).data if hasattr(form, 'email') else None,
                password=hashed_password,
                subscription_tier=current_app.config.get('DEFAULT_SUBSCRIPTION_TIER', 'free'),
                timezone='UTC'
            )
            db.session.add(new_user)
            db.session.commit()
            
            # Assign default 'user' role
            success = assign_default_role(new_user)
            if not success:
                current_app.logger.warning(f"Default role assignment failed for user {new_user.username}. Ensure roles are seeded.")
            
            new_preferences = UserPreferences(user_id=new_user.id)
            db.session.add(new_preferences)
            db.session.flush()  # Ensure the preferences have an ID
            new_preferences.ensure_role_based_modules(new_user)
            db.session.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/admin/users/create', methods=['GET', 'POST'])
@super_admin_required
def admin_create_user():
    form = CreateUserForm()
    if request.method == 'GET':
        # Defaults
        form.subscription_tier.data = current_app.config.get('DEFAULT_SUBSCRIPTION_TIER', 'free')
        form.timezone.data = 'UTC'
    if form.validate_on_submit():
        from src.admin_utils import create_user_account
        role_names = []
        if form.roles.data:
            role_names = [r.strip() for r in form.roles.data.split(',') if r.strip()]
        data = {
            'username': form.username.data,
            'email': form.email.data,
            'first_name': form.first_name.data,
            'last_name': form.last_name.data,
            'company_name': form.company_name.data,
            'subscription_tier': form.subscription_tier.data,
            'tenant_id': form.tenant_id.data,
            'phone': form.phone.data,
            'timezone': form.timezone.data,
            'password': form.password.data or None,
            'notes': form.notes.data,
            'is_active': form.is_active.data,
        }
        user, result = create_user_account(current_user, data, role_names)
        if user:
            flash('User created successfully', 'success')
            return redirect(url_for('admin_user_detail', user_id=user.id))
        else:
            errs = result.get('errors', {}) if isinstance(result, dict) else {}
            for k, v in errs.items():
                flash(f"{k}: {v}", 'danger')
    return render_template('admin/create_user.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/edit/<int:transaction_id>', methods=['GET', 'POST'])
@transaction_owner_or_admin_required('transaction_id')
def edit_transaction(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    if request.method == 'POST':
        transaction.date = request.form['date']
        transaction.description = request.form['description']
        transaction.amount = float(request.form['amount'])
        transaction.type = request.form['type']
        db.session.commit()
        flash('Transaction Updated Successfully', 'success')
        return redirect(url_for('cash_activities'))
    return render_template('edit_transaction.html', transaction=transaction)

@app.route('/delete/<int:transaction_id>', methods=['POST'])
@transaction_owner_or_admin_required('transaction_id')
def delete_transaction(transaction_id):
    transaction = Transaction.query.get_or_404(transaction_id)
    db.session.delete(transaction)
    db.session.commit()
    flash('Your Transaction Deleted!', 'danger')
    return redirect(url_for('home'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_route():
    if request.method == 'GET':
        return render_template('upload.html')
    elif request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        try:
            result = process_upload(file)
            return jsonify(result)
        except Exception as e:
            app.logger.error(f"Error in upload_file: {str(e)}")
            return jsonify({'error': str(e)}), 500

@app.route('/set-initial-balance', methods=['POST'])
@login_required
def set_initial_balance():
    try:
        amount = float(request.form.get('initial_balance'))
        
        # Get or create initial balance record for the user
        initial_balance = InitialBalance.query.filter_by(user_id=current_user.id).first()
        if initial_balance:
            initial_balance.balance = amount
        else:
            initial_balance = InitialBalance(user_id=current_user.id, balance=amount)
            db.session.add(initial_balance)
            
        db.session.commit()
        flash('Initial balance set successfully', 'success')
    except ValueError:
        flash('Please enter a valid number for the initial balance', 'danger')
    except Exception as e:
        flash(f'Error setting initial balance: {str(e)}', 'danger')
        
    return redirect(url_for('cash_overview'))

@app.route('/export/<file_type>')
@login_required
def export(file_type):
    # Get accessible transactions based on user role
    transactions_query, filename_prefix = prepare_export_data(current_user, file_type)
    transactions = transactions_query.all()
    
    # Log data access for security auditing
    log_data_access(current_user, 'transactions', 'export', f'export_{file_type}')
    
    data = [{
        'Date': transaction.date,
        'Description': transaction.description,
        'Amount': transaction.amount,
        'Type': transaction.type,
        'User': transaction.user.username if hasattr(transaction, 'user') else f'User {transaction.user_id}'
    } for transaction in transactions]

    df = pd.DataFrame(data)

    if file_type == 'csv':
        output = BytesIO()
        df.to_csv(output, index=False)
        output.seek(0)
        return send_file(output, mimetype='text/csv', as_attachment=True, download_name=f'{filename_prefix}.csv')
    elif file_type == 'excel':
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Transactions')
        output.seek(0)
        return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 
                         as_attachment=True, download_name=f'{filename_prefix}.xlsx')
    elif file_type == 'pdf':
        flash('PDF export is not yet implemented.', 'warning')
        return redirect(url_for('home'))
    else:
        flash('Invalid file type requested.', 'danger')
        return redirect(url_for('home'))

@app.route('/save_transactions', methods=['POST'])
@login_required
def save_transactions():
    data = request.json
    try:
        for item in data:
            new_transaction = Transaction(
                user_id=current_user.id,
                date=item['date'],
                description=item['description'],
                amount=float(item['amount']),
                type=item['type']
            )
            db.session.add(new_transaction)
        db.session.commit()
        return jsonify({'message': 'Transactions saved successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/balance-by-date', methods=['POST'])
@login_required
def balance_by_date():
    try:
        date_str = request.form.get('date')
        target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        
        # Get initial balance
        initial_balance = InitialBalance.query.filter_by(user_id=current_user.id).first()
        initial_amount = initial_balance.balance if initial_balance else 0
        
        # Get all transactions up to the target date
        transactions = Transaction.query.filter(
            Transaction.user_id == current_user.id,
            Transaction.date <= target_date
        ).all()
        
        # Calculate totals
        total_cfo, total_cfi, total_cff = calculate_totals(transactions)
        balance = initial_amount + total_cfo + total_cfi + total_cff
        
        return jsonify({
            'success': True,
            'balance': balance,
            'date': date_str
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
    
@app.route('/forecast', methods=['GET'])
@super_admin_required
def forecast():
    try:
        # Get current user's transactions only
        transactions_query = Transaction.query.filter_by(user_id=current_user.id)
        transactions = transactions_query.order_by(Transaction.date).all()
        
        if not transactions:
            return jsonify({
                'error': 'No transactions found. Please add some transactions first.'
            }), 400
            
        # Convert transactions to a format suitable for analysis
        transaction_data = []
        for t in transactions:
            if isinstance(t.date, str):
                date_str = t.date
            else:
                date_str = t.date.strftime('%Y-%m-%d')
            transaction_data.append({
                'date': date_str,
                'amount': t.amount,
                'type': t.type,
                'description': t.description
            })
        
        # Initialize financial analytics with API key
        api_key = current_app.config.get('ANTHROPIC_API_KEY')
        if not api_key:
            return jsonify({
                'error': 'API key not found. Please set the ANTHROPIC_API_KEY environment variable.'
            }), 500
            
        analytics = FinancialAnalytics(api_key=api_key, test_connection=False)
        
        # Get initial balance
        initial_balance_record = InitialBalance.query.filter_by(user_id=current_user.id).first()
        initial_balance = initial_balance_record.balance if initial_balance_record else 0.0
        
        # Calculate current balance
        current_balance = initial_balance + sum(t.amount for t in transactions)
        
        # Mock working capital data (you may want to replace this with actual data)
        working_capital = {
            'current_assets': current_balance,
            'current_liabilities': 0,
            'cash': current_balance
        }
        
        # Get analysis results using the correct method
        analysis_results = analytics.generate_advanced_financial_analysis(
            initial_balance=initial_balance,
            current_balance=current_balance,
            transaction_history=transaction_data,
            working_capital=working_capital
        )
        
        return jsonify({
            'success': True,
            'ai_analysis': analysis_results.get('ai_analysis', 'No insights available'),
            'patterns': analysis_results.get('patterns', {'seasonal_pattern': [0] * 12}),
            'forecasts': analysis_results.get('forecasts', {'90_days': [0] * 90}),
            'risk_metrics': analysis_results.get('risk_metrics', {
                'liquidity_ratio': 0,
                'cash_flow_volatility': 0,
                'burn_rate': 0,
                'runway_months': 0
            })
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/generate_cashflow_statement', methods=['GET'])
@login_required
def generate_cashflow_statement_route():
    try:
        transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date).all()
        if not transactions:
            return jsonify({'error': 'No transactions found'}), 400

        initial_balance_record = InitialBalance.query.filter_by(user_id=current_user.id).first()
        initial_balance = initial_balance_record.balance if initial_balance_record else 0.0

        # Enhanced transaction data with transaction_id
        transaction_data = []
        for t in transactions:
            # Handle date formatting - check if it's already a string or datetime object
            if isinstance(t.date, str):
                date_str = t.date
            else:
                date_str = t.date.strftime('%Y-%m-%d')
                
            transaction_data.append({
                "transaction_id": getattr(t, 'transaction_id', str(t.id)),
                "date": date_str,
                "description": t.description,
                "amount": t.amount,
                "type": t.type
            })

        api_key = current_app.config.get('ANTHROPIC_API_KEY')
        if not api_key:
            return jsonify({'error': 'API key not found'}), 500
            
        analytics = FinancialAnalytics(api_key=api_key, test_connection=False)
        statement = analytics.generate_dual_cashflow_statement(initial_balance, transaction_data)
        return jsonify(statement)
    except Exception as e:
        current_app.logger.error(f"Error generating cashflow statement: {str(e)}")
        return jsonify({'error': f"Failed to generate cash flow statement: {str(e)}"}), 500

@app.route('/export_cashflow/excel')
@login_required
def export_cashflow_excel_route():
    try:
        transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date).all()
        if not transactions:
            return jsonify({'error': 'No transactions found'}), 400

        initial_balance_record = InitialBalance.query.filter_by(user_id=current_user.id).first()
        initial_balance = initial_balance_record.balance if initial_balance_record else 0.0

        transaction_data = []
        for t in transactions:
            date_str = t.date if isinstance(t.date, str) else t.date.strftime('%Y-%m-%d')
            transaction_data.append({
                "transaction_id": getattr(t, 'transaction_id', str(t.id)),
                "date": date_str,
                "description": t.description,
                "amount": t.amount,
                "type": t.type
            })

        api_key = current_app.config.get('ANTHROPIC_API_KEY')
        if not api_key:
            return jsonify({'error': 'API key not found'}), 500

        analytics = FinancialAnalytics(api_key=api_key, test_connection=False)
        statement = analytics.generate_dual_cashflow_statement(initial_balance, transaction_data)
        
        # Fallback if AI data is malformed
        if not statement or 'indirect_method' not in statement:
            # Create a simple fallback statement
            total_income = sum(t['amount'] for t in transaction_data if t['amount'] > 0)
            total_expenses = sum(abs(t['amount']) for t in transaction_data if t['amount'] < 0)
            net_income = total_income - total_expenses
            
            statement = {
                'indirect_method': {
                    'operating_activities': {
                        'net_income': net_income,
                        'depreciation': 0,
                        'amortization': 0,
                        'changes_in_working_capital': 0,
                        'total_operating_cash_flow': net_income
                    },
                    'investing_activities': {
                        'purchase_of_assets': 0,
                        'sale_of_assets': 0,
                        'investments': 0,
                        'total_investing_cash_flow': 0
                    },
                    'financing_activities': {
                        'debt_issued': 0,
                        'debt_repayment': 0,
                        'equity_issued': 0,
                        'dividends_paid': 0,
                        'total_financing_cash_flow': 0
                    },
                    'net_cash_flow': net_income,
                    'beginning_cash': initial_balance,
                    'ending_cash': initial_balance + net_income
                },
                'executive_summary': 'Basic cash flow analysis based on transaction data.',
                'validation': {
                    'duplicates': [],
                    'unusual_patterns': [],
                    'warnings': ['AI analysis unavailable - using basic calculation'],
                    'total_issues': 0
                }
            }

        # Generate Excel with better error handling
        output = BytesIO()
        workbook = Workbook()
        workbook.remove(workbook.active)  # Remove default sheet

        # Helper function for currency formatting
        def format_currency(cell):
            cell.number_format = '$#,##0.00'
            cell.font = Font(bold=True)

        # Helper function to safely get values
        def safe_get(data, key, default=0):
            try:
                value = data.get(key, default)
                return float(value) if value is not None else default
            except (ValueError, TypeError):
                return default

        # Executive Summary Sheet
        summary_sheet = workbook.create_sheet("Executive Summary")
        summary_sheet['A1'] = "Cash Flow Statement (Indirect Method)"
        summary_sheet['A1'].font = Font(size=16, bold=True)
        summary_sheet['A3'] = "Executive Summary:"
        summary_sheet['A3'].font = Font(bold=True)
        summary_sheet['A4'] = statement.get('executive_summary', 'No summary available')
        summary_sheet['A6'] = "Key Metrics:"
        summary_sheet['A6'].font = Font(bold=True)
        summary_sheet['A7'] = "Beginning Cash:"
        summary_sheet['B7'] = initial_balance
        format_currency(summary_sheet['B7'])
        summary_sheet['A8'] = "Net Cash Flow:"
        summary_sheet['B8'] = safe_get(statement.get('indirect_method', {}), 'net_cash_flow', 0)
        format_currency(summary_sheet['B8'])
        summary_sheet['A9'] = "Ending Cash:"
        summary_sheet['B9'] = safe_get(statement.get('indirect_method', {}), 'ending_cash', initial_balance + safe_get(statement.get('indirect_method', {}), 'net_cash_flow', 0))
        format_currency(summary_sheet['B9'])

        # Indirect Method Sheet (Main Statement)
        if 'indirect_method' in statement:
            indirect_sheet = workbook.create_sheet("Cash Flow Statement")
            indirect_sheet['A1'] = "Statement of Cash Flows (Indirect Method)"
            indirect_sheet['A1'].font = Font(size=14, bold=True)
            row = 3
            
            # Operating Activities
            indirect_sheet[f'A{row}'] = "CASH FLOWS FROM OPERATING ACTIVITIES"
            indirect_sheet[f'A{row}'].font = Font(bold=True)
            row += 2
            
            indirect_data = statement['indirect_method']
            operating = indirect_data.get('operating_activities', {})
            
            indirect_sheet[f'A{row}'] = "Net Income"
            indirect_sheet[f'B{row}'] = safe_get(operating, 'net_income', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 1
            
            indirect_sheet[f'A{row}'] = "Adjustments to reconcile net income to net cash:"
            indirect_sheet[f'A{row}'].font = Font(italic=True)
            row += 1
            
            indirect_sheet[f'A{row}'] = "  Depreciation"
            indirect_sheet[f'B{row}'] = safe_get(operating, 'depreciation', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 1
            
            indirect_sheet[f'A{row}'] = "  Amortization"
            indirect_sheet[f'B{row}'] = safe_get(operating, 'amortization', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 1
            
            indirect_sheet[f'A{row}'] = "  Changes in Working Capital"
            indirect_sheet[f'B{row}'] = safe_get(operating, 'changes_in_working_capital', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 1
            
            indirect_sheet[f'A{row}'] = "Net Cash from Operating Activities"
            indirect_sheet[f'A{row}'].font = Font(bold=True)
            indirect_sheet[f'B{row}'] = safe_get(operating, 'total_operating_cash_flow', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 2
            
            # Investing Activities
            indirect_sheet[f'A{row}'] = "CASH FLOWS FROM INVESTING ACTIVITIES"
            indirect_sheet[f'A{row}'].font = Font(bold=True)
            row += 2
            
            investing = indirect_data.get('investing_activities', {})
            
            indirect_sheet[f'A{row}'] = "Purchase of Assets"
            indirect_sheet[f'B{row}'] = safe_get(investing, 'purchase_of_assets', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 1
            
            indirect_sheet[f'A{row}'] = "Sale of Assets"
            indirect_sheet[f'B{row}'] = safe_get(investing, 'sale_of_assets', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 1
            
            indirect_sheet[f'A{row}'] = "Investments"
            indirect_sheet[f'B{row}'] = safe_get(investing, 'investments', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 1
            
            indirect_sheet[f'A{row}'] = "Net Cash from Investing Activities"
            indirect_sheet[f'A{row}'].font = Font(bold=True)
            indirect_sheet[f'B{row}'] = safe_get(investing, 'total_investing_cash_flow', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 2
            
            # Financing Activities
            indirect_sheet[f'A{row}'] = "CASH FLOWS FROM FINANCING ACTIVITIES"
            indirect_sheet[f'A{row}'].font = Font(bold=True)
            row += 2
            
            financing = indirect_data.get('financing_activities', {})
            
            indirect_sheet[f'A{row}'] = "Debt Issued"
            indirect_sheet[f'B{row}'] = safe_get(financing, 'debt_issued', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 1
            
            indirect_sheet[f'A{row}'] = "Debt Repayment"
            indirect_sheet[f'B{row}'] = safe_get(financing, 'debt_repayment', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 1
            
            indirect_sheet[f'A{row}'] = "Equity Issued"
            indirect_sheet[f'B{row}'] = safe_get(financing, 'equity_issued', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 1
            
            indirect_sheet[f'A{row}'] = "Dividends Paid"
            indirect_sheet[f'B{row}'] = safe_get(financing, 'dividends_paid', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 1
            
            indirect_sheet[f'A{row}'] = "Net Cash from Financing Activities"
            indirect_sheet[f'A{row}'].font = Font(bold=True)
            indirect_sheet[f'B{row}'] = safe_get(financing, 'total_financing_cash_flow', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 2
            
            # Net Change and Ending Balance
            indirect_sheet[f'A{row}'] = "NET INCREASE (DECREASE) IN CASH"
            indirect_sheet[f'A{row}'].font = Font(bold=True)
            indirect_sheet[f'B{row}'] = safe_get(indirect_data, 'net_cash_flow', 0)
            format_currency(indirect_sheet[f'B{row}'])
            row += 1
            
            indirect_sheet[f'A{row}'] = "Cash at Beginning of Period"
            indirect_sheet[f'B{row}'] = safe_get(indirect_data, 'beginning_cash', initial_balance)
            format_currency(indirect_sheet[f'B{row}'])
            row += 1
            
            indirect_sheet[f'A{row}'] = "Cash at End of Period"
            indirect_sheet[f'A{row}'].font = Font(bold=True)
            indirect_sheet[f'B{row}'] = safe_get(indirect_data, 'ending_cash', initial_balance + safe_get(indirect_data, 'net_cash_flow', 0))
            format_currency(indirect_sheet[f'B{row}'])

        # Validation Sheet
        if 'validation' in statement:
            val_sheet = workbook.create_sheet("Validation")
            val_sheet['A1'] = "Validation Report"
            val_sheet['A1'].font = Font(size=14, bold=True)
            row = 3
            if statement['validation']['duplicates']:
                val_sheet[f'A{row}'] = "Duplicates"
                val_sheet[f'A{row}'].font = Font(bold=True)
                row += 1
                for dup in statement['validation']['duplicates']:
                    val_sheet[f'A{row}'] = dup['transaction_id']
                    val_sheet[f'B{row}'] = dup['issue']
                    val_sheet[f'C{row}'] = dup['severity']
                    row += 1
            if statement['validation']['unusual_patterns']:
                val_sheet[f'A{row}'] = "Unusual Patterns"
                val_sheet[f'A{row}'].font = Font(bold=True)
                row += 1
                for pattern in statement['validation']['unusual_patterns']:
                    val_sheet[f'A{row}'] = pattern['pattern']
                    val_sheet[f'B{row}'] = pattern['description']
                    val_sheet[f'C{row}'] = pattern['severity']
                    row += 1

        try:
            workbook.save(output)
            output.seek(0)
            return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 
                             as_attachment=True, download_name='cashflow_statement.xlsx')
        except Exception as excel_error:
            current_app.logger.error(f"Excel save error: {str(excel_error)}")
            # Try to create a minimal Excel file
            try:
                output = BytesIO()
                workbook = Workbook()
                ws = workbook.active
                ws.title = "Cash Flow Statement"
                ws['A1'] = "Cash Flow Statement (Basic)"
                ws['A1'].font = Font(size=16, bold=True)
                ws['A3'] = "Beginning Cash:"
                ws['B3'] = initial_balance
                ws['A4'] = "Net Cash Flow:"
                ws['B4'] = sum(t['amount'] for t in transaction_data)
                ws['A5'] = "Ending Cash:"
                ws['B5'] = initial_balance + sum(t['amount'] for t in transaction_data)
                workbook.save(output)
                output.seek(0)
                return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 
                                 as_attachment=True, download_name='cashflow_statement_basic.xlsx')
            except Exception as fallback_error:
                current_app.logger.error(f"Fallback Excel error: {str(fallback_error)}")
                return jsonify({'error': f'Excel generation failed: {str(excel_error)}'}), 500

    except Exception as e:
        current_app.logger.error(f"Excel export error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Generate monthly chart function    
def generate_monthly_balance_chart():
    # Get transactions for the current user
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date).all()
    
    # Get initial balance for the current user
    initial_balance_record = InitialBalance.query.filter_by(user_id=current_user.id).first()
    initial_balance = initial_balance_record.balance if initial_balance_record else 0.0

    monthly_balances = []
    current_balance = initial_balance
    current_month = None

    for transaction in transactions:
        transaction_date = transaction.date if isinstance(transaction.date, datetime) else datetime.strptime(transaction.date, '%Y-%m-%d')
        
        if current_month != transaction_date.replace(day=1):
            if current_month:
                last_day = calendar.monthrange(current_month.year, current_month.month)[1]
                monthly_balances.append({
                    'date': current_month.replace(day=last_day),
                    'balance': current_balance
                })
            current_month = transaction_date.replace(day=1)

        current_balance += transaction.amount

    # Add the last month's balance
    if current_month:
        last_day = calendar.monthrange(current_month.year, current_month.month)[1]
        monthly_balances.append({
            'date': current_month.replace(day=last_day),
            'balance': current_balance
        })

    # Create the chart
    fig = Figure(figsize=(12, 6))
    axis = fig.add_subplot(1, 1, 1)
    
    if monthly_balances:
        dates = [balance['date'] for balance in monthly_balances]
        balances = [balance['balance'] for balance in monthly_balances]
        axis.plot(dates, balances, marker='o')  # Added markers for each data point

        # Improve Y-axis formatting
        def currency_formatter(x, p):
            return f'${x:,.0f}'
        
        axis.yaxis.set_major_formatter(ticker.FuncFormatter(currency_formatter))
        
        # Adjust Y-axis ticks for better readability
        axis.yaxis.set_major_locator(ticker.MaxNLocator(nbins=10, integer=True))
        
        # Format X-axis to show dates nicely
        axis.xaxis.set_major_locator(MonthLocator())
        axis.xaxis.set_major_formatter(DateFormatter('%Y-%m-%d'))
        
        # Add some padding to the y-axis
        ylim = axis.get_ylim()
        axis.set_ylim([ylim[0] - (ylim[1] - ylim[0]) * 0.1, ylim[1] + (ylim[1] - ylim[0]) * 0.1])
    else:
        # If no data, show a message on the chart
        axis.text(0.5, 0.5, 'No transaction data available', 
                 horizontalalignment='center', verticalalignment='center',
                 transform=axis.transAxes, fontsize=14)
        axis.set_xticks([])
        axis.set_yticks([])

    axis.set_title('Monthly Balance', fontsize=16, fontweight='bold')
    axis.set_xlabel('Date', fontsize=12)
    axis.set_ylabel('Balance ($)', fontsize=12)
    axis.tick_params(axis='both', which='major', labelsize=10)
    axis.tick_params(axis='x', rotation=45)
    
    # Add gridlines for better readability
    axis.grid(True, linestyle='--', alpha=0.7)

    fig.tight_layout()

    # Convert plot to PNG image
    png_image = io.BytesIO()
    FigureCanvas(fig).print_png(png_image)
    
    # Encode PNG image to base64 string
    png_image_b64_string = "data:image/png;base64,"
    png_image_b64_string += base64.b64encode(png_image.getvalue()).decode('utf8')

    return png_image_b64_string

#Map plotting chart
@app.route('/monthly-balances', methods=['GET'])
@login_required
def monthly_balances():
    try:
        app.logger.info("Starting to generate monthly balance data")
        transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date).all()
        initial_balance_record = InitialBalance.query.filter_by(user_id=current_user.id).first()
        initial_balance = initial_balance_record.balance if initial_balance_record else 0.0

        monthly_data = {}
        current_balance = initial_balance

        for transaction in transactions:
            month = transaction.date.strftime('%Y-%m') if isinstance(transaction.date, datetime) else datetime.strptime(transaction.date, '%Y-%m-%d').strftime('%Y-%m')
            
            if month not in monthly_data:
                monthly_data[month] = current_balance
            
            current_balance += transaction.amount
            monthly_data[month] = current_balance

        app.logger.info(f"Monthly balance data generated: {monthly_data}")
        return jsonify({
            'success': True,
            'data': {
                'labels': list(monthly_data.keys()),
                'balances': list(monthly_data.values())
            }
        })
    except Exception as e:
        app.logger.error(f"Error generating monthly balance data: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/settings')
@login_required
def settings():
    user_preferences = UserPreferences.query.filter_by(user_id=current_user.id).first()
    return render_template('settings.html', user_preferences=user_preferences)

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    current_user.username = request.form.get('username')
    current_user.email = request.form.get('email')
    db.session.commit()
    flash('Profile updated successfully', 'success')
    return redirect(url_for('settings'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    if check_password_hash(current_user.password, request.form.get('current_password')):
        if request.form.get('new_password') == request.form.get('confirm_password'):
            current_user.password = generate_password_hash(request.form.get('new_password'))
            db.session.commit()
            flash('Password changed successfully', 'success')
        else:
            flash('New passwords do not match', 'danger')
    else:
        flash('Current password is incorrect', 'danger')
    return redirect(url_for('settings'))

@app.route('/update_modules', methods=['POST'])
@login_required
def update_modules():
    user_preferences = UserPreferences.query.filter_by(user_id=current_user.id).first()
    if not user_preferences:
        user_preferences = UserPreferences(user_id=current_user.id)
        db.session.add(user_preferences)
    user_preferences.modules = request.form.getlist('modules')
    # Enforce role-based required modules after manual selection
    try:
        user_preferences.ensure_role_based_modules(current_user)
    except Exception:
        pass
    db.session.commit()
    flash('Module preferences updated successfully', 'success')
    return redirect(url_for('settings'))

@app.context_processor
def utility_processor():
    def get_user_preferences():
        if current_user.is_authenticated:
            prefs = UserPreferences.query.filter_by(user_id=current_user.id).first()
            if not prefs:
                prefs = UserPreferences(user_id=current_user.id)
                db.session.add(prefs)
                db.session.flush()  # Ensure the preferences have an ID
                try:
                    prefs.ensure_role_based_modules(current_user)
                except Exception:
                    pass
                db.session.commit()
            else:
                # Ensure existing preferences include any role-based defaults
                try:
                    if prefs.ensure_role_based_modules(current_user):
                        db.session.commit()
                except Exception:
                    pass
            return prefs
        return None
    return dict(user_preferences=get_user_preferences())

@app.route('/cash-overview')
@login_required
def cash_overview():
    # Get or create initial balance for the current user
    initial_balance = InitialBalance.query.filter_by(user_id=current_user.id).first()
    if not initial_balance:
        initial_balance = InitialBalance(user_id=current_user.id, balance=0)
        db.session.add(initial_balance)
        db.session.commit()

    # Get all transactions for the current user
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    
    # Calculate totals
    total_cfo, total_cfi, total_cff = calculate_totals(transactions)
    balance = initial_balance.balance + total_cfo + total_cfi + total_cff

    # Calculate burn rate and runway
    burn_rate = calculate_burn_rate(transactions)
    runway_months = calculate_runway(balance, burn_rate)

    return render_template('cash_overview.html', 
                         initial_balance=initial_balance.balance,
                         total_cfo=total_cfo, 
                         total_cfi=total_cfi, 
                         total_cff=total_cff, 
                         balance=balance,
                         burn_rate=burn_rate,
                         runway_months=runway_months)

@app.route('/cash-activities')
@login_required
def cash_activities():
    page = request.args.get('page', 1, type=int)
    per_page = 8
    
    # Get paginated transactions for the current user
    paginated_transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).paginate(page=page, per_page=per_page)
    
    return render_template('cash_activities.html', transactions=paginated_transactions)

@app.route('/ai-analysis')
@login_required
def ai_analysis():
    # Role-based access with module check and template context
    user_roles = [role.name for role in current_user.roles] if hasattr(current_user, 'roles') else []

    # Ensure user preferences exist
    prefs = UserPreferences.query.filter_by(user_id=current_user.id).first()
    if not prefs:
        prefs = UserPreferences(user_id=current_user.id)
        db.session.add(prefs)
        db.session.flush()
        try:
            prefs.ensure_role_based_modules(current_user)
        except Exception:
            pass
        db.session.commit()

    modules = prefs.modules or []

    # Transaction count for current user
    transaction_count = Transaction.query.filter_by(user_id=current_user.id).count()

    return render_template(
        'ai_analysis.html',
        transaction_count=transaction_count
    )

@app.route('/ai-analysis/basic', methods=['GET'])
@login_required
def ai_analysis_basic():
    """Basic AI analysis for regular users"""
    try:
        # Get current user's transactions
        transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date).all()
        
        if not transactions:
            return jsonify({
                'error': 'No transaction data found. Please add some transactions first.'
            })
        
        # Basic analysis data
        total_transactions = len(transactions)
        total_amount = sum(t.amount for t in transactions)
        avg_amount = total_amount / total_transactions if total_transactions > 0 else 0
        
        # Simple pattern analysis
        income_transactions = [t for t in transactions if t.amount > 0]
        expense_transactions = [t for t in transactions if t.amount < 0]
        
        total_income = sum(t.amount for t in income_transactions)
        total_expenses = abs(sum(t.amount for t in expense_transactions))
        
        # Basic cash flow analysis
        current_balance = sum(t.amount for t in transactions)
        
        # Simple risk metrics (monthly convention)
        monthly_burn = total_expenses  # Treat total monthly expenses as monthly burn
        runway_months = (current_balance / monthly_burn) if monthly_burn > 0 else 0
        risk_metrics = {
            'liquidity_ratio': 1.0 if total_expenses > 0 else 0.0,  # Simplified
            'cash_flow_volatility': abs(total_income - total_expenses),
            'burn_rate': monthly_burn,  # monthly burn
            'runway_months': runway_months
        }
        
        # Basic AI analysis text
        ai_analysis = f"""
        <div class="analysis-summary">
            <h6><i class="fas fa-chart-pie me-2"></i>Transaction Overview</h6>
            <p>You have {total_transactions} transactions with an average amount of ${avg_amount:.2f}.</p>
            <p><strong>Total Income:</strong> ${total_income:.2f}</p>
            <p><strong>Total Expenses:</strong> ${total_expenses:.2f}</p>
            <p><strong>Current Balance:</strong> ${current_balance:.2f}</p>
            
            <h6 class="mt-3"><i class="fas fa-lightbulb me-2"></i>Insights</h6>
            <ul>
                <li>Your expense ratio is {(total_expenses/total_income*100):.1f}% of income</li>
                <li>Average monthly burn rate: ${risk_metrics['burn_rate']:.2f}</li>
                <li>Estimated runway: {risk_metrics['runway_months']:.1f} months</li>
            </ul>
        </div>
        """
        
        return jsonify({
            'ai_analysis': ai_analysis,
            'risk_metrics': risk_metrics,
            'patterns': {
                'seasonal_pattern': [100, 105, 98, 102, 110, 95, 108, 103, 97, 105, 112, 98]  # Mock data
            },
            'forecasts': {
                '90_days': [100 + i * 0.5 + (i % 7 - 3) * 2 for i in range(90)]  # Mock data
            }
        })
        
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/cashflow-statement')
@login_required
def cashflow_statement():
    """Dedicated cashflow statement page"""
    return render_template('cashflow_statement.html')

@app.route('/ai-analysis/generate')
@super_admin_required
def ai_analysis_generate():
    """Dedicated AI analysis generation page"""
    return render_template('ai_analysis_generate.html')

@app.route('/ai-analysis/cashflow')
@super_admin_required
def ai_analysis_cashflow():
    """Dedicated AI cashflow analysis page"""
    return render_template('ai_analysis_cashflow.html')

@app.route('/ai-analysis/risk')
@super_admin_required
def ai_analysis_risk():
    """Dedicated AI risk assessment page"""
    return render_template('ai_analysis_risk.html')

@app.route('/ai-analysis/anomaly')
@super_admin_required
def ai_analysis_anomaly():
    """Dedicated AI anomaly detection page"""
    return render_template('ai_analysis_anomaly.html')

@app.route('/ai-analysis/forecast')
@super_admin_required
def ai_analysis_forecast():
    """Dedicated AI forecast page"""
    return render_template('ai_analysis_forecast.html')

@app.route('/create-transaction', methods=['POST'])
@login_required
def create_transaction():
    try:
        new_transaction = Transaction(
            user_id=current_user.id,
            date=request.form.get('date'),
            description=request.form.get('description'),
            amount=float(request.form.get('amount')),
            type=request.form.get('type')
        )
        db.session.add(new_transaction)
        db.session.commit()
        flash('Transaction added successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error adding transaction: ' + str(e), 'danger')
    
    return redirect(url_for('cash_activities'))

@app.route('/monthly-income-expense', methods=['GET'])
@login_required
def monthly_income_expense():
    try:
        transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date).all()
        monthly_data = {}

        for transaction in transactions:
            month = transaction.date.strftime('%Y-%m') if isinstance(transaction.date, datetime) else datetime.strptime(transaction.date, '%Y-%m-%d').strftime('%Y-%m')
            
            if month not in monthly_data:
                monthly_data[month] = {'income': 0, 'expense': 0}
            
            if transaction.amount > 0:
                monthly_data[month]['income'] += transaction.amount
            else:
                monthly_data[month]['expense'] += abs(transaction.amount)

        return jsonify({
            'success': True,
            'data': {
                'labels': list(monthly_data.keys()),
                'income': [data['income'] for data in monthly_data.values()],
                'expense': [data['expense'] for data in monthly_data.values()]
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/cashout-categories', methods=['GET'])
@login_required
def cashout_categories():
    try:
        # Fix the filter syntax for negative amounts
        transactions = Transaction.query.filter(
            Transaction.user_id == current_user.id,
            Transaction.amount < 0  # Correct syntax for filtering negative amounts
        ).all()

        categories_data = {}
        for transaction in transactions:
            category = transaction.type
            if category not in categories_data:
                categories_data[category] = 0
            categories_data[category] += abs(transaction.amount)

        return jsonify({
            'success': True,
            'data': {
                'labels': list(categories_data.keys()),
                'amounts': list(categories_data.values())
            }
        })
    except Exception as e:
        app.logger.error(f"Error fetching cashout categories: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/debug-language')
def debug_language():
    """Debug endpoint to check translations"""
    all_info = {
        'session_language': session.get('language', 'Not set'),
        'available_translations': os.listdir('translations'),
        'session_data': dict(session),
        'best_match': request.accept_languages.best_match(['en', 'es', 'ja']),
    }
    return jsonify(all_info)

# Advanced AI Features Routes - Super Admin Only
@app.route('/ai/categorize-transactions', methods=['POST'])
@super_admin_required
@ai_rate_limit('categorization')
@monitor_ai_performance('categorization')
def ai_categorize_transactions():
    """Route for automated transaction categorization"""
    try:
        data = request.get_json()
        if data is None:
            return jsonify({'error': 'Invalid or missing JSON body'}), 400
        transactions = data.get('transactions', [])
        
        if not transactions:
            return jsonify({'error': 'No transactions provided'}), 400
        
        # Check cache first
        from src.ai_utils import AIUtils
        import hashlib
        cache_key = f"categorization_{current_user.id}_{hashlib.sha256(str(transactions).encode()).hexdigest()[:16]}"
        cached_result = AIUtils.get_cached_ai_results(cache_key)
        if cached_result:
            return jsonify({
                'success': True,
                'result': cached_result,
                'cached': True
            })
        
        # Initialize financial analytics with API key
        api_key = current_app.config.get('ANTHROPIC_API_KEY')
        if not api_key:
            return jsonify({'error': 'API key not found'}), 500
            
        analytics = FinancialAnalytics(api_key=api_key, test_connection=False)
        
        # Get categorization suggestions
        categorization_result = analytics.automated_transaction_categorization(transactions)
        
        # Cache the result
        ttl = current_app.config['AI_CACHE_TTL']['categorization']
        AIUtils.cache_ai_results(cache_key, categorization_result, ttl)
        
        # Log AI feature usage
        current_app.logger.info(f"AI categorization used by super_admin user {current_user.id}")
        
        return jsonify({
            'success': True,
            'result': categorization_result
        })
        
    except Exception as e:
        current_app.logger.error(f"AI categorization error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/ai/risk-assessment', methods=['GET', 'POST'])
@super_admin_required
@ai_rate_limit('risk_assessment')
@monitor_ai_performance('risk_assessment')
def ai_risk_assessment():
    """Route for comprehensive risk assessment reports"""
    try:
        if request.method == 'GET':
            # Get current user's data for risk assessment
            transactions_query = Transaction.query.filter_by(user_id=current_user.id)
            transactions = transactions_query.order_by(Transaction.date).all()
        else:
            # POST request with specific user data
            data = request.get_json()
            if data is None:
                return jsonify({'error': 'Invalid or missing JSON body'}), 400
            user_id = data.get('user_id', current_user.id)
            transactions_query = Transaction.query.filter_by(user_id=user_id)
            transactions = transactions_query.order_by(Transaction.date).all()
        
        if not transactions:
            return jsonify({'error': 'No transactions found for risk assessment'}), 400
        
        # Prepare transaction history
        from src.ai_utils import AIUtils
        transaction_history = AIUtils.build_transaction_history(transactions)
        
        # Prepare balance data
        if request.method == 'GET':
            target_user_id = current_user.id
            target_user = current_user
        else:
            target_user_id = user_id
            target_user = User.query.get(user_id)
            if not target_user:
                return jsonify({'error': 'User not found'}), 400
        
        initial_balance_record = InitialBalance.query.filter_by(user_id=target_user_id).first()
        initial_balance = initial_balance_record.balance if initial_balance_record else 0.0
        current_balance = initial_balance + sum(t.amount for t in transactions)
        
        balance_data = {
            'initial_balance': initial_balance,
            'current_balance': current_balance,
            'total_transactions': len(transactions)
        }
        
        # Prepare user profile
        user_profile = {
            'user_id': target_user_id,
            'username': target_user.username,
            'account_age_days': 30,  # Placeholder - you might want to calculate this
            'transaction_frequency': len(transactions) / 30  # transactions per day
        }
        
        # Check cache first
        from src.ai_utils import AIUtils
        import hashlib
        cache_key = f"risk_assessment_{target_user_id}_{hashlib.sha256(str(transaction_history + [balance_data, user_profile]).encode()).hexdigest()[:16]}"
        cached_result = AIUtils.get_cached_ai_results(cache_key)
        if cached_result:
            return jsonify({
                'success': True,
                'result': cached_result,
                'cached': True
            })
        
        # Initialize financial analytics
        api_key = current_app.config.get('ANTHROPIC_API_KEY')
        if not api_key:
            return jsonify({'error': 'API key not found'}), 500
            
        analytics = FinancialAnalytics(api_key=api_key, test_connection=False)
        
        # Generate risk assessment
        risk_assessment = analytics.risk_assessment_reports(
            transaction_history, balance_data, user_profile
        )
        
        # Cache the result
        ttl = current_app.config['AI_CACHE_TTL']['risk_assessment']
        AIUtils.cache_ai_results(cache_key, risk_assessment, ttl)
        
        # Log AI feature usage
        log_ai_feature_usage(
            user_id=current_user.id,
            feature_name='risk_assessment',
            duration=0,  # Would be calculated from start time
            success=True,
            details={'user_id': target_user_id, 'transaction_count': len(transactions)}
        )
        
        current_app.logger.info(f"AI risk assessment completed for user {target_user_id}")
        
        return jsonify({
            'success': True,
            'result': risk_assessment
        })
        
    except Exception as e:
        current_app.logger.error(f"AI risk assessment error: {str(e)}")
        
        # Log the error
        log_ai_feature_usage(
            user_id=current_user.id,
            feature_name='risk_assessment',
            duration=0,
            success=False,
            details={'error': str(e)}
        )
        
        return jsonify({'error': 'Risk assessment failed. Please try again.'}), 500

@app.route('/ai/anomaly-detection', methods=['GET', 'POST'])
@super_admin_required
@ai_rate_limit('anomaly_detection')
@monitor_ai_performance('anomaly_detection')
def ai_anomaly_detection():
    """Route for anomaly detection analysis"""
    try:
        if request.method == 'GET':
            transactions_query = Transaction.query.filter_by(user_id=current_user.id)
            transactions = transactions_query.order_by(Transaction.date).all()
        else:
            data = request.get_json()
            if data is None:
                return jsonify({'error': 'Invalid or missing JSON body'}), 400
            user_id = data.get('user_id', current_user.id)
            transactions_query = Transaction.query.filter_by(user_id=user_id)
            transactions = transactions_query.order_by(Transaction.date).all()
        
        if not transactions:
            return jsonify({'error': 'No transactions found for anomaly detection'}), 400
        
        # Prepare transaction history
        from src.ai_utils import AIUtils
        transaction_history = AIUtils.build_transaction_history(transactions)
        
        # Prepare user patterns (simplified)
        amounts = [t.amount for t in transactions]
        user_patterns = {
            'average_amount': sum(amounts) / len(amounts) if amounts else 0,
            'max_amount': max(amounts) if amounts else 0,
            'min_amount': min(amounts) if amounts else 0,
            'transaction_count': len(transactions),
            'typical_frequency': len(transactions) / 30  # transactions per day
        }
        
        # Check cache first
        from src.ai_utils import AIUtils
        import hashlib
        user_id = current_user.id if request.method == 'GET' else data.get('user_id', current_user.id)
        cache_key = f"anomaly_detection_{user_id}_{hashlib.sha256(str(transaction_history + [user_patterns]).encode()).hexdigest()[:16]}"
        cached_result = AIUtils.get_cached_ai_results(cache_key)
        if cached_result:
            return jsonify({
                'success': True,
                'result': cached_result,
                'cached': True
            })
        
        # Initialize financial analytics
        api_key = current_app.config.get('ANTHROPIC_API_KEY')
        if not api_key:
            return jsonify({'error': 'API key not found'}), 500
            
        analytics = FinancialAnalytics(api_key=api_key, test_connection=False)
        
        # Generate anomaly detection
        anomaly_result = analytics.anomaly_detection(transaction_history, user_patterns)
        
        # Cache the result
        ttl = current_app.config['AI_CACHE_TTL']['anomaly_detection']
        AIUtils.cache_ai_results(cache_key, anomaly_result, ttl)
        
        # Log AI feature usage
        current_app.logger.info(f"AI anomaly detection used by super_admin user {current_user.id}")
        
        # Log AI feature usage for analytics
        log_ai_feature_usage(
            user_id=current_user.id,
            feature_name='anomaly_detection',
            duration=0,  # Duration would be calculated if we had timing
            success=True,
            details={'action': 'anomaly_detection_completed'}
        )
        
        return jsonify({
            'success': True,
            'result': anomaly_result
        })
        
    except Exception as e:
        current_app.logger.error(f"AI anomaly detection error: {str(e)}")
        
        # Log AI feature usage for analytics (error case)
        log_ai_feature_usage(
            user_id=current_user.id if current_user.is_authenticated else None,
            feature_name='anomaly_detection',
            duration=0,
            success=False,
            details={'error': str(e)}
        )
        
        return jsonify({'error': str(e)}), 500

@app.route('/ai/advanced-forecast', methods=['GET', 'POST'])
@super_admin_required
@ai_rate_limit('advanced_forecast')
@monitor_ai_performance('advanced_forecast')
def ai_advanced_forecast():
    """Route for advanced forecasting models"""
    try:
        if request.method == 'GET':
            transactions_query = Transaction.query.filter_by(user_id=current_user.id)
            transactions = transactions_query.order_by(Transaction.date).all()
        else:
            data = request.get_json()
            if data is None:
                return jsonify({'error': 'Invalid or missing JSON body'}), 400
            user_id = data.get('user_id', current_user.id)
            transactions_query = Transaction.query.filter_by(user_id=user_id)
            transactions = transactions_query.order_by(Transaction.date).all()
        
        if not transactions:
            return jsonify({'error': 'No transactions found for forecasting'}), 400
        
        # Prepare transaction history
        transaction_history = []
        for t in transactions:
            date_str = t.date if isinstance(t.date, str) else t.date.strftime('%Y-%m-%d')
            transaction_history.append({
                'date': date_str,
                'amount': t.amount,
                'type': t.type,
                'description': t.description
            })
        
        # Prepare external factors (simplified)
        external_factors = {
            'economic_indicators': {
                'inflation_rate': 3.2,
                'interest_rate': 5.25,
                'gdp_growth': 2.1
            },
            'seasonal_factors': {
                'quarter': 1,
                'month': 1,
                'holiday_season': False
            },
            'market_conditions': {
                'volatility_index': 18.5,
                'market_sentiment': 'neutral'
            }
        }
        
        # Check cache first
        from src.ai_utils import AIUtils
        import hashlib
        user_id = current_user.id if request.method == 'GET' else data.get('user_id', current_user.id)
        cache_key = f"advanced_forecast_{user_id}_{hashlib.sha256(str(transaction_history + [external_factors]).encode()).hexdigest()[:16]}"
        cached_result = AIUtils.get_cached_ai_results(cache_key)
        if cached_result:
            return jsonify({
                'success': True,
                'result': cached_result,
                'cached': True
            })
        
        # Initialize financial analytics
        api_key = current_app.config.get('ANTHROPIC_API_KEY')
        if not api_key:
            return jsonify({'error': 'API key not found'}), 500
            
        analytics = FinancialAnalytics(api_key=api_key, test_connection=False)
        
        # Generate advanced forecasting
        forecast_result = analytics.advanced_forecasting_models(
            transaction_history, external_factors
        )
        
        # Cache the result
        ttl = current_app.config['AI_CACHE_TTL']['advanced_forecast']
        AIUtils.cache_ai_results(cache_key, forecast_result, ttl)
        
        # Log AI feature usage
        current_app.logger.info(f"AI advanced forecasting used by super_admin user {current_user.id}")
        
        # Log AI feature usage for analytics
        log_ai_feature_usage(
            user_id=current_user.id,
            feature_name='advanced_forecast',
            duration=0,  # Duration would be calculated if we had timing
            success=True,
            details={'action': 'advanced_forecast_completed'}
        )
        
        return jsonify({
            'success': True,
            'result': forecast_result
        })
        
    except Exception as e:
        current_app.logger.error(f"AI advanced forecasting error: {str(e)}")
        
        # Log AI feature usage for analytics (error case)
        log_ai_feature_usage(
            user_id=current_user.id if current_user.is_authenticated else None,
            feature_name='advanced_forecast',
            duration=0,
            success=False,
            details={'error': str(e)}
        )
        
        return jsonify({'error': str(e)}), 500

@app.route('/ai/custom-insights', methods=['POST'])
@super_admin_required
@ai_rate_limit('custom_insights')
@monitor_ai_performance('custom_insights')
def ai_custom_insights():
    """Route for custom financial insights"""
    try:
        data = request.get_json()
        if data is None:
            return jsonify({'error': 'Invalid or missing JSON body'}), 400
        analysis_type = data.get('analysis_type', 'general')
        custom_parameters = data.get('custom_parameters', {})
        user_id = data.get('user_id', current_user.id)
        
        # Get transactions for analysis
        transactions_query = Transaction.query.filter_by(user_id=user_id)
        transactions = transactions_query.order_by(Transaction.date).all()
        
        if not transactions:
            return jsonify({'error': 'No transactions found for analysis'}), 400
        
        # Prepare transaction data
        transaction_data = []
        for t in transactions:
            date_str = t.date if isinstance(t.date, str) else t.date.strftime('%Y-%m-%d')
            transaction_data.append({
                'date': date_str,
                'amount': t.amount,
                'type': t.type,
                'description': t.description
            })
        
        # Check cache first
        from src.ai_utils import AIUtils
        import hashlib
        cache_key = f"custom_insights_{user_id}_{hashlib.sha256(str(transaction_data + [analysis_type, custom_parameters]).encode()).hexdigest()[:16]}"
        cached_result = AIUtils.get_cached_ai_results(cache_key)
        if cached_result:
            return jsonify({
                'success': True,
                'result': cached_result,
                'cached': True
            })
        
        # Initialize financial analytics
        api_key = current_app.config.get('ANTHROPIC_API_KEY')
        if not api_key:
            return jsonify({'error': 'API key not found'}), 500
            
        analytics = FinancialAnalytics(api_key=api_key, test_connection=False)
        
        # Generate custom insights
        insights_result = analytics.custom_financial_insights(
            transaction_data, analysis_type, custom_parameters
        )
        
        # Cache the result
        ttl = current_app.config['AI_CACHE_TTL']['custom_insights']
        AIUtils.cache_ai_results(cache_key, insights_result, ttl)
        
        # Log AI feature usage
        current_app.logger.info(f"AI custom insights used by super_admin user {current_user.id}, analysis_type: {analysis_type}")
        
        return jsonify({
            'success': True,
            'result': insights_result
        })
        
    except Exception as e:
        current_app.logger.error(f"AI custom insights error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# AI Dashboard Helper Functions and Caching
from src.ai_dashboard_utils import (
    get_ai_system_status,
    get_recent_ai_activities,
    get_ai_performance_metrics,
    log_ai_feature_usage,
    prepare_dashboard_context,
    monitor_system_health
)

@app.route('/ai/dashboard', methods=['GET'])
@super_admin_required
def ai_dashboard():
    """Route for AI dashboard showing all advanced features"""
    try:
        # Log AI dashboard access
        current_app.logger.info(f"AI dashboard accessed by super_admin user {current_user.id}")
        
        # Get comprehensive dashboard context using helper functions
        dashboard_context = prepare_dashboard_context(user_id=current_user.id)
        
        # Get user transaction summary for dashboard
        transactions_query = Transaction.query.filter_by(user_id=current_user.id)
        transaction_count = transactions_query.count()
        
        # Available AI features
        available_ai_features = [
            'risk_assessment', 'anomaly_detection', 'advanced_forecast',
            'custom_insights', 'transaction_categorization', 'chatbot'
        ]
        
        # Log dashboard access
        log_ai_feature_usage(
            user_id=current_user.id,
            feature_name='dashboard_access',
            duration=0,
            success=True,
            details={'action': 'dashboard_view'}
        )
        
        return render_template('ai_dashboard.html', 
                             transaction_count=transaction_count,
                             user=current_user,
                             available_ai_features=available_ai_features,
                             ai_performance_metrics=dashboard_context.get('performance_metrics'),
                             ai_system_status=dashboard_context.get('system_status'),
                             recent_ai_activities=dashboard_context.get('recent_activities', []))
        
    except Exception as e:
        current_app.logger.error(f"AI dashboard error: {str(e)}")
        # Log the error
        log_ai_feature_usage(
            user_id=current_user.id if current_user.is_authenticated else None,
            feature_name='dashboard_access',
            duration=0,
            success=False,
            details={'error': str(e)}
        )
        flash('Error loading AI dashboard. Please try again.', 'danger')
        return redirect(url_for('home'))

@app.route('/ai/results', methods=['GET', 'POST'])
@super_admin_required
def ai_results():
    """Route for displaying AI analysis results"""
    try:
        if request.method == 'POST':
            # Store results in session
            data = request.get_json()
            if data:
                session['ai_results'] = {
                    'results': data.get('results', {}),
                    'feature_type': data.get('feature_type', 'general'),
                    'timestamp': data.get('timestamp', datetime.now().isoformat())
                }
                return jsonify({'success': True})
            else:
                return jsonify({'error': 'No data provided'}), 400
        
        # GET request - display results
        # Get analysis type and results from session or query parameters
        analysis_type = request.args.get('type', 'general')
        results_data = session.get('ai_results', {})
        
        # If no results in session, redirect to dashboard
        if not results_data:
            flash('No analysis results found. Please run an analysis first.', 'info')
            return redirect(url_for('ai_dashboard'))
        
        # Prepare context for results template
        context = {
            'analysis_type': analysis_type,
            'timestamp': results_data.get('timestamp', datetime.now().isoformat()),
            'risk_summary': results_data.get('results', {}).get('risk_summary'),
            'liquidity_risk': results_data.get('results', {}).get('liquidity_risk'),
            'credit_risk': results_data.get('results', {}).get('credit_risk'),
            'market_risk': results_data.get('results', {}).get('market_risk'),
            'anomaly_summary': results_data.get('results', {}).get('anomaly_summary'),
            'anomalies': results_data.get('results', {}).get('anomalies', []),
            'forecasts': results_data.get('results', {}).get('forecasts'),
            'recommendations': results_data.get('results', {}).get('recommendations', []),
            'action_items': results_data.get('results', {}).get('action_items', [])
        }
        
        return render_template('ai_results.html', **context)
        
    except Exception as e:
        current_app.logger.error(f"AI results page error: {str(e)}")
        flash('Error loading results page. Please try again.', 'danger')
        return redirect(url_for('ai_dashboard'))

@app.route('/chatbot', methods=['GET', 'POST'])
@login_required
@ai_rate_limit('chatbot')
def chatbot():
    """Route for Natural Language to SQL chatbot interface"""
    try:
        # Check if chatbot is enabled
        if not current_app.config.get('CHATBOT_ENABLED', True):
            flash('Chatbot feature is currently disabled.', 'error')
            return redirect(url_for('home'))
        
        if request.method == 'GET':
            # Render chatbot interface
            current_app.logger.info(f"Chatbot interface accessed by user {current_user.id}")
            return render_template('chatbot.html', user=current_user)
        
    except Exception as e:
        current_app.logger.error(f"Chatbot error: {str(e)}")
        flash('Error loading chatbot interface', 'danger')
        return redirect(url_for('home'))

@app.route('/chatbot/query', methods=['POST'])
@login_required
@ai_rate_limit('chatbot_query')
def chatbot_query():
    """Route for processing chatbot natural language queries"""
    try:
        # Check if chatbot is enabled
        if not current_app.config.get('CHATBOT_ENABLED', True):
            return jsonify({'success': False, 'error': 'Chatbot feature is currently disabled.'}), 403
        
        # Get request data
        data = request.get_json()
        if not data or 'query' not in data:
            return jsonify({'success': False, 'error': 'Query is required'}), 400
            
        query = data['query'].strip()
        if not query:
            return jsonify({'success': False, 'error': 'Query cannot be empty'}), 400
            
        # Check query length
        if len(query) > current_app.config.get('CHATBOT_MAX_QUERY_LENGTH', 500):
            return jsonify({'success': False, 'error': f'Query too long. Maximum {current_app.config.get("CHATBOT_MAX_QUERY_LENGTH", 500)} characters allowed.'}), 400
        
        # Process the query using our simplified natural language processor
        result = process_natural_language_query(query, current_user)
        
        # Log query execution
        current_app.logger.info(f"Chatbot query executed by user {current_user.id}: {query[:100]}...")
        
        return jsonify(result)
        
    except Exception as e:
        current_app.logger.error(f"Chatbot query error: {str(e)}")
        return jsonify({'success': False, 'error': f'Query processing failed: {str(e)}'}), 500

def process_natural_language_query(query: str, user) -> dict:
    """
    Process natural language queries and convert them to database queries.
    Returns formatted results for the chatbot interface.
    """
    try:
        query_lower = query.lower()
        
        # Initialize result
        result = {
            'success': True,
            'response': '',
            'data': None,
            'sql_query': None
        }
        
        # Parse common query patterns
        if any(word in query_lower for word in ['income', 'revenue', 'earnings']):
            result = handle_income_query(query, user)
        elif any(word in query_lower for word in ['expense', 'spending', 'cost']):
            result = handle_expense_query(query, user)
        elif any(word in query_lower for word in ['balance', 'total', 'sum']):
            result = handle_balance_query(query, user)
        elif any(word in query_lower for word in ['transaction', 'transactions']):
            result = handle_transaction_query(query, user)
        elif any(word in query_lower for word in ['category', 'categories']):
            result = handle_category_query(query, user)
        else:
            # Default response for unrecognized queries
            result = {
                'success': True,
                'response': f"I understand you're asking: '{query}'\n\nI can help you with questions about:\n• Income and revenue\n• Expenses and spending\n• Account balances\n• Transaction history\n• Category breakdowns\n\nTry asking something like 'What was my total income last month?' or 'Show me my expenses by category'.",
                'data': None,
                'sql_query': None
            }
        
        return result
        
    except Exception as e:
        current_app.logger.error(f"Natural language query processing error: {str(e)}")
        return {
            'success': False,
            'error': f'Sorry, I encountered an error processing your query: {str(e)}',
            'data': None,
            'sql_query': None
        }

def handle_income_query(query: str, user) -> dict:
    """Handle income-related queries"""
    try:
        from datetime import datetime, timedelta
        from sqlalchemy import func, and_
        
        # Determine time period
        now = datetime.now()
        if 'last month' in query.lower():
            start_date = (now.replace(day=1) - timedelta(days=1)).replace(day=1)
            end_date = now.replace(day=1)
            period_desc = "last month"
        elif 'this month' in query.lower():
            start_date = now.replace(day=1)
            end_date = now
            period_desc = "this month"
        elif 'last week' in query.lower():
            start_date = now - timedelta(days=now.weekday() + 7)
            end_date = start_date + timedelta(days=7)
            period_desc = "last week"
        elif 'this week' in query.lower():
            start_date = now - timedelta(days=now.weekday())
            end_date = now
            period_desc = "this week"
        else:
            # Default to all time
            start_date = None
            end_date = None
            period_desc = "all time"
        
        # Build query
        income_query = Transaction.query.filter_by(
            user_id=user.id,
            type='income'
        )
        
        if start_date and end_date:
            income_query = income_query.filter(
                and_(Transaction.date >= start_date, Transaction.date < end_date)
            )
        
        # Get total income
        total_income = income_query.with_entities(func.sum(Transaction.amount)).scalar() or 0
        
        # Get detailed breakdown
        income_details = income_query.with_entities(
            Transaction.description,
            func.sum(Transaction.amount).label('total'),
            func.count(Transaction.id).label('count')
        ).group_by(Transaction.description).all()
        
        # Format response
        response = f"📊 **Income Summary for {period_desc.title()}**\n\n"
        response += f"💰 **Total Income:** ${total_income:,.2f}\n\n"
        
        if income_details:
            response += "**Breakdown by Description:**\n"
            for description, total, count in income_details:
                response += f"• {description or 'Uncategorized'}: ${total:,.2f} ({count} transactions)\n"
        else:
            response += "No income transactions found for this period."
        
        # Prepare data for table display
        table_data = []
        for description, total, count in income_details:
            table_data.append({
                'description': description or 'Uncategorized',
                'amount': f"${total:,.2f}",
                'transactions': count
            })
        
        return {
            'success': True,
            'response': response,
            'data': table_data,
            'sql_query': f"SELECT description, SUM(amount) as total, COUNT(*) as count FROM transaction WHERE user_id = {user.id} AND type = 'income' AND date >= '{start_date}' AND date < '{end_date}' GROUP BY description"
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': f'Error processing income query: {str(e)}',
            'data': None,
            'sql_query': None
        }

def handle_expense_query(query: str, user) -> dict:
    """Handle expense-related queries"""
    try:
        from datetime import datetime, timedelta
        from sqlalchemy import func, and_
        
        # Determine time period
        now = datetime.now()
        if 'last month' in query.lower():
            start_date = (now.replace(day=1) - timedelta(days=1)).replace(day=1)
            end_date = now.replace(day=1)
            period_desc = "last month"
        elif 'this month' in query.lower():
            start_date = now.replace(day=1)
            end_date = now
            period_desc = "this month"
        else:
            start_date = None
            end_date = None
            period_desc = "all time"
        
        # Build query
        expense_query = Transaction.query.filter_by(
            user_id=user.id,
            type='expense'
        )
        
        if start_date and end_date:
            expense_query = expense_query.filter(
                and_(Transaction.date >= start_date, Transaction.date < end_date)
            )
        
        # Get total expenses
        total_expenses = expense_query.with_entities(func.sum(Transaction.amount)).scalar() or 0
        
        # Get detailed breakdown
        expense_details = expense_query.with_entities(
            Transaction.description,
            func.sum(Transaction.amount).label('total'),
            func.count(Transaction.id).label('count')
        ).group_by(Transaction.description).all()
        
        # Format response
        response = f"💸 **Expense Summary for {period_desc.title()}**\n\n"
        response += f"💸 **Total Expenses:** ${total_expenses:,.2f}\n\n"
        
        if expense_details:
            response += "**Breakdown by Description:**\n"
            for description, total, count in expense_details:
                response += f"• {description or 'Uncategorized'}: ${total:,.2f} ({count} transactions)\n"
        else:
            response += "No expense transactions found for this period."
        
        # Prepare data for table display
        table_data = []
        for description, total, count in expense_details:
            table_data.append({
                'description': description or 'Uncategorized',
                'amount': f"${total:,.2f}",
                'transactions': count
            })
        
        return {
            'success': True,
            'response': response,
            'data': table_data,
            'sql_query': f"SELECT description, SUM(amount) as total, COUNT(*) as count FROM transaction WHERE user_id = {user.id} AND type = 'expense' AND date >= '{start_date}' AND date < '{end_date}' GROUP BY description"
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': f'Error processing expense query: {str(e)}',
            'data': None,
            'sql_query': None
        }

def handle_balance_query(query: str, user) -> dict:
    """Handle balance-related queries"""
    try:
        from sqlalchemy import func
        
        # Get current balance
        total_income = Transaction.query.filter_by(
            user_id=user.id,
            type='income'
        ).with_entities(func.sum(Transaction.amount)).scalar() or 0
        
        total_expenses = Transaction.query.filter_by(
            user_id=user.id,
            type='expense'
        ).with_entities(func.sum(Transaction.amount)).scalar() or 0
        
        # Get initial balance
        initial_balance = InitialBalance.query.filter_by(user_id=user.id).first()
        initial_amount = initial_balance.balance if initial_balance else 0
        
        current_balance = initial_amount + total_income - total_expenses
        
        # Format response
        response = f"💰 **Current Account Balance**\n\n"
        response += f"🏦 **Current Balance:** ${current_balance:,.2f}\n\n"
        response += f"📊 **Breakdown:**\n"
        response += f"• Initial Balance: ${initial_amount:,.2f}\n"
        response += f"• Total Income: ${total_income:,.2f}\n"
        response += f"• Total Expenses: ${total_expenses:,.2f}\n"
        response += f"• Net Change: ${total_income - total_expenses:,.2f}"
        
        # Prepare data for table display
        table_data = [{
            'type': 'Initial Balance',
            'amount': f"${initial_amount:,.2f}"
        }, {
            'type': 'Total Income',
            'amount': f"${total_income:,.2f}"
        }, {
            'type': 'Total Expenses',
            'amount': f"${total_expenses:,.2f}"
        }, {
            'type': 'Current Balance',
            'amount': f"${current_balance:,.2f}"
        }]
        
        return {
            'success': True,
            'response': response,
            'data': table_data,
            'sql_query': f"SELECT 'Income' as type, SUM(amount) as total FROM transaction WHERE user_id = {user.id} AND type = 'income' UNION ALL SELECT 'Expense' as type, SUM(amount) as total FROM transaction WHERE user_id = {user.id} AND type = 'expense'"
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': f'Error processing balance query: {str(e)}',
            'data': None,
            'sql_query': None
        }

def handle_transaction_query(query: str, user) -> dict:
    """Handle transaction-related queries"""
    try:
        from datetime import datetime, timedelta
        
        # Determine time period and limit
        now = datetime.now()
        limit = 10  # Default limit
        
        if 'last month' in query.lower():
            start_date = (now.replace(day=1) - timedelta(days=1)).replace(day=1)
            end_date = now.replace(day=1)
            period_desc = "last month"
        elif 'this month' in query.lower():
            start_date = now.replace(day=1)
            end_date = now
            period_desc = "this month"
        elif 'recent' in query.lower() or 'latest' in query.lower():
            start_date = None
            end_date = None
            period_desc = "recent"
        else:
            start_date = None
            end_date = None
            period_desc = "all time"
            limit = 20
        
        # Build query
        transaction_query = Transaction.query.filter_by(user_id=user.id)
        
        if start_date and end_date:
            transaction_query = transaction_query.filter(
                Transaction.date >= start_date,
                Transaction.date < end_date
            )
        
        transactions = transaction_query.order_by(Transaction.date.desc()).limit(limit).all()
        
        # Format response
        response = f"📋 **Transaction History ({period_desc.title()})**\n\n"
        
        if transactions:
            response += f"Showing {len(transactions)} transactions:\n\n"
            for txn in transactions:
                emoji = "💰" if txn.type == 'income' else "💸"
                response += f"{emoji} **{txn.description}** - ${txn.amount:,.2f}\n"
                response += f"   Type: {txn.type.title()} | Date: {txn.date}\n\n"
        else:
            response += "No transactions found for this period."
        
        # Prepare data for table display
        table_data = []
        for txn in transactions:
            table_data.append({
                'description': txn.description,
                'type': txn.type.title(),
                'amount': f"${txn.amount:,.2f}",
                'date': txn.date
            })
        
        return {
            'success': True,
            'response': response,
            'data': table_data,
            'sql_query': f"SELECT * FROM transaction WHERE user_id = {user.id} ORDER BY date DESC LIMIT {limit}"
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': f'Error processing transaction query: {str(e)}',
            'data': None,
            'sql_query': None
        }

def handle_category_query(query: str, user) -> dict:
    """Handle category-related queries"""
    try:
        from sqlalchemy import func
        
        # Get all descriptions with totals
        description_data = Transaction.query.filter_by(user_id=user.id).with_entities(
            Transaction.description,
            Transaction.type,
            func.sum(Transaction.amount).label('total'),
            func.count(Transaction.id).label('count')
        ).group_by(Transaction.description, Transaction.type).all()
        
        # Format response
        response = f"📊 **Transaction Breakdown by Description**\n\n"
        
        if description_data:
            # Group by description
            descriptions = {}
            for description, txn_type, total, count in description_data:
                if description not in descriptions:
                    descriptions[description] = {'income': 0, 'expense': 0, 'income_count': 0, 'expense_count': 0}
                
                if txn_type == 'income':
                    descriptions[description]['income'] = total
                    descriptions[description]['income_count'] = count
                else:
                    descriptions[description]['expense'] = total
                    descriptions[description]['expense_count'] = count
            
            for description, data in descriptions.items():
                description_name = description or 'Uncategorized'
                response += f"📁 **{description_name}**\n"
                if data['income'] > 0:
                    response += f"   💰 Income: ${data['income']:,.2f} ({data['income_count']} transactions)\n"
                if data['expense'] > 0:
                    response += f"   💸 Expenses: ${data['expense']:,.2f} ({data['expense_count']} transactions)\n"
                response += "\n"
        else:
            response += "No transaction data found."
        
        # Prepare data for table display
        table_data = []
        descriptions = {}
        for description, txn_type, total, count in description_data:
            if description not in descriptions:
                descriptions[description] = {'income': 0, 'expense': 0, 'income_count': 0, 'expense_count': 0}
            
            if txn_type == 'income':
                descriptions[description]['income'] = total
                descriptions[description]['income_count'] = count
            else:
                descriptions[description]['expense'] = total
                descriptions[description]['expense_count'] = count
        
        for description, data in descriptions.items():
            table_data.append({
                'description': description or 'Uncategorized',
                'income': f"${data['income']:,.2f}",
                'expenses': f"${data['expense']:,.2f}",
                'net': f"${data['income'] - data['expense']:,.2f}"
            })
        
        return {
            'success': True,
            'response': response,
            'data': table_data,
            'sql_query': f"SELECT description, type, SUM(amount) as total, COUNT(*) as count FROM transaction WHERE user_id = {user.id} GROUP BY description, type"
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': f'Error processing category query: {str(e)}',
            'data': None,
            'sql_query': None
        }

############################
# Simple rate limiting (admin)
############################
_admin_rate_limit_bucket = {}

def admin_rate_limit(key_prefix: str, max_requests: int = 30, window_seconds: int = 60):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = getattr(current_user, 'id', 'anon')
            now = time.time()
            bucket_key = f"{key_prefix}:{user_id}"
            window = _admin_rate_limit_bucket.get(bucket_key, [])
            window = [ts for ts in window if now - ts < window_seconds]
            if len(window) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429
            window.append(now)
            _admin_rate_limit_bucket[bucket_key] = window
            return func(*args, **kwargs)
        return wrapper
    return decorator

############################
# Admin Routes
############################

@app.route('/admin/users', methods=['GET'])
@admin_required
@admin_rate_limit('admin_users_list', max_requests=60, window_seconds=60)
def admin_users():
    page = request.args.get('page', 1, type=int)
    raw_per_page = request.args.get('per_page', 20, type=int)
    per_page = max(1, min(raw_per_page, 100))
    search = (request.args.get('q') or '')[:100]
    role_filter = request.args.get('role')

    users_page, roles_map = get_users_with_roles(page=page, per_page=per_page, search=search, role_filter=role_filter)
    stats = get_user_statistics()

    # Roles current admin can assign
    available_roles = get_available_roles_for_admin(current_user)

    # Adapt to current get_users_with_roles() return structure
    try:
        pagination = type('Pagination', (), {})()
        setattr(pagination, 'page', users_page.get('page', page))
        setattr(pagination, 'pages', users_page.get('pages', 1))
        setattr(pagination, 'per_page', per_page)
        setattr(pagination, 'total', users_page.get('total', 0))
        users_list = users_page.get('items', [])
    except Exception:
        # Fallback if a real Pagination object is returned
        pagination = users_page
        users_list = getattr(users_page, 'items', [])

    return render_template(
        'admin/users.html',
        users=users_list,
        pagination=pagination,
        roles_map=roles_map,
        stats=stats,
        search=search or '',
        role_filter=role_filter or '',
        available_roles=available_roles,
        user=current_user
    )

@app.route('/admin/assign-role', methods=['POST'])
@admin_required
@admin_rate_limit('admin_assign_role', max_requests=20, window_seconds=60)
def admin_assign_role():
    try:
        data = request.get_json() or request.form
        user_id = int(data.get('user_id'))
        role_name = (data.get('role_name') or '').strip()
        action = (data.get('action') or 'assign').strip()

        target_user = User.query.get(user_id)
        if not target_user:
            return jsonify({'error': 'User not found'}), 404

        valid, message = validate_role_assignment(current_user, target_user, role_name, action)
        if not valid:
            return jsonify({'error': message}), 400

        if action == 'assign':
            success = assign_role(target_user, role_name)
            action_label = 'assign_role'
            err = None
        else:
            success = remove_role(target_user, role_name)
            action_label = 'remove_role'
            err = None

        if not success:
            return jsonify({'error': err or 'Operation failed'}), 400

        # Sync user preferences with new role configuration
        try:
            update_user_preferences_on_role_change(target_user)
        except Exception:
            pass

        log_admin_action(current_user, action_label, target_user, {'role': role_name})
        return jsonify({'success': True, 'user_id': user_id, 'role': role_name, 'action': action})
    except Exception as e:
        current_app.logger.error(f"Admin role change error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/user/<int:user_id>', methods=['GET'])
@admin_required
@admin_rate_limit('admin_user_detail', max_requests=60, window_seconds=60)
def admin_user_detail(user_id: int):
    user_obj = User.query.get_or_404(user_id)
    summary = get_user_transaction_summary(user_id)
    role_history = get_user_role_history(user_id)
    current_roles = get_user_roles(user_obj)
    available_roles = get_available_roles_for_admin(current_user)

    return render_template(
        'admin/user_detail.html',
        target_user=user_obj,
        summary=summary,
        role_history=role_history,
        current_roles=current_roles,
        available_roles=available_roles,
        user=current_user
    )

@app.route('/admin/dashboard', methods=['GET'])
@admin_required
@admin_rate_limit('admin_dashboard', max_requests=60, window_seconds=60)
def admin_dashboard():
    stats = get_user_statistics()
    # These keys are expected by the dashboard template for charts
    trends = {
        'registrations': [],
        'labels': []
    }
    try:
        from src.admin_utils import get_registration_trends
        trends_data = get_registration_trends(months=12)
        trends['labels'] = [t['label'] for t in trends_data]
        trends['registrations'] = [t['count'] for t in trends_data]
    except Exception:
        pass

    return render_template('admin/dashboard.html', stats=stats, trends=trends, user=current_user)

@app.route('/admin/users/export', methods=['GET'])
@admin_required
@admin_rate_limit('admin_users_export', max_requests=10, window_seconds=60)
def admin_users_export():
    export_format = request.args.get('format', 'csv')
    filters = {
        'q': request.args.get('q'),
        'role': request.args.get('role')
    }
    try:
        output, mimetype, filename = export_user_data(format=export_format, filters=filters)
        return send_file(output, mimetype=mimetype, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/admin/reports', methods=['GET'])
@admin_required
def admin_reports():
    """Admin reports page"""
    try:
        # Get basic statistics for reports
        total_users = User.query.count()
        total_transactions = Transaction.query.count()
        total_balance = db.session.query(db.func.sum(Transaction.amount)).scalar() or 0
        
        # Get recent activity
        recent_transactions = Transaction.query.order_by(Transaction.date.desc()).limit(10).all()
        
        return render_template('admin/reports.html', 
                             total_users=total_users,
                             total_transactions=total_transactions,
                             total_balance=total_balance,
                             recent_transactions=recent_transactions)
    except Exception as e:
        flash(f'Error loading reports: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    """Admin settings page"""
    if request.method == 'POST':
        try:
            # Handle settings updates here
            # This is a placeholder for actual settings management
            flash('Settings updated successfully', 'success')
            return redirect(url_for('admin_settings'))
        except Exception as e:
            flash(f'Error updating settings: {str(e)}', 'error')
    
    try:
        # Get current settings
        # This is a placeholder for actual settings retrieval
        settings = {
            'site_name': 'FlowTrack',
            'maintenance_mode': False,
            'registration_enabled': True,
            'require_2fa': False,
            'session_timeout': 30,
            'max_login_attempts': 5,
            'ai_analysis_enabled': True,
            'ai_forecasting_enabled': True,
            'ai_chatbot_enabled': True,
            'ai_risk_assessment_enabled': True
        }
        
        # System information
        import sys
        import flask
        from datetime import datetime
        
        context = {
            'settings': settings,
            'python_version': sys.version.split()[0],
            'flask_version': flask.__version__,
            'uptime': '24 hours'  # Placeholder
        }
        
        return render_template('admin/settings.html', **context)
    except Exception as e:
        flash(f'Error loading settings: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.errorhandler(403)
def forbidden_error(error):
    has_admin_dashboard = 'admin_dashboard' in current_app.view_functions
    return render_template('errors/403.html', has_admin_dashboard=has_admin_dashboard), 403

@app.route('/admin/sync-user-preferences', methods=['POST'])
@super_admin_required
def admin_sync_user_preferences():
    """Sync all users' preferences with their current roles.

    Ensures super admins (and admins) have their default AI modules enabled
    without removing any manually enabled modules.
    """
    try:
        updated_count = 0
        users = User.query.all()
        for user in users:
            prefs = UserPreferences.query.filter_by(user_id=user.id).first()
            if not prefs:
                prefs = UserPreferences(user_id=user.id)
                db.session.add(prefs)
                db.session.flush()
            changed = False
            try:
                changed = prefs.ensure_role_based_modules(user)
            except Exception:
                # If any error occurs during ensure, skip this user but continue
                changed = False
            if changed:
                updated_count += 1
        db.session.commit()
        return jsonify({'success': True, 'updated_users': updated_count}), 200
    except SQLAlchemyError as db_err:
        db.session.rollback()
        current_app.logger.error(f"DB error during preferences sync: {str(db_err)}")
        return jsonify({'success': False, 'error': 'Database error during sync'}), 500
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Unexpected error during preferences sync: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/ai/analysis-report')
@login_required
def ai_analysis_report_page():
    """Dedicated page to run and display AI analysis without impacting other pages."""
    return render_template('ai_results.html', analysis_type='analysis_report', timestamp=datetime.now().isoformat())

@app.route('/cashflow/statement/view')
@login_required
def cashflow_statement_view():
    """Dedicated web report for cash flow statement similar to QuickBooks, with interactive details."""
    return render_template('ai_advanced_forecast.html')

if __name__ == '__main__':
    app.run(debug=True)
