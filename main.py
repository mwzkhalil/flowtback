"""
FlowTrack - Financial Management Application
Main application file with modular route structure.
"""

import os
import sys
import secrets
import tempfile
from datetime import datetime
from flask import Flask, request, jsonify, send_file, current_app, session, abort, g
from flask_cors import CORS
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# from flask_wtf.csrf import CSRFProtect  # Disabled for API testing
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from typing_extensions import Annotated
from src.models import db, User, Transaction, InitialBalance, UserPreferences, Tenant
from sqlalchemy.exc import OperationalError
from src.forms import LoginForm, RegistrationForm
from src.anthropic_service import FinancialAnalytics
from src.upload_handler import process_upload
from src.utils import calculate_totals, calculate_burn_rate, calculate_runway
from src.rbac import assign_default_role, assign_role, remove_role, get_user_roles, update_user_preferences_on_role_change
from src.auth_decorators import (
    super_admin_required, admin_required, admin_or_super_admin_required,
    transaction_owner_or_admin_required, authenticated_only
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
from datetime import datetime, timedelta
import calendar
from flask_migrate import Migrate
from flask_babel import Babel
import time
from functools import wraps
from datetime import datetime, timedelta
import time
import logging
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
from src.currency_service import init_currency_service, get_currency_service
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.routing import BuildError

# Import route blueprints
from routes import (
    auth_bp, admin_bp, transaction_bp, ai_bp, api_bp, 
    bank_bp, dashboard_bp, upload_bp, report_bp, settings_bp
)

# Load .env file explicitly at the start
load_dotenv()

# Ensure instance folder exists
instance_path = os.path.join(os.path.dirname(__file__),'instance')
os.makedirs(instance_path, exist_ok=True)

upload_path = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(upload_path, exist_ok=True)

# Initialize extensions
login_manager = LoginManager()
limiter = Limiter(key_func=get_remote_address)
migrate = Migrate()
babel = Babel()

# Helper functions for file uploads and CSRF validation
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

def validate_csrf_header():
    """Validate CSRF token from request headers - DISABLED for API testing."""
    # CSRF validation disabled for API testing
    return True

def get_locale():
    # First check if a language is stored in the session
    if 'language' in session:
        lang = session['language']
        return lang
        
    # Otherwise fallback to browser preference
    browser_lang = request.accept_languages.best_match(['en', 'es', 'ja', 'ar', 'ru', 'zh'])
    return browser_lang

def create_app(skip_schema_validation=False, start_services=True):
    """Create and configure Flask application factory.
    
    Args:
        skip_schema_validation (bool): Skip database schema validation on startup
        start_services (bool): Start background services like scheduler
        
    Returns:
        tuple: (app, db) - Flask app instance and database instance
    """
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')
    app.config.from_object(Config)
    app.config.setdefault('UPLOAD_FOLDER', os.path.join(os.path.dirname(__file__), 'uploads'))

    # Initialize rate limiter with Redis storage
    limiter.init_app(app)

    # Initialize CORS for frontend communication
    CORS(app, origins=['http://localhost:3000', 'http://localhost:5173', 'http://localhost:4200'], 
         supports_credentials=True)

    db.init_app(app)
    migrate.init_app(app, db)
    babel.init_app(app, locale_selector=get_locale)

    def validate_database_schema():
        """Validate database schema consistency before application startup.
        
        Checks for required currency columns in the transaction table and provides
        clear error messages if schema is out of sync with model definitions.
        
        Returns:
            bool: True if schema is valid, False otherwise
        """
        try:
            with app.app_context():
                from sqlalchemy import text, inspect
                
                # Check if transaction table exists
                inspector = inspect(db.engine)
                table_names = inspector.get_table_names()
                
                if 'transaction' not in table_names:
                    app.logger.error("Transaction table does not exist in database")
                    return False
                
                # Check for required currency columns
                columns = inspector.get_columns('transaction')
                column_names = [col['name'] for col in columns]
                
                required_currency_columns = [
                    'original_currency',
                    'original_amount', 
                    'base_currency_amount',
                    'exchange_rate',
                    'rate_date',
                    'currency_conversion_status'
                ]
                
                missing_columns = [col for col in required_currency_columns if col not in column_names]
                
                if missing_columns:
                    app.logger.error(f"Missing required currency columns: {missing_columns}")
                    app.logger.error("Database schema is out of sync with model definitions")
                    app.logger.error("This usually indicates missing migrations")
                    return False
                
                # Check for expected indexes
                indexes = inspector.get_indexes('transaction')
                index_names = [idx['name'] for idx in indexes]
                
                expected_indexes = [
                    'ix_transaction_original_currency',
                    'ix_transaction_currency_conversion_status'
                ]
                
                missing_indexes = [idx for idx in expected_indexes if idx not in index_names]
                
                if missing_indexes:
                    app.logger.warning(f"Missing expected indexes: {missing_indexes}")
                    app.logger.warning("Performance may be affected")
                
                return True
                
        except Exception as e:
            app.logger.error(f"Error validating database schema: {str(e)}")
            return False

    # Validate database schema unless explicitly skipped
    if not skip_schema_validation:
        if not validate_database_schema():
            app.logger.error("Database schema validation failed")
            sys.exit(1)

    # Initialize login manager
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'

    # Initialize currency service
    init_currency_service(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(transaction_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(bank_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(upload_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(settings_bp)

    @app.context_processor
    def inject_role_context():
        """Inject role context into templates."""
        if current_user.is_authenticated:
            user_roles = get_user_roles(current_user.id)
            role_names = [role.name for role in user_roles]
            
            return {
                'user_roles': role_names,
                'is_admin': 'admin' in role_names or 'super_admin' in role_names,
                'is_super_admin': 'super_admin' in role_names
            }
        return {
            'user_roles': [],
            'is_admin': False,
            'is_super_admin': False
        }

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Enhanced helper function for AI navigation context
    def get_ai_navigation_context(current_page, page_title=None, page_subtitle=None, page_description=None):
        """Generate navigation context for AI pages."""
        ai_pages = {
            'ai_analysis': {
                'title': 'AI Analysis',
                'subtitle': 'Intelligent Financial Insights',
                'description': 'Get AI-powered analysis of your financial data',
                'icon': 'fas fa-brain',
                'url': '/ai-analysis'
            },
            'ai_cashflow': {
                'title': 'Cashflow Analysis',
                'subtitle': 'Smart Cashflow Insights',
                'description': 'AI-driven cashflow analysis and predictions',
                'icon': 'fas fa-chart-line',
                'url': '/ai-analysis/cashflow'
            },
            'ai_risk': {
                'title': 'Risk Assessment',
                'subtitle': 'Financial Risk Analysis',
                'description': 'Identify and assess financial risks',
                'icon': 'fas fa-shield-alt',
                'url': '/ai-analysis/risk'
            },
            'ai_anomaly': {
                'title': 'Anomaly Detection',
                'subtitle': 'Detect Unusual Patterns',
                'description': 'Find anomalies in your financial data',
                'icon': 'fas fa-exclamation-triangle',
                'url': '/ai-analysis/anomaly'
            },
            'ai_forecast': {
                'title': 'Financial Forecast',
                'subtitle': 'Predict Future Trends',
                'description': 'AI-powered financial forecasting',
                'icon': 'fas fa-crystal-ball',
                'url': '/ai-analysis/forecast'
            },
            'ai_dashboard': {
                'title': 'AI Dashboard',
                'subtitle': 'Comprehensive AI Insights',
                'description': 'Complete AI-powered financial dashboard',
                'icon': 'fas fa-tachometer-alt',
                'url': '/ai-analysis/dashboard'
            },
            'ai_assistant': {
                'title': 'AI Assistant',
                'subtitle': 'Interactive Financial Assistant',
                'description': 'Chat with AI for financial insights',
                'icon': 'fas fa-robot',
                'url': '/ai-analysis/assistant'
            }
        }
        
        context = {
            'current_page': current_page,
            'page_title': page_title or ai_pages.get(current_page, {}).get('title', 'AI Analysis'),
            'page_subtitle': page_subtitle or ai_pages.get(current_page, {}).get('subtitle', ''),
            'page_description': page_description or ai_pages.get(current_page, {}).get('description', ''),
            'ai_pages': ai_pages,
            'navigation_items': []
        }
        
        # Build navigation items
        for page_key, page_info in ai_pages.items():
            context['navigation_items'].append({
                'key': page_key,
                'title': page_info['title'],
                'url': page_info['url'],
                'icon': page_info['icon'],
                'active': page_key == current_page
            })
        
        return context

    def performance_monitor(f):
        """Decorator to monitor route performance"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            start_time = time.time()
            result = f(*args, **kwargs)
            end_time = time.time()
            
            # Log performance metrics
            app.logger.info(f"Route {request.endpoint} took {end_time - start_time:.4f} seconds")
            
            return result
        return decorated_function

    def log_route_error(route_name, error, user_id=None):
        """Log route errors with context"""
        error_info = {
            'route': route_name,
            'error': str(error),
            'user_id': user_id,
            'timestamp': datetime.now().isoformat(),
            'request_data': {
                'method': request.method,
                'url': request.url,
                'args': dict(request.args),
                'form': dict(request.form) if request.form else None
            }
        }
        app.logger.error(f"Route error: {error_info}")

    @app.context_processor
    def inject_tenant_branding():
        """Inject tenant branding into templates."""
        try:
            if current_user.is_authenticated and hasattr(current_user, 'tenant_id') and current_user.tenant_id:
                tenant = Tenant.query.get(current_user.tenant_id)
                if tenant:
                    return {
                        'tenant_name': tenant.name,
                        'tenant_logo': tenant.logo_url,
                        'tenant_primary_color': tenant.primary_color,
                        'tenant_secondary_color': tenant.secondary_color,
                        'tenant_custom_css': tenant.custom_css
                    }
        except Exception:
            pass
        
        return {
            'tenant_name': 'FlowTrack',
            'tenant_logo': None,
            'tenant_primary_color': '#007bff',
            'tenant_secondary_color': '#6c757d',
            'tenant_custom_css': None
        }

    @app.before_request
    def load_current_tenant_into_g():
        """Load current tenant into Flask g object for easy access."""
        if current_user.is_authenticated and hasattr(current_user, 'tenant_id') and current_user.tenant_id:
            g.current_tenant = Tenant.query.get(current_user.tenant_id)
        else:
            g.current_tenant = None

    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses."""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

    @app.context_processor
    def inject_tenant_options():
        """Inject tenant-specific options into templates."""
        try:
            if hasattr(g, 'current_tenant') and g.current_tenant:
                return {
                    'tenant_options': {
                        'enable_ai_features': g.current_tenant.enable_ai_features,
                        'enable_bank_connections': g.current_tenant.enable_bank_connections,
                        'enable_collaboration': g.current_tenant.enable_collaboration,
                        'max_users': g.current_tenant.max_users,
                        'custom_domain': g.current_tenant.custom_domain
                    }
                }
        except Exception:
            pass
        
        return {
            'tenant_options': {
                'enable_ai_features': True,
                'enable_bank_connections': True,
                'enable_collaboration': True,
                'max_users': 100,
                'custom_domain': None
            }
        }

    @app.context_processor
    def inject_current_app_proxy():
        # Provide safe access to common config values without exposing the whole app object
        return {
            'app_config': {
                'debug': current_app.debug,
                'testing': current_app.testing,
                'secret_key': current_app.secret_key[:8] + '...' if current_app.secret_key else None,
                'upload_folder': current_app.config.get('UPLOAD_FOLDER', 'uploads'),
                'max_content_length': current_app.config.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024),
                'supported_languages': ['en', 'es', 'ja', 'ar', 'ru', 'zh'],
                'default_language': 'en',
                'currency_service_enabled': current_app.config.get('CURRENCY_SERVICE_ENABLED', True),
                'ai_service_enabled': current_app.config.get('AI_SERVICE_ENABLED', True),
                'bank_service_enabled': current_app.config.get('BANK_SERVICE_ENABLED', True)
            }
        }

    @app.context_processor
    def inject_url_helpers():
        def endpoint_exists(name: str) -> bool:
            """Check if a route endpoint exists"""
            return name in current_app.view_functions

        def url_or(endpoint: str, **values):
            """Generate URL for endpoint or return None if it doesn't exist"""
            try:
                return url_for(endpoint, **values)
            except BuildError:
                return None

        return {
            'endpoint_exists': endpoint_exists,
            'url_or': url_or
        }

    @app.context_processor
    def inject_currency_context():
        """Inject currency context into templates."""
        try:
            currency_service = get_currency_service()
            if currency_service:
                return {
                    'currency_service': {
                        'enabled': True,
                        'base_currency': currency_service.get_base_currency(),
                        'supported_currencies': currency_service.get_supported_currencies(),
                        'last_updated': currency_service.get_last_update_time(),
                        'rates': currency_service.get_current_rates()
                    }
                }
        except Exception:
            pass
        
        return {
            'currency_service': {
                'enabled': False,
                'base_currency': 'USD',
                'supported_currencies': ['USD'],
                'last_updated': None,
                'rates': {}
            }
        }

    @app.template_filter('datetimeformat')
    def datetimeformat(value, fmt='%Y-%m-%d %H:%M'):
        """Format datetime values in templates."""
        if value is None:
            return ''
        try:
            if isinstance(value, str):
                value = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return value.strftime(fmt)
        except (ValueError, AttributeError):
            return str(value)

    @app.template_filter('currencyformat')
    def currencyformat(value, currency='USD'):
        """Format currency values in templates."""
        if value is None:
            return f'$0.00'
        try:
            return f'${float(value):,.2f}'
        except (ValueError, TypeError):
            return str(value)

    @app.template_filter('percentageformat')
    def percentageformat(value, decimals=2):
        """Format percentage values in templates."""
        if value is None:
            return '0%'
        try:
            return f'{float(value):.{decimals}f}%'
        except (ValueError, TypeError):
            return str(value)

    def validate_csrf_header_if_enabled() -> bool:
        """Validate CSRF header if CSRF protection is enabled - DISABLED for API testing."""
        # CSRF validation disabled for API testing
        return True

    # Error handlers
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return jsonify({'error': 'Too many requests'}), 429

    @app.errorhandler(403)
    def forbidden_error(error):
        return jsonify({'error': 'Forbidden', 'message': 'Access denied'}), 403

    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({'error': 'Not found', 'message': 'Resource not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return jsonify({'error': 'Internal server error', 'message': 'An unexpected error occurred'}), 500

    @app.errorhandler(Exception)
    def handle_exception(e):
        """Handle all exceptions and return JSON responses."""
        app.logger.error(f"Unhandled error: {str(e)}")
        app.logger.error(f"Error type: {type(e)}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")

        return jsonify({
            'error': 'Internal server error',
            'message': 'An unexpected error occurred. Please try again later.',
            'type': type(e).__name__
        }), 500

    # Start background services if requested
    if start_services:
        try:
            from src.scheduler import BankScheduler
            scheduler = BankScheduler(app)
            scheduler.initialize_scheduler(app)
            scheduler.start_scheduler()
            app.logger.info("Background scheduler started")
        except Exception as e:
            app.logger.warning(f"Failed to start scheduler: {str(e)}")

    return app, db

# Create app instance
app, db = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
