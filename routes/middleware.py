"""
Middleware system for FlowTrack application.
Handles authentication, authorization, and route restrictions.
"""

from functools import wraps
from flask import request, jsonify, redirect, url_for, flash, current_app
from flask_login import current_user
from src.auth_decorators import (
    super_admin_required, admin_required, admin_or_super_admin_required,
    transaction_owner_or_admin_required, authenticated_only
)
from src.rbac import get_user_roles
from werkzeug.exceptions import Forbidden, Unauthorized
import logging

logger = logging.getLogger(__name__)

def login_required(f):
    """Decorator to require user authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            if request.is_json:
                return jsonify({'error': 'Authentication required'}), 401
            flash('Please log in to access this page', 'info')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(required_roles):
    """Decorator to require specific roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                if request.is_json:
                    return jsonify({'error': 'Authentication required'}), 401
                flash('Please log in to access this page', 'info')
                return redirect(url_for('auth.login'))
            
            user_roles = get_user_roles(current_user.id)
            user_role_names = [role.name for role in user_roles]
            
            if not any(role in user_role_names for role in required_roles):
                if request.is_json:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                flash('You do not have permission to access this page', 'error')
                return redirect(url_for('dashboard.home'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    """Decorator to require admin role."""
    return role_required(['admin', 'super_admin'])(f)

def super_admin_required(f):
    """Decorator to require super admin role."""
    return role_required(['super_admin'])(f)

def validate_csrf_token(f):
    """Decorator to validate CSRF token for POST requests - DISABLED for API testing."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # CSRF validation disabled for API testing
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(max_requests=60, window_seconds=60):
    """Decorator to implement rate limiting."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Simple in-memory rate limiting
            # In production, use Redis or similar
            from flask_limiter import Limiter
            from flask_limiter.util import get_remote_address
            
            limiter = current_app.extensions.get('limiter')
            if limiter:
                try:
                    limiter.limit(f"{max_requests} per {window_seconds} seconds")(f)(*args, **kwargs)
                except Exception as e:
                    logger.warning(f"Rate limit exceeded for {request.endpoint}: {e}")
                    if request.is_json:
                        return jsonify({'error': 'Rate limit exceeded'}), 429
                    flash('Too many requests. Please try again later.', 'error')
                    return redirect(request.referrer or url_for('dashboard.home'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_access(f):
    """Decorator to log route access."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        logger.info(f"Route accessed: {request.endpoint} by user: {current_user.id if current_user.is_authenticated else 'anonymous'}")
        return f(*args, **kwargs)
    return decorated_function

def handle_errors(f):
    """Decorator to handle common errors."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Unauthorized:
            if request.is_json:
                return jsonify({'error': 'Unauthorized'}), 401
            flash('You must be logged in to access this page', 'error')
            return redirect(url_for('auth.login'))
        except Forbidden:
            if request.is_json:
                return jsonify({'error': 'Forbidden'}), 403
            flash('You do not have permission to access this page', 'error')
            return redirect(url_for('dashboard.home'))
        except Exception as e:
            logger.error(f"Error in route {request.endpoint}: {str(e)}")
            if request.is_json:
                return jsonify({'error': 'Internal server error'}), 500
            flash('An error occurred. Please try again.', 'error')
            return redirect(request.referrer or url_for('dashboard.home'))
    
    return decorated_function

def require_tenant(f):
    """Decorator to require valid tenant context."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(current_user, 'tenant_id') or not current_user.tenant_id:
            if request.is_json:
                return jsonify({'error': 'Tenant context required'}), 400
            flash('Tenant context is required', 'error')
            return redirect(url_for('dashboard.home'))
        return f(*args, **kwargs)
    return decorated_function

def validate_json(f):
    """Decorator to validate JSON requests."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.is_json:
            if not request.get_json():
                return jsonify({'error': 'Invalid JSON'}), 400
        return f(*args, **kwargs)
    return decorated_function

# Legacy decorator compatibility
def transaction_owner_or_admin_required(param_name='transaction_id'):
    """Decorator to require transaction ownership or admin role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                if request.is_json:
                    return jsonify({'error': 'Authentication required'}), 401
                return redirect(url_for('auth.login'))
            
            # Check if user is admin
            user_roles = get_user_roles(current_user.id)
            user_role_names = [role.name for role in user_roles]
            
            if 'admin' in user_role_names or 'super_admin' in user_role_names:
                return f(*args, **kwargs)
            
            # Check transaction ownership
            transaction_id = kwargs.get(param_name)
            if transaction_id:
                from src.models import Transaction
                transaction = Transaction.query.get(transaction_id)
                if transaction and transaction.user_id == current_user.id:
                    return f(*args, **kwargs)
            
            if request.is_json:
                return jsonify({'error': 'Access denied'}), 403
            flash('You do not have permission to access this resource', 'error')
            return redirect(url_for('dashboard.home'))
        
        return decorated_function
    return decorator
