# in `src/auth_decorators.py`
from functools import wraps
from flask import current_app, redirect, url_for, flash, abort, request, render_template
from flask_login import current_user
from src.rbac import (
    require_role,
    require_permission,
    super_admin_required,
    has_role,
    has_permission,
    validate_subscription_tier_access,
)
from src.models import db, Transaction, User
import logging
import time

# Configure logging
logger = logging.getLogger(__name__)

# Enhanced Role Decorators
def admin_required(f):
    """
    Decorator for admin and super_admin access.
    """
    return require_role('admin', 'super_admin')(f)

def user_or_admin_required(f):
    """
    Decorator for user, admin, and super_admin access.
    """
    return require_role('user', 'admin', 'super_admin')(f)

def admin_or_super_admin_required(f):
    """
    Decorator specifically for admin and super_admin roles.
    """
    return admin_required(f)

# Enterprise-grade decorators
def super_admin_only(f):
    """Decorator alias for super admin only operations (clarity)."""
    return super_admin_required(f)

def can_manage_users():
    """Decorator that checks for user management permissions."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
            if not (has_permission(current_user, 'manage_all_users') or has_role(current_user, 'super_admin', 'admin')):
                logger.warning(f"User {getattr(current_user, 'username', 'unknown')} blocked from managing users on {f.__name__}")
                return handle_access_denied("You don't have permission to manage users.")
            return f(*args, **kwargs)
        return decorated
    return decorator

def subscription_tier_required(tier: str):
    """Decorator to restrict access based on subscription tier."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
            if not validate_subscription_tier_access(current_user, tier):
                logger.warning(f"User {getattr(current_user, 'username', 'unknown')} lacks subscription tier {tier} for {f.__name__}")
                return handle_access_denied("Your subscription tier does not allow this feature.")
            return f(*args, **kwargs)
        return decorated
    return decorator

def active_user_required(f):
    """Ensure the user's account is active."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        if hasattr(current_user, 'is_active') and not current_user.is_active:
            logger.warning(f"Inactive user {getattr(current_user, 'username', 'unknown')} attempted to access {f.__name__}")
            return handle_access_denied("Your account is inactive. Contact an administrator.")
        return f(*args, **kwargs)
    return decorated

def company_admin_required(f):
    """Decorator placeholder for company-level admin access."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        if not (has_role(current_user, 'company_admin') or has_role(current_user, 'super_admin')):
            logger.warning(f"User {getattr(current_user, 'username', 'unknown')} is not a company_admin for {f.__name__}")
            return handle_access_denied()
        return f(*args, **kwargs)
    return decorated

def validate_user_access(param_name: str = 'user_id'):
    """Decorator for user-specific operations, allowing self or admin access."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
            target_id = kwargs.get(param_name)
            if target_id is None:
                abort(400)
            try:
                target_id = int(target_id)
            except Exception:
                abort(400)
            if current_user.id != target_id and not has_role(current_user, 'admin', 'super_admin'):
                log_unauthorized_access(current_user, 'user', target_id)
                return handle_access_denied()
            return f(*args, **kwargs)
        return decorated
    return decorator

# Simple in-memory rate limiter per admin for sensitive ops
_ADMIN_RATE_BUCKET: dict[int, list[float]] = {}

def admin_rate_limit(key: str, max_requests: int | None = None, window_seconds: int = 60):
    """Unified key-based admin rate limiting decorator.

    Args:
        key: Logical key for the route (e.g., 'admin_users_list').
        max_requests: Overrides per-minute limit; defaults to config ADMIN_RATE_LIMIT_PER_MINUTE.
        window_seconds: Time window for rate limiting (default 60 seconds).
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
            if not has_role(current_user, 'admin', 'super_admin'):
                return handle_access_denied()
            limit = max_requests or current_app.config.get('ADMIN_RATE_LIMIT_PER_MINUTE', 60)
            now = time.time()
            bucket_key = f"{key}:{getattr(current_user, 'id', 'anon')}"
            bucket = _ADMIN_RATE_BUCKET.setdefault(bucket_key, [])
            cutoff = now - float(window_seconds)
            bucket[:] = [t for t in bucket if t >= cutoff]
            if len(bucket) >= int(limit):
                logger.warning(f"Admin rate limit exceeded by user {getattr(current_user,'id','anon')} on {f.__name__} key={key}")
                return handle_access_denied("Too many admin actions. Please slow down.")
            bucket.append(now)
            return f(*args, **kwargs)
        return decorated
    return decorator

def audit_admin_action(action_name: str):
    """Decorator to automatically log administrative actions."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            resp = f(*args, **kwargs)
            try:
                logger.info(f"Admin action: {action_name} by user={getattr(current_user, 'id', None)} path={request.path}")
            except Exception:
                pass
            return resp
        return decorated
    return decorator

# Data Access Control Decorators
def authenticated_only(f):
    """
    Ensures user is authenticated. For data access control, routes should implement
    their own user-specific filtering logic.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def transaction_owner_or_admin_required(transaction_id_param='transaction_id'):
    """
    Validates transaction ownership or admin privileges.
    
    Args:
        transaction_id_param: Name of the parameter containing transaction ID
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
            
            # Admin and super_admin can access any transaction
            if has_role(current_user, 'admin', 'super_admin'):
                return f(*args, **kwargs)
            
            # Get transaction ID from kwargs
            transaction_id = kwargs.get(transaction_id_param)
            if not transaction_id:
                logger.error(f"Transaction ID not found in parameter: {transaction_id_param}")
                abort(400)
            
            # Check transaction ownership
            transaction = db.session.get(Transaction, transaction_id)
            if not transaction:
                logger.warning(f"Transaction {transaction_id} not found")
                abort(404)
            
            if transaction.user_id != current_user.id:
                logger.warning(f"User {current_user.username} attempted to access transaction {transaction_id} owned by user {transaction.user_id}")
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Permission-Based Decorators
def require_view_all_transactions(f):
    """
    For routes that show all user data.
    """
    return require_permission('view_all_transactions')(f)

def require_manage_users(f):
    """
    For user management routes.
    """
    return require_permission('manage_users')(f)

def require_advanced_ai(f):
    """
    For advanced AI features.
    """
    return require_permission('access_advanced_ai')(f)

# Error Handling and Logging
def log_unauthorized_access(user, resource_type, resource_id=None):
    """
    Log unauthorized access attempts for security auditing.
    """
    resource_info = f"{resource_type}"
    if resource_id:
        resource_info += f" (ID: {resource_id})"
    
    logger.warning(f"Unauthorized access attempt by user {user.username} to {resource_info}")

def handle_access_denied(message="You don't have permission to access this resource."):
    """
    Handle access denied with proper error response.
    """
    logger.warning(f"Access denied for user {current_user.username if current_user.is_authenticated else 'anonymous'}")
    try:
        return render_template('errors/403.html', message=message), 403
    except Exception:
        # Fallback minimal response if template is unavailable
        from flask import Response
        return Response(message or "Forbidden", status=403)

# Export the enhanced decorators
__all__ = [
    "require_role", "require_permission", "super_admin_required",
    "admin_required", "user_or_admin_required", "admin_or_super_admin_required",
    "super_admin_only", "can_manage_users", "subscription_tier_required", "active_user_required",
    "company_admin_required", "validate_user_access", "admin_rate_limit", "audit_admin_action",
    "authenticated_only", "transaction_owner_or_admin_required",
    "require_view_all_transactions", "require_manage_users", "require_advanced_ai",
    "log_unauthorized_access", "handle_access_denied"
]
