from functools import wraps
from flask import current_app, redirect, url_for, flash, abort
from flask_login import current_user
from src.models import db, Role, Permission, User, UserPreferences
import logging
from datetime import datetime
from werkzeug.security import generate_password_hash

# Configure logging
logger = logging.getLogger(__name__)

# ------------------------------
# Audit helper
# ------------------------------
def _audit(action: str, actor_id: int | None, target_id: int | None = None, details: dict | None = None) -> None:
    try:
        current_app.logger.info(
            f"RBAC audit action={action} actor={actor_id} target={target_id} details={details}"
        )
    except Exception:
        logger.info(f"RBAC audit (fallback): {action} actor={actor_id} target={target_id} details={details}")

def has_role(user, *role_names):
    """
    Check if user has any of the specified roles.
    
    Args:
        user: User object to check
        *role_names: Variable number of role names to check for
        
    Returns:
        bool: True if user has any of the specified roles, False otherwise
    """
    if not user or not user.is_authenticated:
        return False
    
    user_role_names = [role.name for role in user.roles]
    return any(role_name in user_role_names for role_name in role_names)

def has_permission(user, permission_name):
    """
    Check if user has a specific permission through their roles.
    
    Args:
        user: User object to check
        permission_name: Name of the permission to check for
        
    Returns:
        bool: True if user has the permission, False otherwise
    """
    if not user or not user.is_authenticated:
        return False
    
    for role in user.roles:
        for permission in role.permissions:
            if permission.name == permission_name:
                return True
    return False

def get_user_roles(user):
    """
    Return list of role names for a user.
    
    Args:
        user: User object
        
    Returns:
        list: List of role names for the user
    """
    if not user or not user.is_authenticated:
        return []
    
    return [role.name for role in user.roles]

def get_user_permissions(user):
    """
    Return list of permission names for a user.
    
    Args:
        user: User object
        
    Returns:
        list: List of permission names for the user
    """
    if not user or not user.is_authenticated:
        return []
    
    permissions = set()
    for role in user.roles:
        for permission in role.permissions:
            permissions.add(permission.name)
    return list(permissions)

def require_role(*role_names):
    """
    Decorator that checks if current_user has any of the specified roles.
    Returns 403 Forbidden if user lacks required role, redirects to login if not authenticated.
    
    Args:
        *role_names: Variable number of role names to check for
        
    Returns:
        function: Decorated function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
            
            if not has_role(current_user, *role_names):
                logger.warning(f"User {current_user.username} attempted to access {f.__name__} without required roles: {role_names}")
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_permission(permission_name):
    """
    Decorator that checks if current_user has the specified permission.
    Provides future-proof granular access control.
    
    Args:
        permission_name: Name of the permission to check for
        
    Returns:
        function: Decorated function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'error')
                return redirect(url_for('login'))
            
            if not has_permission(current_user, permission_name):
                logger.warning(f"User {current_user.username} attempted to access {f.__name__} without required permission: {permission_name}")
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def super_admin_required(f):
    """
    Convenience decorator specifically for super_admin access.
    
    Args:
        f: Function to decorate
        
    Returns:
        function: Decorated function
    """
    return require_role('super_admin')(f)

# Alias for clarity in user management operations
def super_admin_only(f):
    return super_admin_required(f)

# ------------------------------
# Permission convenience checks
# ------------------------------
def can_create_users(user) -> bool:
    return has_permission(user, 'create_users') or has_role(user, 'super_admin')

def can_manage_all_users(user) -> bool:
    return has_permission(user, 'manage_all_users') or has_role(user, 'super_admin')

def can_assign_roles(user) -> bool:
    return has_permission(user, 'assign_roles') or has_role(user, 'super_admin')

def can_view_user_details(user) -> bool:
    return has_permission(user, 'view_user_details') or has_role(user, 'admin', 'super_admin')

def assign_role(user, role_name, commit=False):
    """
    Assign a role to a user.
    
    Args:
        user: User object
        role_name: Name of the role to assign
        commit: Whether to commit the transaction (default: False)
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Prevent privilege escalation: only super_admin can grant super_admin
        if role_name == 'super_admin' and not has_role(current_user, 'super_admin'):
            logger.warning(f"Unauthorized attempt to assign 'super_admin' by {getattr(current_user, 'username', 'unknown')}")
            abort(403)
        # Validate permission to assign roles generally
        if not can_assign_roles(current_user):
            logger.warning(f"User {getattr(current_user, 'username', 'unknown')} lacks permission to assign roles")
            abort(403)
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            logger.error(f"Role '{role_name}' not found")
            return False
        
        if role not in user.roles:
            user.roles.append(role)
            if commit:
                db.session.commit()
            logger.info(f"Assigned role '{role_name}' to user '{user.username}'")
            _audit('assign_role', getattr(current_user, 'id', None), getattr(user, 'id', None), {'role': role_name})
            return True
        else:
            logger.info(f"User '{user.username}' already has role '{role_name}'")
            return True
    except Exception as e:
        logger.error(f"Error assigning role '{role_name}' to user '{user.username}': {str(e)}")
        db.session.rollback()
        return False

def remove_role(user, role_name, commit=False):
    """
    Remove a role from a user.
    
    Args:
        user: User object
        role_name: Name of the role to remove
        commit: Whether to commit the transaction (default: False)
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            logger.error(f"Role '{role_name}' not found")
            return False
        
        if role in user.roles:
            user.roles.remove(role)
            if commit:
                db.session.commit()
            logger.info(f"Removed role '{role_name}' from user '{user.username}'")
            _audit('remove_role', getattr(current_user, 'id', None), getattr(user, 'id', None), {'role': role_name})
            return True
        else:
            logger.info(f"User '{user.username}' does not have role '{role_name}'")
            return True
    except Exception as e:
        logger.error(f"Error removing role '{role_name}' from user '{user.username}': {str(e)}")
        db.session.rollback()
        return False

def assign_default_role(user):
    """
    Assign the default 'user' role to a new user.
    
    Args:
        user: User object
        
    Returns:
        bool: True if successful, False otherwise
    """
    return assign_role(user, 'user', commit=True)


def update_user_preferences_on_role_change(user):
    """Update user's module preferences based on their current roles.

    Ensures that role-based default modules are present without removing
    any manually enabled modules. Commits the change and logs the update.
    """
    try:
        prefs = UserPreferences.query.filter_by(user_id=user.id).first()
        if not prefs:
            prefs = UserPreferences(user_id=user.id)
            db.session.add(prefs)
            db.session.flush()

        changed = prefs.ensure_role_based_modules(user)
        # Enhance: adjust subscription-tier-driven preferences (placeholder logic)
        try:
            subscription_tier = getattr(user, 'subscription_tier', 'free')
            if subscription_tier == 'pro':
                # Ensure pro-related modules are present (example placeholder)
                modules = set(prefs.modules or [])
                modules.update([])
                prefs.modules = list(modules)
            elif subscription_tier == 'enterprise':
                modules = set(prefs.modules or [])
                modules.update([])
                prefs.modules = list(modules)
        except Exception:
            pass
        if changed:
            db.session.commit()
            logger.info(f"Updated preferences for user '{user.username}' after role change")
        else:
            # No change needed, but ensure session is clean
            db.session.flush()
        return True
    except Exception as e:
        logger.error(f"Error updating preferences for user '{user.username}' on role change: {str(e)}")
        db.session.rollback()
        return False

# ------------------------------
# User lifecycle management
# ------------------------------
def deactivate_user(target_user: User, reason: str | None = None, commit: bool = True) -> bool:
    try:
        if not can_manage_all_users(current_user):
            abort(403)
        target_user.is_active = False
        _audit('deactivate_user', getattr(current_user, 'id', None), getattr(target_user, 'id', None), {'reason': reason})
        if commit:
            db.session.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to deactivate user {getattr(target_user, 'id', None)}: {e}")
        db.session.rollback()
        return False

def reactivate_user(target_user: User, reason: str | None = None, commit: bool = True) -> bool:
    try:
        if not can_manage_all_users(current_user):
            abort(403)
        target_user.is_active = True
        _audit('reactivate_user', getattr(current_user, 'id', None), getattr(target_user, 'id', None), {'reason': reason})
        if commit:
            db.session.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to reactivate user {getattr(target_user, 'id', None)}: {e}")
        db.session.rollback()
        return False

def validate_subscription_tier_access(user: User, required_tier: str) -> bool:
    tier_order = {'free': 0, 'pro': 1, 'enterprise': 2}
    user_tier = getattr(user, 'subscription_tier', 'free')
    return tier_order.get(user_tier, 0) >= tier_order.get(required_tier, 0)

def get_users_by_company(company_name: str):
    return User.query.filter_by(company_name=company_name).all()

def get_users_by_tenant(tenant_id: str):
    return User.query.filter_by(tenant_id=tenant_id).all()

def create_user_with_roles(user_data: dict, role_names: list[str] | None = None) -> tuple[User | None, str | None]:
    try:
        if not can_create_users(current_user):
            return None, 'Insufficient permissions to create users.'
        role_names = role_names or []
        # Ensure password hashing if provided; otherwise, leave as-is for external auth
        data = dict(user_data)
        if data.get('password'):
            try:
                data['password'] = generate_password_hash(data['password'])
            except Exception:
                pass
        user = User(**data)
        db.session.add(user)
        db.session.flush()
        for rn in role_names:
            assign_role(user, rn, commit=False)
        # Update preferences after role assignment
        update_user_preferences_on_role_change(user)
        db.session.commit()
        _audit('create_user', getattr(current_user, 'id', None), getattr(user, 'id', None), {'roles': role_names})
        return user, None
    except Exception as e:
        logger.error(f"Error creating user with roles: {e}")
        db.session.rollback()
        return None, 'Failed to create user.'

# Public exports of new helpers
__all__ = [
    'has_role', 'has_permission', 'get_user_roles', 'get_user_permissions',
    'require_role', 'require_permission', 'super_admin_required', 'super_admin_only',
    'assign_role', 'remove_role', 'assign_default_role', 'update_user_preferences_on_role_change',
    'can_create_users', 'can_manage_all_users', 'can_assign_roles', 'can_view_user_details',
    'deactivate_user', 'reactivate_user', 'validate_subscription_tier_access',
    'get_users_by_company', 'get_users_by_tenant', 'create_user_with_roles'
]
