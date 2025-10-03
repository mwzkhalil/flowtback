# in `src/transaction_security.py`
from flask import abort
from flask_login import current_user
from src.models import db, Transaction, User
from src.rbac import has_role
import logging

# Configure logging
logger = logging.getLogger(__name__)

def validate_transaction_ownership(transaction_id, user_id):
    """
    Check if a transaction belongs to a user.
    
    Args:
        transaction_id: ID of the transaction to check
        user_id: ID of the user to check ownership against
        
    Returns:
        bool: True if transaction belongs to user, False otherwise
    """
    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        return False
    
    return transaction.user_id == user_id

def get_user_transaction_or_404(transaction_id, user_id):
    """
    Get transaction with ownership validation.
    
    Args:
        transaction_id: ID of the transaction to retrieve
        user_id: ID of the user requesting the transaction
        
    Returns:
        Transaction: The transaction object if found and owned by user
        
    Raises:
        404: If transaction not found or not owned by user
    """
    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        logger.warning(f"Transaction {transaction_id} not found")
        abort(404)
    
    if transaction.user_id != user_id:
        logger.warning(f"User {user_id} attempted to access transaction {transaction_id} owned by user {transaction.user_id}")
        abort(404)
    
    return transaction

def can_access_transaction(transaction, user):
    """
    Check if user can access a specific transaction.
    
    Args:
        transaction: Transaction object to check access for
        user: User object requesting access
        
    Returns:
        bool: True if user can access transaction, False otherwise
    """
    if not user or not user.is_authenticated:
        return False
    
    # Admin and super_admin can access any transaction
    if has_role(user, 'admin', 'super_admin'):
        return True
    
    # Regular users can only access their own transactions
    return transaction.user_id == user.id

def filter_transactions_by_role(query, user):
    """
    Apply appropriate filters based on user role.
    
    Args:
        query: SQLAlchemy query object for transactions
        user: User object to filter for
        
    Returns:
        Query: Filtered query based on user role
    """
    if not user or not user.is_authenticated:
        return query.filter(False)  # Return empty query for unauthenticated users
    
    # Admin and super_admin can see all transactions
    if has_role(user, 'admin', 'super_admin'):
        return query
    
    # Regular users can only see their own transactions
    return query.filter(Transaction.user_id == user.id)

def get_accessible_transactions(user):
    """
    Get all transactions accessible to a user based on their role.
    
    Args:
        user: User object to get transactions for
        
    Returns:
        Query: Query object for accessible transactions
    """
    base_query = Transaction.query
    return filter_transactions_by_role(base_query, user)

def get_accessible_users(user):
    """
    Get all users accessible to a user based on their role.
    
    Args:
        user: User object to get accessible users for
        
    Returns:
        Query: Query object for accessible users
    """
    if not user or not user.is_authenticated:
        return User.query.filter(False)  # Return empty query for unauthenticated users
    
    # Admin and super_admin can see all users
    if has_role(user, 'admin', 'super_admin'):
        return User.query
    
    # Regular users can only see themselves
    return User.query.filter(User.id == user.id)

def prepare_export_data(user, file_type='csv'):
    """
    Prepare transaction data for export based on user role.
    
    Args:
        user: User object requesting export
        file_type: Type of file to export (csv, json, etc.)
        
    Returns:
        tuple: (transactions_query, filename_prefix)
    """
    if not user or not user.is_authenticated:
        logger.warning(f"Unauthenticated user attempted to export data")
        abort(401)
    
    # Get accessible transactions based on user role
    transactions_query = get_accessible_transactions(user)
    
    # Determine filename prefix based on role
    if has_role(user, 'admin', 'super_admin'):
        filename_prefix = f"all_transactions_export"
    else:
        filename_prefix = f"user_{user.id}_transactions_export"
    
    return transactions_query, filename_prefix

def validate_export_permissions(user):
    """
    Check if user can export data.
    
    Args:
        user: User object requesting export
        
    Returns:
        bool: True if user can export data, False otherwise
    """
    if not user or not user.is_authenticated:
        return False
    
    # All authenticated users can export their accessible data
    return True

def log_data_access(user, resource_type, resource_id, action):
    """
    Log data access attempts for security auditing.
    
    Args:
        user: User object performing the action
        resource_type: Type of resource being accessed (transaction, user, etc.)
        resource_id: ID of the resource being accessed
        action: Action being performed (view, edit, delete, export, etc.)
    """
    logger.info(f"Data access: User {user.username} performed {action} on {resource_type} {resource_id}")

def log_unauthorized_access(user, resource_type, resource_id):
    """
    Log unauthorized access attempts for security auditing.
    
    Args:
        user: User object attempting access
        resource_type: Type of resource being accessed
        resource_id: ID of the resource being accessed
    """
    logger.warning(f"Unauthorized access attempt: User {user.username} attempted to access {resource_type} {resource_id}")

def apply_user_data_filter(query, user):
    """
    Apply user-specific data filters to a query.
    
    Args:
        query: SQLAlchemy query object
        user: User object to filter for
        
    Returns:
        Query: Filtered query based on user role
    """
    if not user or not user.is_authenticated:
        return query.filter(False)  # Return empty query for unauthenticated users
    
    # Admin and super_admin can see all data
    if has_role(user, 'admin', 'super_admin'):
        return query
    
    # Regular users can only see their own data
    # This assumes the query is for a model with user_id field
    if hasattr(query.column_descriptions[0]['entity'], 'user_id'):
        return query.filter(query.column_descriptions[0]['entity'].user_id == user.id)
    
    return query

def check_bulk_operation_permissions(user, operation_type):
    """
    Validate bulk operations based on user role.
    
    Args:
        user: User object requesting the operation
        operation_type: Type of bulk operation (delete, update, export, etc.)
        
    Returns:
        bool: True if user can perform the operation, False otherwise
    """
    if not user or not user.is_authenticated:
        return False
    
    # Admin and super_admin can perform any bulk operation
    if has_role(user, 'admin', 'super_admin'):
        return True
    
    # Regular users can only perform bulk operations on their own data
    # This is handled at the route level by filtering data before operations
    return True

def get_user_role_info(user):
    """
    Get user role information for display purposes.
    
    Args:
        user: User object to get role info for
        
    Returns:
        dict: Dictionary containing role information
    """
    if not user or not user.is_authenticated:
        return {'roles': [], 'is_admin': False, 'is_super_admin': False}
    
    roles = [role.name for role in user.roles]
    is_admin = has_role(user, 'admin', 'super_admin')
    is_super_admin = has_role(user, 'super_admin')
    
    return {
        'roles': roles,
        'is_admin': is_admin,
        'is_super_admin': is_super_admin
    }

