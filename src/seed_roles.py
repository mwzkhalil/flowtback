from src.models import db, Role, Permission
from sqlalchemy import text
import logging

# Configure logging
logger = logging.getLogger(__name__)


def seed_roles():
    """
    Create the required roles if they don't exist.
    """
    roles_data = [
        {'name': 'user', 'description': 'Basic access to own transactions and basic features'},
        {'name': 'admin', 'description': 'Access to user management and basic AI features'},
        {'name': 'super_admin', 'description': 'Full access including advanced AI features'},
    ]

    created_count = 0
    for role_data in roles_data:
        existing_role = Role.query.filter_by(name=role_data['name']).first()
        if not existing_role:
            role = Role(name=role_data['name'], description=role_data['description'])
            db.session.add(role)
            created_count += 1
            logger.info(f"Created role: {role_data['name']}")
        else:
            logger.info(f"Role already exists: {role_data['name']}")

    try:
        db.session.commit()
        logger.info(f"Successfully created {created_count} new roles")
        return True
    except Exception as e:
        logger.error(f"Error creating roles: {str(e)}")
        db.session.rollback()
        return False


def seed_permissions():
    """
    Create all permissions if they don't exist.
    """
    permissions_data = [
        # Existing/basic
        {'name': 'view_own_transactions', 'description': 'View own transaction data'},
        {'name': 'view_all_transactions', 'description': 'View all user transaction data'},
        {'name': 'access_basic_ai', 'description': 'Access to basic AI features'},
        {'name': 'access_advanced_ai', 'description': 'Access to advanced AI features (Anthropic)'},
        {'name': 'manage_users', 'description': 'Manage user accounts and roles'},
        # New granular user management permissions
        {'name': 'create_users', 'description': 'Create user accounts'},
        {'name': 'manage_all_users', 'description': 'Manage all users across tenants'},
        {'name': 'assign_roles', 'description': 'Assign roles to users'},
        {'name': 'view_user_details', 'description': 'View detailed user profiles'},
        {'name': 'deactivate_users', 'description': 'Deactivate user accounts'},
        {'name': 'reactivate_users', 'description': 'Reactivate user accounts'},
        {'name': 'reset_passwords', 'description': 'Reset user passwords'},
        {'name': 'manage_companies', 'description': 'Manage company entities'},
        {'name': 'view_audit_logs', 'description': 'View system audit logs'},
        # Subscription-tier permissions
        {'name': 'subscription_free', 'description': 'Access features for Free tier'},
        {'name': 'subscription_pro', 'description': 'Access features for Pro tier'},
        {'name': 'subscription_enterprise', 'description': 'Access features for Enterprise tier'},
    ]

    created_count = 0
    for pd in permissions_data:
        existing_permission = Permission.query.filter_by(name=pd['name']).first()
        if not existing_permission:
            permission = Permission(name=pd['name'], description=pd.get('description'))
            db.session.add(permission)
            created_count += 1
            logger.info(f"Created permission: {pd['name']}")
        else:
            logger.info(f"Permission already exists: {pd['name']}")

    try:
        db.session.commit()
        logger.info(f"Successfully created {created_count} new permissions")
        return True
    except Exception as e:
        logger.error(f"Error creating permissions: {str(e)}")
        db.session.rollback()
        return False


def assign_role_permissions():
    """
    Map permissions to roles.
    """
    role_permissions_map = {
        'user': [
            'view_own_transactions',
            'subscription_free',
        ],
        'admin': [
            'view_own_transactions', 'view_all_transactions',
            'manage_users', 'assign_roles', 'create_users', 'view_user_details',
            'deactivate_users', 'reactivate_users', 'reset_passwords',
            'access_basic_ai', 'subscription_pro'
        ],
        'super_admin': [
            # all
            'view_own_transactions', 'view_all_transactions', 'manage_users',
            'assign_roles', 'create_users', 'manage_all_users', 'view_user_details',
            'deactivate_users', 'reactivate_users', 'reset_passwords', 'manage_companies',
            'view_audit_logs', 'access_basic_ai', 'access_advanced_ai',
            'subscription_free', 'subscription_pro', 'subscription_enterprise'
        ],
    }

    assigned_count = 0
    for role_name, permission_names in role_permissions_map.items():
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            logger.error(f"Role '{role_name}' not found")
            continue
        for permission_name in permission_names:
            permission = Permission.query.filter_by(name=permission_name).first()
            if not permission:
                logger.error(f"Permission '{permission_name}' not found")
                continue
            if permission not in role.permissions:
                role.permissions.append(permission)
                assigned_count += 1
                logger.info(f"Assigned permission '{permission_name}' to role '{role_name}'")

    try:
        db.session.commit()
        logger.info(f"Successfully assigned {assigned_count} role-permission relationships")
        return True
    except Exception as e:
        logger.error(f"Error assigning role permissions: {str(e)}")
        db.session.rollback()
        return False


def seed_all():
    logger.info("Starting RBAC seeding process...")
    if not seed_roles():
        logger.error("Failed to seed roles")
        return False
    if not seed_permissions():
        logger.error("Failed to seed permissions")
        return False
    if not assign_role_permissions():
        logger.error("Failed to assign role permissions")
        return False
    logger.info("RBAC seeding completed successfully!")
    return True


def reset_rbac():
    logger.warning("Resetting RBAC data...")
    try:
        db.session.execute(text("DELETE FROM role_permissions"))
        db.session.execute(text("DELETE FROM user_roles"))
        Permission.query.delete()
        Role.query.delete()
        db.session.commit()
        logger.info("RBAC data reset successfully")
        return True
    except Exception as e:
        logger.error(f"Error resetting RBAC data: {str(e)}")
        db.session.rollback()
        return False

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    print("This script should be run within a Flask application context.")
    print("Use: python -c \"from src.seed_roles import seed_all; seed_all()\"")
