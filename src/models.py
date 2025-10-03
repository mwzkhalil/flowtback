from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

# Association tables for many-to-many relationships
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id', name='fk_user_roles_user'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id', name='fk_user_roles_role'), primary_key=True)
)

role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id', name='fk_role_permissions_role'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id', name='fk_role_permissions_permission'), primary_key=True)
)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    # Enterprise fields
    email = db.Column(db.String(120), unique=True, nullable=True)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    company_name = db.Column(db.String(100), nullable=True, index=True)
    subscription_tier = db.Column(db.String(20), nullable=False, default='free', index=True)
    tenant_id = db.Column(db.String(36), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False, index=True)
    phone = db.Column(db.String(20), nullable=True)
    timezone = db.Column(db.String(50), nullable=False, default='UTC')
    notes = db.Column(db.Text, nullable=True)
    
    # RBAC relationship
    roles = db.relationship('Role', secondary=user_roles, back_populates='users')

    def __repr__(self):
        return f"<User id={self.id} username={self.username} email={getattr(self, 'email', None)} company={getattr(self, 'company_name', None)}>"

    @classmethod
    def active_users(cls):
        """Query for users who are marked active."""
        return cls.query.filter_by(is_active=True)

    @classmethod
    def users_by_subscription_tier(cls, tier: str):
        """Query for users by subscription tier."""
        return cls.query.filter_by(subscription_tier=tier)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=True)
    
    # Relationships
    users = db.relationship('User', secondary=user_roles, back_populates='roles')
    permissions = db.relationship('Permission', secondary=role_permissions, back_populates='roles')

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200), nullable=True)
    
    # Relationships
    roles = db.relationship('Role', secondary=role_permissions, back_populates='permissions')

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_transaction_user'), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    description = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(10), nullable=False)
    
    user = db.relationship('User', backref=db.backref('transactions', lazy=True))

class InitialBalance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_initial_balance_user'), nullable=False)
    balance = db.Column(db.Float, nullable=False)
    
    user = db.relationship('User', backref=db.backref('initial_balance', lazy=True))

class UserPreferences(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    modules = db.Column(db.JSON, default=list)
    email_notifications = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref=db.backref('preferences', lazy=True))

    @classmethod
    def get_default_modules_for_role(cls, user):
        """Return default enabled modules based on the user's roles.

        - super_admin: ['ai_analysis', 'advanced_reporting']
        - admin: ['ai_analysis']  # Admins get ai_analysis by default by design
        - regular: []
        """
        try:
            role_names = [role.name for role in getattr(user, 'roles', [])] if user else []
        except Exception:
            role_names = []

        default_modules = set()
        if 'super_admin' in role_names:
            default_modules.update(['ai_analysis', 'advanced_reporting'])
        elif 'admin' in role_names:
            default_modules.update(['ai_analysis'])
        else:
            default_modules.update([])
        return list(default_modules)

    def ensure_role_based_modules(self, user):
        """Ensure this preference includes role-based default modules.

        Does not remove any manually enabled modules. Returns True if any change was made.
        """
        current_modules = set(self.modules or [])
        required_by_role = set(self.get_default_modules_for_role(user))
        merged_modules = current_modules.union(required_by_role)

        if merged_modules != current_modules:
            self.modules = list(merged_modules)
            return True
        return False

class AIActivityLog(db.Model):
    """Log AI feature usage for monitoring and analytics"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_ai_activity_user'), nullable=False)
    feature_name = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    success = db.Column(db.Boolean, nullable=False, default=True)
    response_time = db.Column(db.Float, nullable=True)  # Response time in milliseconds
    details = db.Column(db.JSON, nullable=True)  # Additional details about the activity
    
    # Relationship
    user = db.relationship('User', backref='ai_activities')