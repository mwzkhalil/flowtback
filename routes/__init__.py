"""
Routes package for FlowTrack application.
Contains all route definitions organized by functionality.
"""

from .auth_routes import auth_bp
from .admin_routes import admin_bp
from .transaction_routes import transaction_bp
from .ai_routes import ai_bp
from .api_routes import api_bp
from .bank_routes import bank_bp
from .dashboard_routes import dashboard_bp
from .upload_routes import upload_bp
from .report_routes import report_bp
from .settings_routes import settings_bp

__all__ = [
    'auth_bp',
    'admin_bp', 
    'transaction_bp',
    'ai_bp',
    'api_bp',
    'bank_bp',
    'dashboard_bp',
    'upload_bp',
    'report_bp',
    'settings_bp'
]
