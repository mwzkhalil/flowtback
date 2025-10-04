"""
Authentication routes for FlowTrack application.
Handles login, registration, logout, and password management.
"""

from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from src.models import db, User
from src.forms import LoginForm, RegistrationForm
from routes.middleware import login_required, validate_csrf_token
from src.superadmin import setup_superadmin_account

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    """Handle user login - API endpoint."""
    if current_user.is_authenticated:
        return jsonify({
            'success': True,
            'message': 'Already logged in',
            'user': {
                'id': current_user.id,
                'email': current_user.email,
                'first_name': current_user.first_name,
                'last_name': current_user.last_name
            }
        })
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400
    
    email = data.get('email')
    password = data.get('password')
    remember_me = data.get('remember_me', False)
    
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if user and check_password_hash(user.password_hash, password):
        login_user(user, remember=remember_me)
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        })
    else:
        return jsonify({'error': 'Invalid email or password'}), 401

@auth_bp.route('/register', methods=['POST'])
def register():
    """Handle user registration - API endpoint."""
    if current_user.is_authenticated:
        return jsonify({
            'success': True,
            'message': 'Already logged in',
            'user': {
                'id': current_user.id,
                'email': current_user.email,
                'first_name': current_user.first_name,
                'last_name': current_user.last_name
            }
        })
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid request data'}), 400
    
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    
    if not all([email, password, confirm_password, first_name, last_name]):
        return jsonify({'error': 'All fields are required'}), 400
    
    if password != confirm_password:
        return jsonify({'error': 'Passwords do not match'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 400
    
    # Check if this is the first user (SuperAdmin setup)
    user_count = User.query.count()
    
    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        first_name=first_name,
        last_name=last_name
    )
    db.session.add(user)
    db.session.commit()
    
    if user_count == 0:
        # First user becomes SuperAdmin
        setup_superadmin_account(user.id)
        return jsonify({
            'success': True,
            'message': 'Account created successfully! You are now the SuperAdmin.',
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': 'super_admin'
            },
            'is_superadmin': True
        }), 201
    else:
        # Regular user registration
        from src.rbac import assign_default_role
        assign_default_role(user.id)
        
        return jsonify({
            'success': True,
            'message': 'Registration successful! Please log in.',
            'user': {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        }), 201

@auth_bp.route('/user', methods=['GET'])
@login_required
def get_current_user():
    """Get current user profile - API endpoint."""
    try:
        return jsonify({
            'success': True,
            'data': {
                'id': current_user.id,
                'email': current_user.email,
                'first_name': current_user.first_name,
                'last_name': current_user.last_name,
                'created_at': current_user.created_at.isoformat() if current_user.created_at else None,
                'updated_at': current_user.updated_at.isoformat() if current_user.updated_at else None
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error fetching user profile: {str(e)}'
        }), 500

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    """Handle user logout - API endpoint."""
    logout_user()
    return jsonify({
        'success': True,
        'message': 'Logout successful'
    })

# Template-based routes removed - using API endpoints instead
