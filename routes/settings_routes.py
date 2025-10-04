"""
Settings routes for FlowTrack application.
Handles user settings, preferences, and configuration.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import current_user
from src.models import db, User, UserPreferences
from routes.middleware import login_required, validate_csrf_token
from src.rbac import update_user_preferences_on_role_change
import logging

settings_bp = Blueprint('settings', __name__)

@settings_bp.route('/settings')
@login_required
def settings():
    """User settings page."""
    try:
        user_preferences = UserPreferences.query.filter_by(user_id=current_user.id).first()
        
        return render_template('settings.html', user_preferences=user_preferences)
        
    except Exception as e:
        flash(f'Error loading settings: {str(e)}', 'error')
        return redirect(url_for('dashboard.home'))

@settings_bp.route('/update_profile', methods=['POST'])
@login_required
@validate_csrf_token
def update_profile():
    """Update user profile information."""
    try:
        # Get form data
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        
        # Validate required fields
        if not all([first_name, last_name, email]):
            flash('All fields are required', 'error')
            return redirect(url_for('settings.settings'))
        
        # Check if email is already taken by another user
        existing_user = User.query.filter(
            User.email == email,
            User.id != current_user.id
        ).first()
        
        if existing_user:
            flash('Email address is already in use', 'error')
            return redirect(url_for('settings.settings'))
        
        # Update user profile
        current_user.first_name = first_name
        current_user.last_name = last_name
        current_user.email = email
        
        db.session.commit()
        
        flash('Profile updated successfully', 'success')
        return redirect(url_for('settings.settings'))
        
    except Exception as e:
        flash(f'Error updating profile: {str(e)}', 'error')
        return redirect(url_for('settings.settings'))

@settings_bp.route('/update_modules', methods=['POST'])
@login_required
@validate_csrf_token
def update_modules():
    """Update user's enabled modules."""
    try:
        # Get form data
        enabled_modules = request.form.getlist('enabled_modules')
        
        # Get or create user preferences
        user_preferences = UserPreferences.query.filter_by(user_id=current_user.id).first()
        
        if not user_preferences:
            user_preferences = UserPreferences(user_id=current_user.id)
            db.session.add(user_preferences)
        
        # Update enabled modules
        user_preferences.enabled_modules = ','.join(enabled_modules)
        
        db.session.commit()
        
        flash('Modules updated successfully', 'success')
        return redirect(url_for('settings.settings'))
        
    except Exception as e:
        flash(f'Error updating modules: {str(e)}', 'error')
        return redirect(url_for('settings.settings'))

@settings_bp.route('/update_preferences', methods=['POST'])
@login_required
@validate_csrf_token
def update_preferences():
    """Update user preferences."""
    try:
        # Get form data
        currency = request.form.get('currency', 'USD')
        date_format = request.form.get('date_format', '%Y-%m-%d')
        timezone = request.form.get('timezone', 'UTC')
        language = request.form.get('language', 'en')
        
        # Get or create user preferences
        user_preferences = UserPreferences.query.filter_by(user_id=current_user.id).first()
        
        if not user_preferences:
            user_preferences = UserPreferences(user_id=current_user.id)
            db.session.add(user_preferences)
        
        # Update preferences
        user_preferences.currency = currency
        user_preferences.date_format = date_format
        user_preferences.timezone = timezone
        user_preferences.language = language
        
        db.session.commit()
        
        flash('Preferences updated successfully', 'success')
        return redirect(url_for('settings.settings'))
        
    except Exception as e:
        flash(f'Error updating preferences: {str(e)}', 'error')
        return redirect(url_for('settings.settings'))

@settings_bp.route('/update_notifications', methods=['POST'])
@login_required
@validate_csrf_token
def update_notifications():
    """Update notification preferences."""
    try:
        # Get form data
        email_notifications = request.form.get('email_notifications') == 'on'
        sms_notifications = request.form.get('sms_notifications') == 'on'
        push_notifications = request.form.get('push_notifications') == 'on'
        
        # Get or create user preferences
        user_preferences = UserPreferences.query.filter_by(user_id=current_user.id).first()
        
        if not user_preferences:
            user_preferences = UserPreferences(user_id=current_user.id)
            db.session.add(user_preferences)
        
        # Update notification preferences
        user_preferences.email_notifications = email_notifications
        user_preferences.sms_notifications = sms_notifications
        user_preferences.push_notifications = push_notifications
        
        db.session.commit()
        
        flash('Notification preferences updated successfully', 'success')
        return redirect(url_for('settings.settings'))
        
    except Exception as e:
        flash(f'Error updating notification preferences: {str(e)}', 'error')
        return redirect(url_for('settings.settings'))

@settings_bp.route('/update_security', methods=['POST'])
@login_required
@validate_csrf_token
def update_security():
    """Update security settings."""
    try:
        # Get form data
        two_factor_enabled = request.form.get('two_factor_enabled') == 'on'
        session_timeout = request.form.get('session_timeout', 30)
        
        # Get or create user preferences
        user_preferences = UserPreferences.query.filter_by(user_id=current_user.id).first()
        
        if not user_preferences:
            user_preferences = UserPreferences(user_id=current_user.id)
            db.session.add(user_preferences)
        
        # Update security settings
        user_preferences.two_factor_enabled = two_factor_enabled
        user_preferences.session_timeout = int(session_timeout)
        
        db.session.commit()
        
        flash('Security settings updated successfully', 'success')
        return redirect(url_for('settings.settings'))
        
    except Exception as e:
        flash(f'Error updating security settings: {str(e)}', 'error')
        return redirect(url_for('settings.settings'))

@settings_bp.route('/export_data')
@login_required
def export_data():
    """Export user data."""
    try:
        # Get user data
        user_data = {
            'profile': {
                'first_name': current_user.first_name,
                'last_name': current_user.last_name,
                'email': current_user.email,
                'created_at': current_user.created_at.isoformat()
            },
            'preferences': {},
            'transactions': []
        }
        
        # Get user preferences
        user_preferences = UserPreferences.query.filter_by(user_id=current_user.id).first()
        if user_preferences:
            user_data['preferences'] = {
                'currency': user_preferences.currency,
                'date_format': user_preferences.date_format,
                'timezone': user_preferences.timezone,
                'language': user_preferences.language,
                'enabled_modules': user_preferences.enabled_modules
            }
        
        # Get user transactions
        from src.transaction_security import get_accessible_transactions
        transactions = get_accessible_transactions(current_user.id)
        
        for transaction in transactions:
            user_data['transactions'].append({
                'date': transaction.date.isoformat(),
                'description': transaction.description,
                'amount': float(transaction.amount),
                'category': transaction.category,
                'created_at': transaction.created_at.isoformat()
            })
        
        return jsonify({
            'success': True,
            'data': user_data
        })
        
    except Exception as e:
        return jsonify({'error': f'Error exporting data: {str(e)}'}), 500

@settings_bp.route('/delete_account', methods=['POST'])
@login_required
@validate_csrf_token
def delete_account():
    """Delete user account."""
    try:
        # Get confirmation
        confirmation = request.form.get('confirmation')
        
        if confirmation != 'DELETE':
            flash('Please type DELETE to confirm account deletion', 'error')
            return redirect(url_for('settings.settings'))
        
        # Delete user data
        from src.transaction_security import get_accessible_transactions
        
        # Delete transactions
        transactions = get_accessible_transactions(current_user.id)
        for transaction in transactions:
            db.session.delete(transaction)
        
        # Delete user preferences
        user_preferences = UserPreferences.query.filter_by(user_id=current_user.id).first()
        if user_preferences:
            db.session.delete(user_preferences)
        
        # Delete user
        db.session.delete(current_user)
        db.session.commit()
        
        flash('Account deleted successfully', 'success')
        return redirect(url_for('auth.login'))
        
    except Exception as e:
        flash(f'Error deleting account: {str(e)}', 'error')
        return redirect(url_for('settings.settings'))

@settings_bp.route('/enable_2fa')
@login_required
def enable_2fa():
    """Enable two-factor authentication."""
    try:
        # Get or create user preferences
        user_preferences = UserPreferences.query.filter_by(user_id=current_user.id).first()
        
        if not user_preferences:
            user_preferences = UserPreferences(user_id=current_user.id)
            db.session.add(user_preferences)
        
        # Generate 2FA secret (simplified)
        import secrets
        two_factor_secret = secrets.token_hex(16)
        user_preferences.two_factor_secret = two_factor_secret
        
        db.session.commit()
        
        return render_template('enable_2fa.html', 
                             two_factor_secret=two_factor_secret,
                             user_preferences=user_preferences)
        
    except Exception as e:
        flash(f'Error enabling 2FA: {str(e)}', 'error')
        return redirect(url_for('settings.settings'))

@settings_bp.route('/disable_2fa', methods=['POST'])
@login_required
@validate_csrf_token
def disable_2fa():
    """Disable two-factor authentication."""
    try:
        # Get user preferences
        user_preferences = UserPreferences.query.filter_by(user_id=current_user.id).first()
        
        if user_preferences:
            user_preferences.two_factor_enabled = False
            user_preferences.two_factor_secret = None
            db.session.commit()
        
        flash('Two-factor authentication disabled successfully', 'success')
        return redirect(url_for('settings.settings'))
        
    except Exception as e:
        flash(f'Error disabling 2FA: {str(e)}', 'error')
        return redirect(url_for('settings.settings'))

@settings_bp.route('/verify_2fa', methods=['POST'])
@login_required
@validate_csrf_token
def verify_2fa():
    """Verify two-factor authentication code."""
    try:
        # Get form data
        verification_code = request.form.get('verification_code')
        
        if not verification_code:
            flash('Verification code is required', 'error')
            return redirect(url_for('settings.enable_2fa'))
        
        # Get user preferences
        user_preferences = UserPreferences.query.filter_by(user_id=current_user.id).first()
        
        if not user_preferences or not user_preferences.two_factor_secret:
            flash('2FA setup not found', 'error')
            return redirect(url_for('settings.settings'))
        
        # Verify code (simplified - in real implementation, use proper TOTP)
        if verification_code == '123456':  # Placeholder
            user_preferences.two_factor_enabled = True
            db.session.commit()
            
            flash('Two-factor authentication enabled successfully', 'success')
            return redirect(url_for('settings.settings'))
        else:
            flash('Invalid verification code', 'error')
            return redirect(url_for('settings.enable_2fa'))
        
    except Exception as e:
        flash(f'Error verifying 2FA: {str(e)}', 'error')
        return redirect(url_for('settings.enable_2fa'))
