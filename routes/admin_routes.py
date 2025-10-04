"""
Admin routes for FlowTrack application.
Handles administrative functions, user management, and system configuration.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import current_user
from src.models import db, User, UserRole, Role, Transaction
from routes.middleware import admin_required, super_admin_required, rate_limit, validate_csrf_token
from src.admin_utils import (
    get_users_with_roles, get_user_statistics, get_user_transaction_summary,
    validate_role_assignment, log_admin_action, get_user_role_history,
    export_user_data, get_available_roles_for_admin
)
from src.superadmin import reset_superadmin_password, get_superadmin_users
from src.rbac import assign_role, remove_role, get_user_roles
from io import BytesIO
import csv

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/dashboard')
@admin_required
@rate_limit(max_requests=60, window_seconds=60)
def dashboard():
    """Admin dashboard with system overview."""
    try:
        stats = get_user_statistics()
        recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
        
        return render_template('admin/dashboard.html', 
                             stats=stats, 
                             recent_users=recent_users)
    except Exception as e:
        flash(f'Error loading admin dashboard: {str(e)}', 'error')
        return redirect(url_for('dashboard.home'))

@admin_bp.route('/users')
@admin_required
@rate_limit(max_requests=60, window_seconds=60)
def users():
    """List all users with their roles."""
    try:
        users_with_roles = get_users_with_roles()
        available_roles = get_available_roles_for_admin(current_user.id)
        
        return render_template('admin/users.html', 
                             users=users_with_roles,
                             available_roles=available_roles)
    except Exception as e:
        flash(f'Error loading users: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/user/<int:user_id>')
@admin_required
@rate_limit(max_requests=60, window_seconds=60)
def user_detail(user_id):
    """View detailed information about a specific user."""
    try:
        user = User.query.get_or_404(user_id)
        user_roles = get_user_roles(user_id)
        transaction_summary = get_user_transaction_summary(user_id)
        role_history = get_user_role_history(user_id)
        
        return render_template('admin/user_detail.html',
                             user=user,
                             user_roles=user_roles,
                             transaction_summary=transaction_summary,
                             role_history=role_history)
    except Exception as e:
        flash(f'Error loading user details: {str(e)}', 'error')
        return redirect(url_for('admin.users'))

@admin_bp.route('/assign-role', methods=['POST'])
@admin_required
@rate_limit(max_requests=20, window_seconds=60)
@validate_csrf_token
def assign_role():
    """Assign a role to a user."""
    try:
        user_id = request.form.get('user_id')
        role_id = request.form.get('role_id')
        
        if not user_id or not role_id:
            flash('User ID and Role ID are required', 'error')
            return redirect(url_for('admin.users'))
        
        # Validate role assignment
        if not validate_role_assignment(current_user.id, int(user_id), int(role_id)):
            flash('You do not have permission to assign this role', 'error')
            return redirect(url_for('admin.users'))
        
        # Assign role
        success = assign_role(int(user_id), int(role_id))
        
        if success:
            log_admin_action(current_user.id, f'Assigned role {role_id} to user {user_id}')
            flash('Role assigned successfully', 'success')
        else:
            flash('Failed to assign role', 'error')
        
        return redirect(url_for('admin.users'))
        
    except Exception as e:
        flash(f'Error assigning role: {str(e)}', 'error')
        return redirect(url_for('admin.users'))

@admin_bp.route('/remove-role', methods=['POST'])
@admin_required
@rate_limit(max_requests=20, window_seconds=60)
@validate_csrf_token
def remove_role():
    """Remove a role from a user."""
    try:
        user_id = request.form.get('user_id')
        role_id = request.form.get('role_id')
        
        if not user_id or not role_id:
            flash('User ID and Role ID are required', 'error')
            return redirect(url_for('admin.users'))
        
        # Validate role removal
        if not validate_role_assignment(current_user.id, int(user_id), int(role_id)):
            flash('You do not have permission to remove this role', 'error')
            return redirect(url_for('admin.users'))
        
        # Remove role
        success = remove_role(int(user_id), int(role_id))
        
        if success:
            log_admin_action(current_user.id, f'Removed role {role_id} from user {user_id}')
            flash('Role removed successfully', 'success')
        else:
            flash('Failed to remove role', 'error')
        
        return redirect(url_for('admin.users'))
        
    except Exception as e:
        flash(f'Error removing role: {str(e)}', 'error')
        return redirect(url_for('admin.users'))

@admin_bp.route('/users/export')
@admin_required
@rate_limit(max_requests=10, window_seconds=60)
def users_export():
    """Export user data to CSV."""
    try:
        users_data = export_user_data()
        
        # Create CSV in memory
        output = BytesIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow(['ID', 'Email', 'First Name', 'Last Name', 'Created At', 'Roles'])
        
        # Write user data
        for user in users_data:
            roles = ', '.join([role.name for role in user.roles])
            writer.writerow([
                user.id,
                user.email,
                user.first_name,
                user.last_name,
                user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                roles
            ])
        
        output.seek(0)
        
        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name='users_export.csv'
        )
        
    except Exception as e:
        flash(f'Error exporting users: {str(e)}', 'error')
        return redirect(url_for('admin.users'))

@admin_bp.route('/settings', methods=['GET', 'POST'])
@admin_required
def settings():
    """Admin settings page."""
    if request.method == 'POST':
        # Handle settings update
        flash('Settings updated successfully', 'success')
        return redirect(url_for('admin.settings'))
    
    return render_template('admin/settings.html')

@admin_bp.route('/reports')
@admin_required
def reports():
    """Admin reports page."""
    try:
        # Generate system reports
        total_users = User.query.count()
        total_transactions = Transaction.query.count()
        super_admin_users = get_superadmin_users()
        
        return render_template('admin/reports.html',
                             total_users=total_users,
                             total_transactions=total_transactions,
                             super_admin_users=super_admin_users)
    except Exception as e:
        flash(f'Error loading reports: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/templates')
@admin_required
def templates():
    """Template management page."""
    return render_template('admin/templates.html', templates=[])

@admin_bp.route('/templates/create', methods=['GET', 'POST'])
@admin_required
def templates_create():
    """Create new template."""
    if request.method == 'POST':
        # Handle template creation
        flash('Template created successfully', 'success')
        return redirect(url_for('admin.templates'))
    
    return render_template('admin/template_create.html')

@admin_bp.route('/templates/<int:template_id>/edit', methods=['GET', 'POST'])
@admin_required
def templates_edit(template_id):
    """Edit existing template."""
    if request.method == 'POST':
        # Handle template update
        flash('Template updated successfully', 'success')
        return redirect(url_for('admin.templates'))
    
    return render_template('admin/template_edit.html', template_id=template_id)

@admin_bp.route('/invitations')
@admin_required
def invitations():
    """Invitation management page."""
    return render_template('admin/invitations.html', pending_invitations=0)

@admin_bp.route('/invitations/send', methods=['GET', 'POST'])
@admin_required
def invitations_send():
    """Send invitations."""
    if request.method == 'POST':
        # Handle invitation sending
        flash('Invitations sent successfully', 'success')
        return redirect(url_for('admin.invitations'))
    
    return render_template('admin/invitation_send.html')

@admin_bp.route('/approvals/pending')
@admin_required
def approvals_pending():
    """Pending approvals page."""
    return render_template('admin/approvals.html', pending_approvals=0)

@admin_bp.route('/categorize-transactions')
@admin_required
def categorize_transactions():
    """Bulk categorize transactions page."""
    return render_template('admin/categorize_transactions.html')

@admin_bp.route('/tenant-switch', methods=['POST'])
@super_admin_required
@validate_csrf_token
def tenant_switch():
    """Switch tenant context (SuperAdmin only)."""
    try:
        tenant_id = request.form.get('tenant_id')
        if tenant_id:
            # Handle tenant switching logic
            flash(f'Switched to tenant {tenant_id}', 'success')
        else:
            flash('Invalid tenant ID', 'error')
        
        return redirect(url_for('admin.dashboard'))
        
    except Exception as e:
        flash(f'Error switching tenant: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/sync-user-preferences', methods=['POST'])
@super_admin_required
@validate_csrf_token
def sync_user_preferences():
    """Sync user preferences (SuperAdmin only)."""
    try:
        # Handle user preferences sync
        flash('User preferences synced successfully', 'success')
        return redirect(url_for('admin.dashboard'))
        
    except Exception as e:
        flash(f'Error syncing user preferences: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard'))

@admin_bp.route('/banks')
@admin_required
def banks():
    """Bank management page."""
    return render_template('admin/banks.html')

@admin_bp.route('/banks/sync-all', methods=['POST'])
@admin_required
@validate_csrf_token
def banks_sync_all():
    """Sync all bank connections."""
    try:
        # Handle bank sync logic
        flash('Bank sync completed', 'success')
        return redirect(url_for('admin.banks'))
        
    except Exception as e:
        flash(f'Error syncing banks: {str(e)}', 'error')
        return redirect(url_for('admin.banks'))

@admin_bp.route('/banks/logs')
@admin_required
def banks_logs():
    """Bank sync logs page."""
    return render_template('admin/bank_logs.html')
