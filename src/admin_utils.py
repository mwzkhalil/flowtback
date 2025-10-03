import io
import csv
from datetime import datetime, timedelta
from typing import Dict, Any, List, Tuple

from flask import current_app
from werkzeug.security import generate_password_hash

from src.models import db, User, Transaction
from sqlalchemy import or_
from src.rbac import get_user_roles


def _get_role_names_for_user(user: User) -> List[str]:
    try:
        roles = get_user_roles(user)
        return roles or []
    except Exception:
        # Fallback if relationship exists: user.roles
        try:
            return [r.name for r in getattr(user, 'roles', [])]
        except Exception:
            return []


def get_users_with_roles(page: int = 1, per_page: int = 20, search: str | None = None, role_filter: str | None = None):
    query = User.query
    if search:
        like = f"%{search}%"
        # Guard against missing email attribute
        try:
            query = query.filter(or_(User.username.ilike(like), User.email.ilike(like)))
        except Exception:
            query = query.filter(User.username.ilike(like))

    # Apply role filtering at the query level to avoid post-pagination filtering
    if role_filter:
        try:
            from src.models import Role
            query = query.filter(User.roles.any(Role.name == role_filter))
        except Exception:
            # If Role is not available or relationship misconfigured, fallback to no-op filter
            pass

    users_page = query.order_by(User.id.asc()).paginate(page=page, per_page=per_page)

    roles_map: Dict[int, List[str]] = {}
    for u in users_page.items:
        role_names = _get_role_names_for_user(u)
        roles_map[u.id] = role_names

    # Enrich results with enterprise fields for templates
    enriched_items: List[Dict[str, Any]] = []
    for u in users_page.items:
        enriched_items.append({
            'id': u.id,
            'username': getattr(u, 'username', ''),
            'email': getattr(u, 'email', ''),
            'first_name': getattr(u, 'first_name', ''),
            'last_name': getattr(u, 'last_name', ''),
            'company_name': getattr(u, 'company_name', ''),
            'subscription_tier': getattr(u, 'subscription_tier', 'free'),
            'created_at': getattr(u, 'created_at', None),
            'last_login': getattr(u, 'last_login', None),
            'is_active': getattr(u, 'is_active', True),
            'phone': getattr(u, 'phone', ''),
            'timezone': getattr(u, 'timezone', 'UTC'),
            'notes': getattr(u, 'notes', ''),
            'roles': roles_map.get(u.id, []),
        })
    return { 'items': enriched_items, 'total': users_page.total, 'page': users_page.page, 'pages': users_page.pages }, roles_map


def get_user_statistics() -> Dict[str, Any]:
    total_users = User.query.count()
    # Compute active users from available data only; fall back to 0 without exceptions
    active_users = 0
    try:
        # Prefer last_login if exists
        if hasattr(User, 'last_login'):
            last_30_days = datetime.utcnow() - timedelta(days=30)
            active_users = User.query.filter(User.last_login >= last_30_days).count()
        elif hasattr(User, 'created_at'):
            last_30_days = datetime.utcnow() - timedelta(days=30)
            active_users = User.query.filter(User.created_at >= last_30_days).count()
    except Exception:
        active_users = 0

    # Role distribution rough count using get_user_roles
    role_counts: Dict[str, int] = {}
    for u in User.query.limit(1000).all():  # cap for performance
        for r in _get_role_names_for_user(u):
            role_counts[r] = role_counts.get(r, 0) + 1

    # Subscription tier distribution
    tier_counts: Dict[str, int] = {'free': 0, 'pro': 0, 'enterprise': 0}
    try:
        for tier in list(tier_counts.keys()):
            try:
                tier_counts[tier] = User.query.filter_by(subscription_tier=tier).count()
            except Exception:
                tier_counts[tier] = 0
    except Exception:
        pass

    # Company statistics (top 5)
    company_stats: Dict[str, int] = {}
    try:
        for u in User.query.limit(2000).all():
            cname = getattr(u, 'company_name', None)
            if cname:
                company_stats[cname] = company_stats.get(cname, 0) + 1
        # sort top 5
        company_stats = dict(sorted(company_stats.items(), key=lambda x: x[1], reverse=True)[:5])
    except Exception:
        company_stats = {}

    return {
        'total_users': total_users,
        'active_users_30d': active_users,
        'role_distribution': role_counts,
        'subscription_distribution': tier_counts,
        'top_companies': company_stats,
    }


def get_registration_trends(months: int = 12) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    now = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    for i in range(months - 1, -1, -1):
        month_start = (now - timedelta(days=30 * i)).replace(day=1)
        next_month = (month_start + timedelta(days=32)).replace(day=1)
        try:
            count = User.query.filter(User.created_at >= month_start, User.created_at < next_month).count()
        except Exception:
            # Fallback: approximate by id ranges if timestamps unavailable
            count = 0
        results.append({'label': month_start.strftime('%Y-%m'), 'count': count})
    return results


def get_user_transaction_summary(user_id: int) -> Dict[str, Any]:
    txns = Transaction.query.filter_by(user_id=user_id).all()
    income = sum(t.amount for t in txns if t.amount > 0)
    expense = sum(-t.amount for t in txns if t.amount < 0)
    total = income - expense
    return {
        'count': len(txns),
        'income': income,
        'expense': expense,
        'net': total,
    }


def validate_role_assignment(admin_user: User, target_user: User, new_role: str, action: str = 'assign') -> Tuple[bool, str | None]:
    admin_roles = set(_get_role_names_for_user(admin_user))
    if 'super_admin' in admin_roles:
        return True, None
    if 'admin' in admin_roles:
        if new_role in {'user', 'admin'}:
            # Prevent self-demotion or escalation loops
            if admin_user.id == target_user.id and action == 'remove' and new_role == 'admin':
                return False, 'Admins cannot remove their own admin role.'
            return True, None
        return False, 'Insufficient privileges to assign this role.'
    return False, 'Only admins can manage roles.'


def bulk_role_assignment(user_ids: List[int], role_name: str, admin_user: User) -> Dict[str, Any]:
    from src.rbac import assign_role as r_assign
    results = {'success': [], 'failed': []}
    for uid in user_ids:
        user = User.query.get(uid)
        if not user:
            results['failed'].append({'user_id': uid, 'error': 'User not found'})
            continue
        ok, msg = validate_role_assignment(admin_user, user, role_name, 'assign')
        if not ok:
            results['failed'].append({'user_id': uid, 'error': msg})
            continue
        success = r_assign(user, role_name)
        if success:
            results['success'].append(uid)
        else:
            results['failed'].append({'user_id': uid, 'error': 'Unknown error'})
    return results


def export_user_data(format: str = 'csv', filters: Dict[str, Any] | None = None):
    filters = filters or {}
    query = User.query
    if filters.get('q'):
        like = f"%{filters['q']}%"
        try:
            query = query.filter(or_(User.username.ilike(like), User.email.ilike(like)))
        except Exception:
            query = query.filter(User.username.ilike(like))

    if filters.get('role'):
        try:
            from src.models import Role
            query = query.filter(User.roles.any(Role.name == filters['role']))
        except Exception:
            pass

    users: List[User] = query.order_by(User.id.asc()).all()

    output = io.BytesIO()
    if format == 'csv':
        text_stream = io.StringIO()
        writer = csv.writer(text_stream)
        writer.writerow(['id', 'username', 'email', 'first_name', 'last_name', 'company_name', 'subscription_tier', 'created_at', 'last_login', 'is_active', 'phone', 'timezone', 'roles', 'notes'])
        for u in users:
            roles = '|'.join(_get_role_names_for_user(u))
            writer.writerow([
                u.id,
                getattr(u, 'username', ''),
                getattr(u, 'email', ''),
                getattr(u, 'first_name', ''),
                getattr(u, 'last_name', ''),
                getattr(u, 'company_name', ''),
                getattr(u, 'subscription_tier', 'free'),
                getattr(u, 'created_at', None),
                getattr(u, 'last_login', None),
                getattr(u, 'is_active', True),
                getattr(u, 'phone', ''),
                getattr(u, 'timezone', 'UTC'),
                roles,
                getattr(u, 'notes', ''),
            ])
        output.write(text_stream.getvalue().encode('utf-8'))
        output.seek(0)
        return output, 'text/csv', 'users_export.csv'

    if format == 'excel':
        try:
            import xlsxwriter  # type: ignore
            output_excel = io.BytesIO()
            workbook = xlsxwriter.Workbook(output_excel, {'in_memory': True})
            worksheet = workbook.add_worksheet('Users')
            headers = ['id', 'username', 'email', 'first_name', 'last_name', 'company_name', 'subscription_tier', 'created_at', 'last_login', 'is_active', 'phone', 'timezone', 'roles', 'notes']
            for col, h in enumerate(headers):
                worksheet.write(0, col, h)
            row_idx = 1
            for u in users:
                roles = '|'.join(_get_role_names_for_user(u))
                worksheet.write(row_idx, 0, u.id)
                worksheet.write(row_idx, 1, getattr(u, 'username', ''))
                worksheet.write(row_idx, 2, getattr(u, 'email', ''))
                worksheet.write(row_idx, 3, getattr(u, 'first_name', ''))
                worksheet.write(row_idx, 4, getattr(u, 'last_name', ''))
                worksheet.write(row_idx, 5, getattr(u, 'company_name', ''))
                worksheet.write(row_idx, 6, getattr(u, 'subscription_tier', 'free'))
                worksheet.write(row_idx, 7, str(getattr(u, 'created_at', '')))
                worksheet.write(row_idx, 8, str(getattr(u, 'last_login', '')))
                worksheet.write(row_idx, 9, getattr(u, 'is_active', True))
                worksheet.write(row_idx, 10, getattr(u, 'phone', ''))
                worksheet.write(row_idx, 11, getattr(u, 'timezone', 'UTC'))
                worksheet.write(row_idx, 12, roles)
                worksheet.write(row_idx, 13, getattr(u, 'notes', ''))
                row_idx += 1
            workbook.close()
            output_excel.seek(0)
            return output_excel, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'users_export.xlsx'
        except Exception:
            # Fallback to CSV if Excel generation fails
            text_stream = io.StringIO()
            writer = csv.writer(text_stream)
            writer.writerow(['id', 'username', 'email', 'first_name', 'last_name', 'company_name', 'subscription_tier', 'created_at', 'last_login', 'is_active', 'phone', 'timezone', 'roles', 'notes'])
            for u in users:
                roles = '|'.join(_get_role_names_for_user(u))
                writer.writerow([
                    u.id,
                    getattr(u, 'username', ''),
                    getattr(u, 'email', ''),
                    getattr(u, 'first_name', ''),
                    getattr(u, 'last_name', ''),
                    getattr(u, 'company_name', ''),
                    getattr(u, 'subscription_tier', 'free'),
                    getattr(u, 'created_at', None),
                    getattr(u, 'last_login', None),
                    getattr(u, 'is_active', True),
                    getattr(u, 'phone', ''),
                    getattr(u, 'timezone', 'UTC'),
                    roles,
                    getattr(u, 'notes', ''),
                ])
            output.write(text_stream.getvalue().encode('utf-8'))
            output.seek(0)
            return output, 'text/csv', 'users_export.csv'

    # Fallback to CSV if unknown format
    text_stream = io.StringIO()
    writer = csv.writer(text_stream)
    writer.writerow(['id', 'username', 'email', 'first_name', 'last_name', 'company_name', 'subscription_tier', 'created_at', 'last_login', 'is_active', 'phone', 'timezone', 'roles', 'notes'])
    for u in users:
        roles = '|'.join(_get_role_names_for_user(u))
        writer.writerow([
            u.id,
            getattr(u, 'username', ''),
            getattr(u, 'email', ''),
            getattr(u, 'first_name', ''),
            getattr(u, 'last_name', ''),
            getattr(u, 'company_name', ''),
            getattr(u, 'subscription_tier', 'free'),
            getattr(u, 'created_at', None),
            getattr(u, 'last_login', None),
            getattr(u, 'is_active', True),
            getattr(u, 'phone', ''),
            getattr(u, 'timezone', 'UTC'),
            roles,
            getattr(u, 'notes', ''),
        ])
    output.write(text_stream.getvalue().encode('utf-8'))
    output.seek(0)
    return output, 'text/csv', 'users_export.csv'


def log_admin_action(admin_user: User, action: str, target_user: User | None, details: Dict[str, Any] | None = None) -> None:
    try:
        current_app.logger.info(
            f"Admin action: {action} by {getattr(admin_user, 'id', None)} on {getattr(target_user, 'id', None)} details={details}"
        )
    except Exception:
        pass


def validate_admin_permissions(admin_user: User, action_type: str) -> bool:
    roles = set(_get_role_names_for_user(admin_user))
    if 'super_admin' in roles:
        return True
    if 'admin' in roles:
        return action_type in {'assign_role', 'remove_role', 'view_users', 'export_users'}
    return False


def get_admin_activity_log(time_period: str, admin_user: User | None = None) -> List[Dict[str, Any]]:
    # Placeholder: if you add a real audit model, query it here
    return []


def get_user_role_history(user_id: int) -> List[Dict[str, Any]]:
    # Placeholder until an audit trail is implemented
    return []


def analyze_user_behavior_patterns(user_id: int) -> Dict[str, Any]:
    # Placeholder behavior analysis
    return {
        'most_active_day': None,
        'avg_daily_transactions': 0,
    }


def get_inactive_users(days: int = 30) -> List[int]:
    threshold = datetime.utcnow() - timedelta(days=days)
    try:
        users = User.query.filter(User.last_login < threshold).all()
    except Exception:
        users = []
    return [u.id for u in users]


def get_available_roles_for_admin(admin_user: User) -> List[str]:
    roles = set(_get_role_names_for_user(admin_user))
    if 'super_admin' in roles:
        # Try to list all roles from a Role model if present
        try:
            from src.models import Role
            return [r.name for r in Role.query.all()]
        except Exception:
            return ['user', 'admin', 'super_admin']
    if 'admin' in roles:
        return ['user', 'admin']
    return []


def check_role_assignment_conflicts(user: User, new_role: str) -> Tuple[bool, str | None]:
    # Simplified: allow all combinations
    return True, None


def get_role_permission_matrix() -> Dict[str, List[str]]:
    # Placeholder matrix
    return {
        'user': ['view_own_data'],
        'admin': ['view_all_users', 'assign_roles'],
        'super_admin': ['all_permissions'],
    }


def cache_user_statistics(ttl: int = 300):
    # Placeholder no-op decorator
    def decorator(func):
        return func
    return decorator


def optimize_user_queries():
    # Placeholder hook
    pass


def generate_temp_password(length: int | None = None) -> str:
    import secrets
    import string
    from flask import current_app
    length = length or getattr(current_app.config, 'TEMP_PASSWORD_LENGTH', 12)
    alphabet = string.ascii_letters + string.digits + '!@#$%^&*()'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def validate_user_creation_data(data: Dict[str, Any]) -> Tuple[bool, Dict[str, str]]:
    errors: Dict[str, str] = {}
    username = (data.get('username') or '').strip()
    email = (data.get('email') or '').strip()
    subscription_tier = (data.get('subscription_tier') or 'free').strip()
    if not username:
        errors['username'] = 'Username is required.'
    elif len(username) < 2 or len(username) > 20:
        errors['username'] = 'Username must be 2-20 characters.'
    if email and '@' not in email:
        errors['email'] = 'Invalid email format.'
    if subscription_tier not in {'free', 'pro', 'enterprise'}:
        errors['subscription_tier'] = 'Invalid subscription tier.'
    company_name = (data.get('company_name') or '').strip()
    if company_name and len(company_name) > 100:
        errors['company_name'] = 'Company name too long.'
    return len(errors) == 0, errors


def create_user_account(admin_user: User, data: Dict[str, Any], role_names: List[str] | None = None) -> Tuple[User | None, Dict[str, Any]]:
    from src.rbac import can_create_users, assign_role, update_user_preferences_on_role_change
    result: Dict[str, Any] = {'errors': {}}
    if not can_create_users(admin_user):
        result['errors'] = {'permission': 'You do not have permission to create users.'}
        return None, result
    ok, errors = validate_user_creation_data(data)
    if not ok:
        result['errors'] = errors
        return None, result
    user = None
    try:
        # Default fields
        data.setdefault('subscription_tier', current_app.config.get('DEFAULT_SUBSCRIPTION_TIER', 'free'))
        data.setdefault('timezone', 'UTC')
        # Ensure password is hashed if provided; if not, optionally generate a temp password
        raw_password = data.get('password')
        if raw_password:
            data['password'] = generate_password_hash(raw_password)
        else:
            try:
                temp = generate_temp_password()
                data['password'] = generate_password_hash(temp)
            except Exception:
                pass
        user = User(**data)
        db.session.add(user)
        db.session.flush()
        for rn in (role_names or []):
            assign_role(user, rn, commit=False)
        update_user_preferences_on_role_change(user)
        db.session.commit()
        log_admin_action(admin_user, 'create_user', user, {'roles': role_names or []})
        return user, result
    except Exception as e:
        db.session.rollback()
        result['errors'] = {'exception': str(e)}
        return None, result


def get_company_statistics() -> Dict[str, Any]:
    stats: Dict[str, int] = {}
    try:
        for u in User.query.limit(5000).all():
            cname = getattr(u, 'company_name', None)
            if cname:
                stats[cname] = stats.get(cname, 0) + 1
    except Exception:
        pass
    return {'companies': stats, 'total_companies': len(stats)}


def get_subscription_analytics() -> Dict[str, Any]:
    tiers = ['free', 'pro', 'enterprise']
    counts: Dict[str, int] = {t: 0 for t in tiers}
    try:
        for t in tiers:
            counts[t] = User.query.filter_by(subscription_tier=t).count()
    except Exception:
        pass
    return {'tiers': counts}


def send_user_invitation(email: str, roles: List[str] | None = None) -> bool:
    # Placeholder for future email integration
    try:
        current_app.logger.info(f"Invitation requested for {email} roles={roles}")
    except Exception:
        pass
    return True


def bulk_user_operations(admin_user: User, operations: List[Dict[str, Any]]):
    from src.rbac import deactivate_user as r_deactivate, reactivate_user as r_reactivate, assign_role as r_assign
    results = []
    for op in operations:
        op_type = op.get('type')
        user_id = op.get('user_id')
        target = User.query.get(user_id) if user_id is not None else None
        if not target:
            results.append({'op': op, 'status': 'failed', 'error': 'User not found'})
            continue
        if op_type == 'deactivate':
            ok = r_deactivate(target, reason=op.get('reason'))
            results.append({'op': op, 'status': 'success' if ok else 'failed'})
        elif op_type == 'reactivate':
            ok = r_reactivate(target, reason=op.get('reason'))
            results.append({'op': op, 'status': 'success' if ok else 'failed'})
        elif op_type == 'assign_role':
            role = op.get('role')
            ok = r_assign(target, role)
            results.append({'op': op, 'status': 'success' if ok else 'failed'})
        elif op_type == 'update_subscription':
            tier = op.get('subscription_tier')
            if tier in {'free', 'pro', 'enterprise'}:
                try:
                    target.subscription_tier = tier
                    db.session.commit()
                    results.append({'op': op, 'status': 'success'})
                except Exception as e:
                    db.session.rollback()
                    results.append({'op': op, 'status': 'failed', 'error': str(e)})
            else:
                results.append({'op': op, 'status': 'failed', 'error': 'Invalid subscription tier'})
        else:
            results.append({'op': op, 'status': 'skipped'})
    return results


def get_user_activity_summary(user_id: int) -> Dict[str, Any]:
    summary = get_user_transaction_summary(user_id)
    try:
        user = User.query.get(user_id)
        last_login = getattr(user, 'last_login', None)
        created_at = getattr(user, 'created_at', None)
    except Exception:
        last_login = None
        created_at = None
    summary.update({'last_login': last_login, 'created_at': created_at})
    return summary


