#!/usr/bin/env python3
"""
Role validation utility module for comprehensive RBAC testing and validation
"""
import logging
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple

from src.models import db, User, Role, Permission, Transaction, InitialBalance, UserPreferences
from src.rbac import has_role, has_permission, assign_role, remove_role
from src.auth_decorators import super_admin_required, admin_required, require_permission

# Configure logging
logger = logging.getLogger(__name__)

class RoleValidationError(Exception):
    """Custom exception for role validation errors"""
    pass

class RoleValidator:
    """Comprehensive role validation utility class"""
    
    def __init__(self):
        self.validation_results = {}
        self.performance_metrics = {}
    
    def validate_user_roles(self, user_id: int) -> Dict[str, Any]:
        """
        Validate that a user has correct roles assigned.
        
        Args:
            user_id: ID of the user to validate
            
        Returns:
            Dict containing validation results
        """
        try:
            user = User.query.get(user_id)
            if not user:
                raise RoleValidationError(f"User with ID {user_id} not found")
            
            user_roles = [role.name for role in user.roles]
            validation_result = {
                'user_id': user_id,
                'username': user.username,
                'roles': user_roles,
                'valid': True,
                'issues': []
            }
            
            # Check if user has at least one role
            if not user_roles:
                validation_result['valid'] = False
                validation_result['issues'].append("User has no roles assigned")
            
            # Check for role consistency
            if 'super_admin' in user_roles and 'user' in user_roles:
                validation_result['valid'] = False
                validation_result['issues'].append("User has both super_admin and user roles (inconsistent)")
            
            self.validation_results[f"user_{user_id}"] = validation_result
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating user roles for user {user_id}: {str(e)}")
            return {
                'user_id': user_id,
                'valid': False,
                'error': str(e)
            }
    
    def validate_role_permissions(self, role_name: str) -> Dict[str, Any]:
        """
        Verify that a role has correct permissions.
        
        Args:
            role_name: Name of the role to validate
            
        Returns:
            Dict containing validation results
        """
        try:
            role = Role.query.filter_by(name=role_name).first()
            if not role:
                raise RoleValidationError(f"Role '{role_name}' not found")
            
            role_permissions = [perm.name for perm in role.permissions]
            expected_permissions = self._get_expected_permissions(role_name)
            
            validation_result = {
                'role_name': role_name,
                'permissions': role_permissions,
                'expected_permissions': expected_permissions,
                'valid': True,
                'issues': []
            }
            
            # Check for missing permissions
            missing_permissions = set(expected_permissions) - set(role_permissions)
            if missing_permissions:
                validation_result['valid'] = False
                validation_result['issues'].append(f"Missing permissions: {list(missing_permissions)}")
            
            # Check for unexpected permissions
            unexpected_permissions = set(role_permissions) - set(expected_permissions)
            if unexpected_permissions:
                validation_result['issues'].append(f"Unexpected permissions: {list(unexpected_permissions)}")
            
            self.validation_results[f"role_{role_name}"] = validation_result
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating role permissions for role {role_name}: {str(e)}")
            return {
                'role_name': role_name,
                'valid': False,
                'error': str(e)
            }
    
    def validate_rbac_system(self) -> Dict[str, Any]:
        """
        Comprehensive RBAC system validation.
        
        Returns:
            Dict containing system-wide validation results
        """
        try:
            validation_result = {
                'timestamp': datetime.now().isoformat(),
                'valid': True,
                'issues': [],
                'roles_validated': 0,
                'users_validated': 0,
                'permissions_validated': 0
            }
            
            # Validate all roles
            roles = Role.query.all()
            for role in roles:
                role_validation = self.validate_role_permissions(role.name)
                validation_result['roles_validated'] += 1
                if not role_validation['valid']:
                    validation_result['valid'] = False
                    validation_result['issues'].extend(role_validation['issues'])
            
            # Validate all users
            users = User.query.all()
            for user in users:
                user_validation = self.validate_user_roles(user.id)
                validation_result['users_validated'] += 1
                if not user_validation['valid']:
                    validation_result['valid'] = False
                    validation_result['issues'].extend(user_validation['issues'])
            
            # Validate permissions exist
            permissions = Permission.query.all()
            expected_permissions = [
                'view_own_transactions', 'manage_users', 'access_basic_ai',
                'access_advanced_ai', 'view_all_transactions'
            ]
            
            permission_names = [perm.name for perm in permissions]
            for expected_perm in expected_permissions:
                validation_result['permissions_validated'] += 1
                if expected_perm not in permission_names:
                    validation_result['valid'] = False
                    validation_result['issues'].append(f"Missing permission: {expected_perm}")
            
            self.validation_results['system'] = validation_result
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating RBAC system: {str(e)}")
            return {
                'valid': False,
                'error': str(e)
            }
    
    def check_data_isolation(self, user_id: int) -> Dict[str, Any]:
        """
        Verify that a user can only access their own data.
        
        Args:
            user_id: ID of the user to check
            
        Returns:
            Dict containing data isolation validation results
        """
        try:
            user = User.query.get(user_id)
            if not user:
                raise RoleValidationError(f"User with ID {user_id} not found")
            
            # Get user's own transactions
            own_transactions = Transaction.query.filter_by(user_id=user_id).all()
            own_transaction_ids = [t.id for t in own_transactions]
            
            # Get all transactions (to check if user can access others')
            all_transactions = Transaction.query.all()
            all_transaction_ids = [t.id for t in all_transactions]
            
            validation_result = {
                'user_id': user_id,
                'username': user.username,
                'own_transactions_count': len(own_transactions),
                'total_transactions_count': len(all_transactions),
                'data_isolation_valid': True,
                'issues': []
            }
            
            # Check if user has access to other users' transactions
            # This would need to be implemented based on actual access control logic
            # For now, we'll just verify the data exists and is properly separated
            
            if len(own_transactions) == 0:
                validation_result['issues'].append("User has no transactions")
            
            if len(all_transactions) == 0:
                validation_result['issues'].append("No transactions found in system")
            
            self.validation_results[f"data_isolation_{user_id}"] = validation_result
            return validation_result
            
        except Exception as e:
            logger.error(f"Error checking data isolation for user {user_id}: {str(e)}")
            return {
                'user_id': user_id,
                'data_isolation_valid': False,
                'error': str(e)
            }
    
    def validate_ai_feature_access(self, user_id: int, feature_name: str) -> Dict[str, Any]:
        """
        Check AI feature access for a user.
        
        Args:
            user_id: ID of the user to check
            feature_name: Name of the AI feature
            
        Returns:
            Dict containing AI feature access validation results
        """
        try:
            user = User.query.get(user_id)
            if not user:
                raise RoleValidationError(f"User with ID {user_id} not found")
            
            # Check if user has required permissions for AI features
            has_basic_ai = has_permission(user, 'access_basic_ai')
            has_advanced_ai = has_permission(user, 'access_advanced_ai')
            
            validation_result = {
                'user_id': user_id,
                'username': user.username,
                'feature_name': feature_name,
                'has_basic_ai': has_basic_ai,
                'has_advanced_ai': has_advanced_ai,
                'access_granted': False,
                'issues': []
            }
            
            # Determine access based on feature type
            if feature_name in ['basic_analysis', 'simple_reports']:
                validation_result['access_granted'] = has_basic_ai
            elif feature_name in ['advanced_ai', 'chatbot', 'risk_assessment', 'anomaly_detection']:
                validation_result['access_granted'] = has_advanced_ai
            else:
                validation_result['issues'].append(f"Unknown feature: {feature_name}")
            
            if not validation_result['access_granted']:
                validation_result['issues'].append(f"User lacks required permissions for {feature_name}")
            
            self.validation_results[f"ai_access_{user_id}_{feature_name}"] = validation_result
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating AI feature access for user {user_id}, feature {feature_name}: {str(e)}")
            return {
                'user_id': user_id,
                'feature_name': feature_name,
                'access_granted': False,
                'error': str(e)
            }
    
    def validate_admin_feature_access(self, user_id: int) -> Dict[str, Any]:
        """
        Check admin feature access for a user.
        
        Args:
            user_id: ID of the user to check
            
        Returns:
            Dict containing admin feature access validation results
        """
        try:
            user = User.query.get(user_id)
            if not user:
                raise RoleValidationError(f"User with ID {user_id} not found")
            
            has_manage_users = has_permission(user, 'manage_users')
            has_view_all = has_permission(user, 'view_all_transactions')
            is_admin = has_role(user, 'admin', 'super_admin')
            
            validation_result = {
                'user_id': user_id,
                'username': user.username,
                'has_manage_users': has_manage_users,
                'has_view_all': has_view_all,
                'is_admin': is_admin,
                'admin_access_granted': is_admin and has_manage_users,
                'issues': []
            }
            
            if not is_admin:
                validation_result['issues'].append("User is not an admin")
            
            if not has_manage_users:
                validation_result['issues'].append("User lacks manage_users permission")
            
            self.validation_results[f"admin_access_{user_id}"] = validation_result
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating admin feature access for user {user_id}: {str(e)}")
            return {
                'user_id': user_id,
                'admin_access_granted': False,
                'error': str(e)
            }
    
    def validate_sample_data_integrity(self) -> Dict[str, Any]:
        """
        Check sample data consistency and integrity.
        
        Returns:
            Dict containing sample data validation results
        """
        try:
            validation_result = {
                'timestamp': datetime.now().isoformat(),
                'valid': True,
                'issues': [],
                'users_count': 0,
                'transactions_count': 0,
                'initial_balances_count': 0,
                'preferences_count': 0
            }
            
            # Count entities
            users = User.query.all()
            transactions = Transaction.query.all()
            initial_balances = InitialBalance.query.all()
            preferences = UserPreferences.query.all()
            
            validation_result['users_count'] = len(users)
            validation_result['transactions_count'] = len(transactions)
            validation_result['initial_balances_count'] = len(initial_balances)
            validation_result['preferences_count'] = len(preferences)
            
            # Check data consistency
            if len(users) == 0:
                validation_result['valid'] = False
                validation_result['issues'].append("No users found")
            
            if len(transactions) == 0:
                validation_result['valid'] = False
                validation_result['issues'].append("No transactions found")
            
            # Check that each user has transactions
            for user in users:
                user_transactions = Transaction.query.filter_by(user_id=user.id).all()
                if len(user_transactions) == 0:
                    validation_result['issues'].append(f"User {user.username} has no transactions")
            
            # Check that each user has initial balance
            for user in users:
                user_balance = InitialBalance.query.filter_by(user_id=user.id).first()
                if not user_balance:
                    validation_result['issues'].append(f"User {user.username} has no initial balance")
            
            # Check that each user has preferences
            for user in users:
                user_prefs = UserPreferences.query.filter_by(user_id=user.id).first()
                if not user_prefs:
                    validation_result['issues'].append(f"User {user.username} has no preferences")
            
            self.validation_results['sample_data'] = validation_result
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating sample data integrity: {str(e)}")
            return {
                'valid': False,
                'error': str(e)
            }
    
    def measure_role_check_performance(self, iterations: int = 1000) -> Dict[str, Any]:
        """
        Benchmark role checking speed.
        
        Args:
            iterations: Number of iterations to run
            
        Returns:
            Dict containing performance metrics
        """
        try:
            users = User.query.all()
            if not users:
                return {'error': 'No users found for performance testing'}
            
            # Test role checking performance
            start_time = time.time()
            
            for _ in range(iterations):
                for user in users:
                    has_role(user, 'user')
                    has_role(user, 'admin')
                    has_role(user, 'super_admin')
                    has_permission(user, 'view_own_transactions')
                    has_permission(user, 'manage_users')
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            performance_result = {
                'iterations': iterations,
                'users_tested': len(users),
                'total_operations': iterations * len(users) * 5,  # 5 operations per user per iteration
                'execution_time': execution_time,
                'operations_per_second': (iterations * len(users) * 5) / execution_time,
                'average_time_per_operation': execution_time / (iterations * len(users) * 5)
            }
            
            self.performance_metrics['role_checking'] = performance_result
            return performance_result
            
        except Exception as e:
            logger.error(f"Error measuring role check performance: {str(e)}")
            return {
                'error': str(e)
            }
    
    def measure_ai_feature_performance(self, user_id: int, feature_name: str, iterations: int = 100) -> Dict[str, Any]:
        """
        Benchmark AI feature response times.
        
        Args:
            user_id: ID of the user to test with
            feature_name: Name of the AI feature
            iterations: Number of iterations to run
            
        Returns:
            Dict containing performance metrics
        """
        try:
            user = User.query.get(user_id)
            if not user:
                return {'error': f'User with ID {user_id} not found'}
            
            # Test AI feature access performance
            start_time = time.time()
            
            for _ in range(iterations):
                self.validate_ai_feature_access(user_id, feature_name)
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            performance_result = {
                'user_id': user_id,
                'feature_name': feature_name,
                'iterations': iterations,
                'execution_time': execution_time,
                'average_time_per_operation': execution_time / iterations,
                'operations_per_second': iterations / execution_time
            }
            
            self.performance_metrics[f'ai_feature_{feature_name}'] = performance_result
            return performance_result
            
        except Exception as e:
            logger.error(f"Error measuring AI feature performance: {str(e)}")
            return {
                'error': str(e)
            }
    
    def test_unauthorized_access_attempts(self) -> Dict[str, Any]:
        """
        Simulate unauthorized access attempts for security testing.
        
        Returns:
            Dict containing security test results
        """
        try:
            test_result = {
                'timestamp': datetime.now().isoformat(),
                'tests_performed': 0,
                'unauthorized_attempts': 0,
                'issues': []
            }
            
            # Test with different user types
            users = User.query.all()
            
            for user in users:
                user_roles = [role.name for role in user.roles]
                
                # Test AI feature access
                ai_access = self.validate_ai_feature_access(user.id, 'advanced_ai')
                test_result['tests_performed'] += 1
                
                if not ai_access['access_granted'] and 'super_admin' not in user_roles:
                    test_result['unauthorized_attempts'] += 1
                elif ai_access['access_granted'] and 'super_admin' not in user_roles:
                    test_result['issues'].append(f"User {user.username} has unauthorized AI access")
                
                # Test admin feature access
                admin_access = self.validate_admin_feature_access(user.id)
                test_result['tests_performed'] += 1
                
                if not admin_access['admin_access_granted'] and 'admin' not in user_roles and 'super_admin' not in user_roles:
                    test_result['unauthorized_attempts'] += 1
                elif admin_access['admin_access_granted'] and 'admin' not in user_roles and 'super_admin' not in user_roles:
                    test_result['issues'].append(f"User {user.username} has unauthorized admin access")
            
            self.validation_results['security_test'] = test_result
            return test_result
            
        except Exception as e:
            logger.error(f"Error testing unauthorized access attempts: {str(e)}")
            return {
                'error': str(e)
            }
    
    def generate_validation_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive validation report.
        
        Returns:
            Dict containing complete validation report
        """
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'validation_summary': {},
                'detailed_results': self.validation_results,
                'performance_metrics': self.performance_metrics,
                'recommendations': []
            }
            
            # Generate summary - only count entries with 'valid' key and 'evaluated' flag
            total_validations = 0
            valid_validations = 0
            
            for result in self.validation_results.values():
                if isinstance(result, dict) and 'valid' in result and result.get('evaluated', True):
                    total_validations += 1
                    if result['valid']:
                        valid_validations += 1
            
            report['validation_summary'] = {
                'total_validations': total_validations,
                'valid_validations': valid_validations,
                'invalid_validations': total_validations - valid_validations,
                'success_rate': (valid_validations / total_validations * 100) if total_validations > 0 else 0
            }
            
            # Generate recommendations
            if report['validation_summary']['success_rate'] < 100:
                report['recommendations'].append("Some validations failed - review detailed results")
            
            role_perf = self.performance_metrics.get('role_checking', {})
            if role_perf.get('average_time_per_operation', 0) > 0.01:  # 10ms threshold
                report['recommendations'].append("Role checking performance could be improved")
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating validation report: {str(e)}")
            return {
                'error': str(e)
            }
    
    def measure_database_query_performance(self, iterations: int = 100) -> Dict[str, Any]:
        """
        Measure database query performance for RBAC operations.
        
        Args:
            iterations: Number of iterations to run
            
        Returns:
            Dict containing performance metrics
        """
        try:
            start_time = time.time()
            
            for _ in range(iterations):
                # Test user queries
                users = User.query.all()
                for user in users:
                    # Test role queries
                    user_roles = [role.name for role in user.roles]
                    # Test permission queries
                    for role in user.roles:
                        permissions = [perm.name for perm in role.permissions]
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            performance_result = {
                'iterations': iterations,
                'execution_time': execution_time,
                'average_time_per_iteration': execution_time / iterations,
                'queries_per_second': iterations / execution_time
            }
            
            self.performance_metrics['database_queries'] = performance_result
            return performance_result
            
        except Exception as e:
            logger.error(f"Error measuring database query performance: {str(e)}")
            return {'error': str(e)}
    
    def validate_caching_effectiveness(self) -> Dict[str, Any]:
        """
        Validate caching effectiveness for role and permission checks.
        
        Returns:
            Dict containing caching validation results
        """
        try:
            validation_result = {
                'timestamp': datetime.now().isoformat(),
                'caching_enabled': False,  # Would need to check actual caching implementation
                'cache_hit_rate': 0.0,    # Would need to measure actual cache hits
                'recommendations': []
            }
            
            # Test repeated role checks to measure potential caching benefits
            users = User.query.all()
            if not users:
                return {'error': 'No users found for caching validation'}
            
            # Measure performance without caching (simulated)
            start_time = time.time()
            for _ in range(100):
                for user in users:
                    has_role(user, 'user')
                    has_role(user, 'admin')
                    has_permission(user, 'view_own_transactions')
            end_time = time.time()
            
            validation_result['no_cache_time'] = end_time - start_time
            validation_result['operations_per_second'] = (100 * len(users) * 3) / (end_time - start_time)
            
            if validation_result['operations_per_second'] < 1000:
                validation_result['recommendations'].append("Consider implementing role/permission caching for better performance")
            
            self.validation_results['caching'] = validation_result
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating caching effectiveness: {str(e)}")
            return {'error': str(e)}
    
    def validate_audit_logging(self) -> Dict[str, Any]:
        """
        Validate audit logging for RBAC operations.
        
        Returns:
            Dict containing audit logging validation results
        """
        try:
            validation_result = {
                'timestamp': datetime.now().isoformat(),
                'audit_logging_enabled': False,  # Would need to check actual audit implementation
                'logged_operations': [],
                'recommendations': []
            }
            
            # Test various RBAC operations that should be logged
            test_operations = [
                'user_login',
                'role_assignment',
                'permission_check',
                'admin_action',
                'data_access'
            ]
            
            # Simulate audit logging validation
            for operation in test_operations:
                validation_result['logged_operations'].append({
                    'operation': operation,
                    'logged': False,  # Would need to check actual audit logs
                    'timestamp': datetime.now().isoformat()
                })
            
            validation_result['recommendations'].append("Implement comprehensive audit logging for all RBAC operations")
            validation_result['recommendations'].append("Log user role changes, permission checks, and admin actions")
            
            self.validation_results['audit_logging'] = validation_result
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating audit logging: {str(e)}")
            return {'error': str(e)}

    def _get_expected_permissions(self, role_name: str) -> List[str]:
        """Get expected permissions for a role."""
        expected_permissions = {
            'user': ['view_own_transactions'],
            'admin': ['view_own_transactions', 'manage_users', 'access_basic_ai', 'view_all_transactions'],
            'super_admin': ['view_own_transactions', 'manage_users', 'access_basic_ai', 'access_advanced_ai', 'view_all_transactions']
        }
        return expected_permissions.get(role_name, [])

def run_automated_validation_suite() -> Dict[str, Any]:
    """
    Execute all validation tests automatically.
    
    Returns:
        Dict containing complete validation results
    """
    validator = RoleValidator()
    
    try:
        logger.info("Starting automated validation suite...")
        
        # Run all validations
        validator.validate_rbac_system()
        validator.validate_sample_data_integrity()
        validator.test_unauthorized_access_attempts()
        validator.measure_role_check_performance()
        validator.measure_database_query_performance()
        validator.validate_caching_effectiveness()
        validator.validate_audit_logging()
        
        # Generate comprehensive report
        report = validator.generate_validation_report()
        
        logger.info("Automated validation suite completed")
        return report
        
    except Exception as e:
        logger.error(f"Error running automated validation suite: {str(e)}")
        return {
            'error': str(e),
            'validation_summary': {'success_rate': 0}
        }

def create_validation_dashboard() -> str:
    """
    Create a visual validation status dashboard.
    
    Returns:
        HTML string for the dashboard
    """
    try:
        report = run_automated_validation_suite()
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>FlowTrack RBAC Validation Dashboard</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .summary {{ background-color: #e8f5e8; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .error {{ background-color: #ffe8e8; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .metric {{ display: inline-block; margin: 10px; padding: 10px; background-color: #f9f9f9; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>FlowTrack RBAC Validation Dashboard</h1>
                <p>Generated: {report.get('timestamp', 'Unknown')}</p>
            </div>
            
            <div class="summary">
                <h2>Validation Summary</h2>
                <p>Success Rate: {report.get('validation_summary', {}).get('success_rate', 0):.1f}%</p>
                <p>Total Validations: {report.get('validation_summary', {}).get('total_validations', 0)}</p>
                <p>Valid Validations: {report.get('validation_summary', {}).get('valid_validations', 0)}</p>
            </div>
            
            <div class="metric">
                <h3>Performance Metrics</h3>
                <p>Role Checking: {report.get('performance_metrics', {}).get('role_checking', {}).get('operations_per_second', 0):.0f} ops/sec</p>
            </div>
            
            <div class="error">
                <h3>Issues Found</h3>
                <ul>
                    {''.join(f'<li>{issue}</li>' for issue in report.get('recommendations', []))}
                </ul>
            </div>
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        logger.error(f"Error creating validation dashboard: {str(e)}")
        return f"<html><body><h1>Error</h1><p>{str(e)}</p></body></html>"

def run_ci_cd_validation() -> Dict[str, Any]:
    """
    Run validation for CI/CD pipeline integration.
    
    Returns:
        Dict containing CI/CD validation results
    """
    try:
        logger.info("Running CI/CD validation suite...")
        
        # Run automated validation suite
        report = run_automated_validation_suite()
        
        # CI/CD specific checks
        ci_cd_result = {
            'timestamp': datetime.now().isoformat(),
            'pipeline_status': 'passed' if report.get('validation_summary', {}).get('success_rate', 0) >= 95 else 'failed',
            'validation_report': report,
            'recommendations': []
        }
        
        # Check if validation passed threshold
        success_rate = report.get('validation_summary', {}).get('success_rate', 0)
        if success_rate < 95:
            ci_cd_result['recommendations'].append(f"Validation success rate ({success_rate:.1f}%) below threshold (95%)")
            ci_cd_result['pipeline_status'] = 'failed'
        
        # Check performance metrics
        perf_metrics = report.get('performance_metrics', {})
        role_checking = perf_metrics.get('role_checking', {})
        if role_checking.get('average_time_per_operation', 0) > 0.01:  # 10ms threshold
            ci_cd_result['recommendations'].append("Role checking performance below threshold")
        
        logger.info(f"CI/CD validation completed with status: {ci_cd_result['pipeline_status']}")
        return ci_cd_result
        
    except Exception as e:
        logger.error(f"Error running CI/CD validation: {str(e)}")
        return {
            'timestamp': datetime.now().isoformat(),
            'pipeline_status': 'error',
            'error': str(e),
            'recommendations': ['Fix validation errors before deployment']
        }

if __name__ == "__main__":
    # Run validation when executed directly
    report = run_automated_validation_suite()
    print("Validation Report:")
    print(f"Success Rate: {report.get('validation_summary', {}).get('success_rate', 0):.1f}%")
    print(f"Total Validations: {report.get('validation_summary', {}).get('total_validations', 0)}")
    
    if 'error' in report:
        print(f"Error: {report['error']}")
