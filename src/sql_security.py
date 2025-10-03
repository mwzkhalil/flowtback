import re
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from flask import current_app
from src.models import db, User, Role

logger = logging.getLogger(__name__)

class SQLSecurityValidator:
    """
    Comprehensive SQL security and validation utility for the NL to SQL chatbot.
    Provides SQL injection prevention, query validation, and user permission enforcement.
    """
    
    def __init__(self):
        """Initialize the SQL security validator with security patterns and rules."""
        self.dangerous_patterns = [
            # SQL injection patterns
            r'(?i)(union\s+select)',
            r'(?i)(drop\s+table)',
            r'(?i)(delete\s+from)',
            r'(?i)(update\s+\w+\s+set)',
            r'(?i)(insert\s+into)',
            r'(?i)(alter\s+table)',
            r'(?i)(create\s+table)',
            r'(?i)(truncate\s+table)',
            r'(?i)(exec\s*\()',
            r'(?i)(execute\s*\()',
            r'(?i)(sp_executesql)',
            r'(?i)(xp_cmdshell)',
            r'(?i)(bulk\s+insert)',
            r'(?i)(load_file\s*\()',
            r'(?i)(into\s+outfile)',
            r'(?i)(into\s+dumpfile)',
            r'(?i)(load\s+data\s+infile)',
            
            # Comment patterns that could break queries
            r'--.*$',
            r'/\*.*?\*/',
            r'#.*$',
            
            # Dangerous functions
            r'(?i)(benchmark\s*\()',
            r'(?i)(sleep\s*\()',
            r'(?i)(waitfor\s+delay)',
            r'(?i)(pg_sleep\s*\()',
            
            # System information gathering
            r'(?i)(version\s*\()',
            r'(?i)(user\s*\()',
            r'(?i)(database\s*\()',
            r'(?i)(@@version)',
            r'(?i)(@@hostname)',
            r'(?i)(@@datadir)',
            
            # File system access
            r'(?i)(load_file)',
            r'(?i)(into\s+outfile)',
            r'(?i)(into\s+dumpfile)',
        ]
        
        # Initialize from config with fallbacks
        self.allowed_operations = current_app.config.get('CHATBOT_ALLOWED_OPERATIONS', [
            'SELECT',
            'WITH',  # For CTEs
            'CASE',
            'WHEN',
            'THEN',
            'ELSE',
            'END'
        ])
        
        # Allowed functions
        self.allowed_functions = [
            'COUNT', 'SUM', 'AVG', 'MIN', 'MAX',
            'UPPER', 'LOWER', 'TRIM', 'LENGTH',
            'SUBSTR', 'REPLACE', 'COALESCE',
            'ROUND', 'ABS', 'CAST', 'DATE',
            'DATETIME', 'STRFTIME', 'JULIANDAY'
        ]
        
        # Allowed tables from config
        self.allowed_tables = current_app.config.get('CHATBOT_ALLOWED_TABLES', [
            'user', 'transaction', 'initial_balance', 
            'role', 'permission', 'user_roles', 'role_permissions'
        ])
        
        # Query execution limits
        self.max_query_length = 10000
        self.max_result_rows = 1000
        self.max_execution_time = 30  # seconds
        
    def validate_sql_safety(self, sql_query: str) -> Dict[str, Any]:
        """
        Validate SQL query for security threats and safety.
        
        Args:
            sql_query: SQL query to validate
            
        Returns:
            Dictionary with validation results
        """
        try:
            # Basic input validation
            if not sql_query or not sql_query.strip():
                return {'is_safe': False, 'reason': 'Empty query'}
            
            if len(sql_query) > self.max_query_length:
                return {'is_safe': False, 'reason': f'Query too long (max {self.max_query_length} characters)'}
            
            # Normalize query for analysis
            normalized_query = sql_query.strip().upper()
            
            # Check for dangerous patterns
            for pattern in self.dangerous_patterns:
                if re.search(pattern, sql_query, re.IGNORECASE | re.MULTILINE):
                    return {
                        'is_safe': False, 
                        'reason': f'Dangerous pattern detected: {pattern}',
                        'pattern': pattern
                    }
            
            # Validate query structure
            structure_validation = self.validate_query_structure(sql_query)
            if not structure_validation['is_valid']:
                return {
                    'is_safe': False,
                    'reason': f'Invalid query structure: {structure_validation["reason"]}'
                }
            
            # Check for allowed operations only
            operation_validation = self.validate_allowed_operations(sql_query)
            if not operation_validation['is_allowed']:
                return {
                    'is_safe': False,
                    'reason': f'Disallowed operation: {operation_validation["reason"]}'
                }
            
            # Validate table access
            table_validation = self.validate_table_access(sql_query)
            if not table_validation['is_allowed']:
                return {
                    'is_safe': False,
                    'reason': f'Table access not allowed: {table_validation["reason"]}'
                }
            
            return {'is_safe': True, 'reason': 'Query passed all security checks'}
            
        except Exception as e:
            logger.error(f"Error validating SQL safety: {e}")
            return {'is_safe': False, 'reason': f'Validation error: {str(e)}'}
    
    def validate_query_structure(self, sql_query: str) -> Dict[str, Any]:
        """Validate basic SQL query structure."""
        try:
            # Must start with SELECT or WITH
            if not re.match(r'^\s*(SELECT|WITH)\b', sql_query, re.IGNORECASE):
                return {'is_valid': False, 'reason': 'Query must start with SELECT or WITH'}
            
            # Check for balanced parentheses
            paren_count = 0
            for char in sql_query:
                if char == '(':
                    paren_count += 1
                elif char == ')':
                    paren_count -= 1
                if paren_count < 0:
                    return {'is_valid': False, 'reason': 'Unbalanced parentheses'}
            
            if paren_count != 0:
                return {'is_valid': False, 'reason': 'Unbalanced parentheses'}
            
            # Check for semicolon injection
            if ';' in sql_query and not sql_query.strip().endswith(';'):
                return {'is_valid': False, 'reason': 'Multiple statements not allowed'}
            
            return {'is_valid': True}
            
        except Exception as e:
            return {'is_valid': False, 'reason': f'Structure validation error: {str(e)}'}
    
    def validate_allowed_operations(self, sql_query: str) -> Dict[str, Any]:
        """Validate that only allowed SQL operations are used."""
        try:
            # Extract SQL keywords
            keywords = re.findall(r'\b[A-Z]+\b', sql_query.upper())
            
            for keyword in keywords:
                if keyword not in self.allowed_operations and keyword not in self.allowed_functions:
                    # Check if it's a common SQL keyword that might be allowed
                    common_keywords = [
                        'FROM', 'WHERE', 'GROUP', 'BY', 'ORDER', 'HAVING',
                        'AS', 'AND', 'OR', 'NOT', 'IN', 'LIKE', 'BETWEEN',
                        'IS', 'NULL', 'DISTINCT', 'LIMIT', 'OFFSET',
                        'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER', 'ON'
                    ]
                    
                    if keyword not in common_keywords:
                        return {
                            'is_allowed': False,
                            'reason': f'Disallowed keyword: {keyword}'
                        }
            
            return {'is_allowed': True}
            
        except Exception as e:
            return {'is_allowed': False, 'reason': f'Operation validation error: {str(e)}'}
    
    def validate_table_access(self, sql_query: str) -> Dict[str, Any]:
        """Validate that only allowed tables are accessed."""
        try:
            # Extract table names from FROM and JOIN clauses
            table_pattern = r'(?i)(?:FROM|JOIN)\s+(\w+)'
            tables = re.findall(table_pattern, sql_query)
            
            for table in tables:
                if table.lower() not in self.allowed_tables:
                    return {
                        'is_allowed': False,
                        'reason': f'Table not allowed: {table}'
                    }
            
            return {'is_allowed': True}
            
        except Exception as e:
            return {'is_allowed': False, 'reason': f'Table validation error: {str(e)}'}
    
    def apply_user_data_filter(self, sql_query: str, user_id: int) -> str:
        """
        Apply user data filtering to ensure users only see their own data.
        Enhanced to handle JOIN/CTE scenarios by qualifying user_id with correct table/alias.
        
        Args:
            sql_query: Original SQL query
            user_id: ID of the user making the query
            
        Returns:
            Modified SQL query with user data filtering
        """
        try:
            # Check if query already has user_id filtering
            if f'user_id = {user_id}' in sql_query or f"user_id = '{user_id}'" in sql_query:
                return sql_query
            
            # Parse FROM clause to find the base table/alias
            base_table = self._extract_base_table(sql_query)
            qualified_user_id = f"{base_table}.user_id" if base_table else "user_id"
            
            # Add user_id filter to WHERE clause
            if 'WHERE' in sql_query.upper():
                # Add to existing WHERE clause
                where_pattern = r'(\bWHERE\b.*?)(?:\bGROUP\b|\bORDER\b|\bLIMIT\b|$)'
                match = re.search(where_pattern, sql_query, re.IGNORECASE | re.DOTALL)
                if match:
                    existing_where = match.group(1)
                    new_where = f"{existing_where} AND {qualified_user_id} = {user_id}"
                    return re.sub(where_pattern, new_where, sql_query, flags=re.IGNORECASE | re.DOTALL)
            else:
                # Add new WHERE clause
                where_pattern = r'(\bFROM\b.*?)(?:\bGROUP\b|\bORDER\b|\bLIMIT\b|$)'
                match = re.search(where_pattern, sql_query, re.IGNORECASE | re.DOTALL)
                if match:
                    from_clause = match.group(1)
                    new_where = f"{from_clause} WHERE {qualified_user_id} = {user_id}"
                    return re.sub(where_pattern, new_where, sql_query, flags=re.IGNORECASE | re.DOTALL)
            
            # Fallback: append WHERE clause at the end
            if not sql_query.strip().endswith(';'):
                return f"{sql_query} WHERE {qualified_user_id} = {user_id}"
            else:
                return f"{sql_query.rstrip(';')} WHERE {qualified_user_id} = {user_id};"
                
        except Exception as e:
            logger.error(f"Error applying user data filter: {e}")
            return sql_query
    
    def _extract_base_table(self, sql_query: str) -> str:
        """
        Extract the base table name or alias from the FROM clause.
        Handles simple queries, JOINs, and CTEs.
        
        Args:
            sql_query: SQL query to parse
            
        Returns:
            Base table name or alias, or empty string if not found
        """
        try:
            # Handle CTEs (WITH clauses)
            if re.match(r'^\s*WITH\b', sql_query, re.IGNORECASE):
                # For CTEs, find the main SELECT after the CTE definitions
                cte_end_pattern = r'\)\s*SELECT\s+.*?FROM\s+(\w+)'
                match = re.search(cte_end_pattern, sql_query, re.IGNORECASE | re.DOTALL)
                if match:
                    return match.group(1)
            
            # Handle regular FROM clause
            from_pattern = r'\bFROM\s+(\w+)(?:\s+AS\s+(\w+))?'
            match = re.search(from_pattern, sql_query, re.IGNORECASE)
            if match:
                # Return alias if present, otherwise table name
                return match.group(2) if match.group(2) else match.group(1)
            
            # Handle JOINs - find the first table in FROM
            join_pattern = r'\bFROM\s+(\w+)(?:\s+AS\s+(\w+))?\s+JOIN'
            match = re.search(join_pattern, sql_query, re.IGNORECASE)
            if match:
                return match.group(2) if match.group(2) else match.group(1)
            
            return ""
            
        except Exception as e:
            logger.error(f"Error extracting base table: {e}")
            return ""
    
    def check_query_permissions(self, sql_query: str, user_permissions: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if user has permission to execute the query.
        
        Args:
            sql_query: SQL query to check
            user_permissions: User permission information
            
        Returns:
            Permission check results
        """
        try:
            # Super admin can execute any query
            if user_permissions.get('role') == 'super_admin':
                return {'has_permission': True, 'reason': 'Super admin access'}
            
            # Check for admin-only operations
            admin_only_patterns = [
                r'(?i)(SELECT.*FROM\s+user)',
                r'(?i)(SELECT.*FROM\s+role)',
                r'(?i)(SELECT.*FROM\s+permission)',
            ]
            
            for pattern in admin_only_patterns:
                if re.search(pattern, sql_query):
                    if user_permissions.get('role') not in ['admin', 'super_admin']:
                        return {
                            'has_permission': False,
                            'reason': 'Admin access required for user/role queries'
                        }
            
            # Regular users can only query their own data
            if user_permissions.get('role') == 'user':
                if not self.has_user_data_filter(sql_query, user_permissions['user_id']):
                    return {
                        'has_permission': False,
                        'reason': 'Users can only access their own data'
                    }
            
            return {'has_permission': True, 'reason': 'Permission granted'}
            
        except Exception as e:
            logger.error(f"Error checking query permissions: {e}")
            return {'has_permission': False, 'reason': f'Permission check error: {str(e)}'}
    
    def has_user_data_filter(self, sql_query: str, user_id: int) -> bool:
        """Check if query has proper user data filtering."""
        return (f'user_id = {user_id}' in sql_query or 
                f"user_id = '{user_id}'" in sql_query)
    
    def add_query_limits(self, sql_query: str, max_rows: int = 1000) -> str:
        """Add LIMIT clause to prevent large result sets."""
        try:
            # Check if LIMIT already exists
            if re.search(r'\bLIMIT\b', sql_query, re.IGNORECASE):
                return sql_query
            
            # Add LIMIT clause
            if not sql_query.strip().endswith(';'):
                return f"{sql_query} LIMIT {max_rows}"
            else:
                return f"{sql_query.rstrip(';')} LIMIT {max_rows};"
                
        except Exception as e:
            logger.error(f"Error adding query limits: {e}")
            return sql_query
    
    def optimize_query_performance(self, sql_query: str) -> str:
        """Add performance optimizations to the query."""
        try:
            # Add LIMIT if not present
            if not re.search(r'\bLIMIT\b', sql_query, re.IGNORECASE):
                sql_query = self.add_query_limits(sql_query)
            
            # Add ORDER BY if not present (for consistent results)
            if not re.search(r'\bORDER\s+BY\b', sql_query, re.IGNORECASE):
                if 'transaction' in sql_query.lower():
                    sql_query = sql_query.rstrip(';') + ' ORDER BY date DESC;'
                elif 'user' in sql_query.lower():
                    sql_query = sql_query.rstrip(';') + ' ORDER BY id;'
            
            return sql_query
            
        except Exception as e:
            logger.error(f"Error optimizing query performance: {e}")
            return sql_query
    
    def estimate_query_cost(self, sql_query: str) -> Dict[str, Any]:
        """Estimate the computational cost of executing the query."""
        try:
            cost_factors = {
                'joins': len(re.findall(r'\bJOIN\b', sql_query, re.IGNORECASE)),
                'aggregations': len(re.findall(r'\b(COUNT|SUM|AVG|MIN|MAX)\b', sql_query, re.IGNORECASE)),
                'subqueries': len(re.findall(r'\(SELECT', sql_query, re.IGNORECASE)),
                'complex_where': len(re.findall(r'\b(AND|OR)\b', sql_query, re.IGNORECASE)),
                'group_by': 1 if re.search(r'\bGROUP\s+BY\b', sql_query, re.IGNORECASE) else 0,
                'order_by': 1 if re.search(r'\bORDER\s+BY\b', sql_query, re.IGNORECASE) else 0
            }
            
            # Calculate estimated cost
            base_cost = 1
            join_cost = cost_factors['joins'] * 2
            agg_cost = cost_factors['aggregations'] * 3
            subquery_cost = cost_factors['subqueries'] * 5
            where_cost = cost_factors['complex_where'] * 0.5
            group_cost = cost_factors['group_by'] * 2
            order_cost = cost_factors['order_by'] * 1
            
            total_cost = base_cost + join_cost + agg_cost + subquery_cost + where_cost + group_cost + order_cost
            
            return {
                'estimated_cost': total_cost,
                'cost_factors': cost_factors,
                'risk_level': 'high' if total_cost > 10 else 'medium' if total_cost > 5 else 'low'
            }
            
        except Exception as e:
            logger.error(f"Error estimating query cost: {e}")
            return {'estimated_cost': 1, 'risk_level': 'unknown'}
    
    def format_sql_results(self, results: List[Dict[str, Any]], query_metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Format SQL results for user-friendly display."""
        try:
            formatted_results = []
            
            for row in results:
                formatted_row = {}
                for key, value in row.items():
                    # Format currency amounts
                    if key.lower() in ['amount', 'total', 'sum', 'avg', 'balance', 'income', 'expense']:
                        if isinstance(value, (int, float)):
                            formatted_row[key] = f"${value:,.2f}"
                        else:
                            formatted_row[key] = value
                    # Format dates
                    elif key.lower() in ['date', 'created_at', 'updated_at']:
                        if value:
                            formatted_row[key] = str(value)
                        else:
                            formatted_row[key] = value
                    # Format numbers
                    elif isinstance(value, (int, float)) and not key.lower().endswith('_id'):
                        formatted_row[key] = f"{value:,.2f}" if value != int(value) else f"{int(value):,}"
                    else:
                        formatted_row[key] = value
                
                formatted_results.append(formatted_row)
            
            return formatted_results
            
        except Exception as e:
            logger.error(f"Error formatting SQL results: {e}")
            return results
    
    def add_result_metadata(self, results: List[Dict[str, Any]], query_info: Dict[str, Any]) -> Dict[str, Any]:
        """Add metadata to query results."""
        return {
            'data': results,
            'metadata': {
                'row_count': len(results),
                'execution_time': query_info.get('execution_time', 0),
                'query_type': query_info.get('query_type', 'unknown'),
                'timestamp': datetime.now().isoformat(),
                'user_id': query_info.get('user_id'),
                'query_hash': query_info.get('query_hash', '')
            }
        }
    
    def anonymize_sensitive_data(self, results: List[Dict[str, Any]], anonymization_rules: Dict[str, str]) -> List[Dict[str, Any]]:
        """Anonymize sensitive data in results based on rules."""
        try:
            anonymized_results = []
            
            for row in results:
                anonymized_row = row.copy()
                
                for field, rule in anonymization_rules.items():
                    if field in anonymized_row:
                        if rule == 'hash':
                            anonymized_row[field] = f"***{str(anonymized_row[field])[-4:]}"
                        elif rule == 'mask':
                            anonymized_row[field] = "***MASKED***"
                        elif rule == 'remove':
                            del anonymized_row[field]
                
                anonymized_results.append(anonymized_row)
            
            return anonymized_results
            
        except Exception as e:
            logger.error(f"Error anonymizing sensitive data: {e}")
            return results
    
    def log_sql_query_execution(self, user_id: int, query: str, results_count: int, execution_time: float):
        """Log SQL query execution for audit purposes."""
        try:
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'user_id': user_id,
                'query_hash': hash(query),
                'query_length': len(query),
                'results_count': results_count,
                'execution_time': execution_time,
                'query_preview': query[:100] + '...' if len(query) > 100 else query
            }
            
            logger.info(f"SQL Query Execution: {json.dumps(log_entry)}")
            
            # Store in database for audit trail (if needed)
            # This could be implemented as a separate audit table
            
        except Exception as e:
            logger.error(f"Error logging SQL query execution: {e}")
    
    def detect_suspicious_queries(self, query_pattern: str, user_behavior: Dict[str, Any]) -> Dict[str, Any]:
        """Detect suspicious query patterns and user behavior."""
        try:
            suspicious_indicators = []
            
            # Check for rapid successive queries
            if user_behavior.get('query_count', 0) > 10:
                suspicious_indicators.append('High query frequency')
            
            # Check for unusual query patterns
            if len(query_pattern) > 5000:
                suspicious_indicators.append('Unusually long query')
            
            # Check for system information gathering
            system_patterns = ['version', 'user()', 'database()', '@@']
            for pattern in system_patterns:
                if pattern.lower() in query_pattern.lower():
                    suspicious_indicators.append('System information gathering attempt')
            
            risk_score = len(suspicious_indicators) * 25
            
            return {
                'is_suspicious': risk_score > 50,
                'risk_score': risk_score,
                'indicators': suspicious_indicators,
                'recommendation': 'Block query' if risk_score > 75 else 'Monitor user' if risk_score > 50 else 'Normal'
            }
            
        except Exception as e:
            logger.error(f"Error detecting suspicious queries: {e}")
            return {'is_suspicious': False, 'risk_score': 0, 'indicators': []}
    
    def generate_query_report(self, time_period: str, user_filter: Optional[int] = None) -> Dict[str, Any]:
        """Generate query usage analytics report."""
        try:
            # This would typically query an audit log table
            # For now, return a placeholder structure
            
            return {
                'time_period': time_period,
                'total_queries': 0,
                'unique_users': 0,
                'average_execution_time': 0,
                'most_common_queries': [],
                'error_rate': 0,
                'top_users': [],
                'query_types': {}
            }
            
        except Exception as e:
            logger.error(f"Error generating query report: {e}")
            return {'error': f'Report generation failed: {str(e)}'}
    
    def handle_sql_execution_errors(self, error: Exception, query_context: Dict[str, Any]) -> Dict[str, Any]:
        """Handle SQL execution errors with appropriate responses."""
        try:
            error_message = str(error)
            
            # Categorize error types
            if 'syntax error' in error_message.lower():
                return {
                    'error_type': 'syntax_error',
                    'user_message': 'There was a syntax error in the generated query. Please try rephrasing your question.',
                    'technical_details': 'SQL syntax error',
                    'suggestions': ['Check your query syntax', 'Try a simpler question', 'Use standard SQL keywords']
                }
            elif 'no such table' in error_message.lower():
                return {
                    'error_type': 'table_not_found',
                    'user_message': 'The requested table was not found. Please check your query.',
                    'technical_details': 'Table does not exist',
                    'suggestions': ['Verify table name', 'Check available tables', 'Use correct table names']
                }
            elif 'no such column' in error_message.lower():
                return {
                    'error_type': 'column_not_found',
                    'user_message': 'The requested column was not found. Please check your query.',
                    'technical_details': 'Column does not exist',
                    'suggestions': ['Verify column name', 'Check available columns', 'Use correct column names']
                }
            else:
                return {
                    'error_type': 'unknown_error',
                    'user_message': 'An unexpected error occurred. Please try again.',
                    'technical_details': error_message,
                    'suggestions': ['Try a different query', 'Contact support if the problem persists']
                }
                
        except Exception as e:
            logger.error(f"Error handling SQL execution error: {e}")
            return {
                'error_type': 'handler_error',
                'user_message': 'An error occurred while processing your request.',
                'technical_details': str(e),
                'suggestions': ['Please try again', 'Contact support']
            }
    
    def provide_query_suggestions(self, failed_query: str, error_type: str) -> List[str]:
        """Provide suggestions to help users fix failed queries."""
        suggestions = []
        
        if error_type == 'syntax_error':
            suggestions.extend([
                'Use proper SQL syntax',
                'Check for missing keywords like SELECT, FROM, WHERE',
                'Ensure proper use of quotes and parentheses',
                'Try breaking down complex queries into simpler parts'
            ])
        elif error_type == 'table_not_found':
            suggestions.extend([
                'Use correct table names: user, transaction, initial_balance',
                'Check spelling of table names',
                'Verify the table exists in the database'
            ])
        elif error_type == 'column_not_found':
            suggestions.extend([
                'Use correct column names from the schema',
                'Check spelling of column names',
                'Verify the column exists in the specified table'
            ])
        else:
            suggestions.extend([
                'Try a simpler query first',
                'Check your spelling and syntax',
                'Use standard SQL keywords',
                'Contact support if the problem persists'
            ])
        
        return suggestions
    
    def mask_sensitive_error_details(self, error_message: str) -> str:
        """Mask sensitive information in error messages."""
        try:
            # Remove potential sensitive information
            masked_message = error_message
            
            # Mask database paths
            masked_message = re.sub(r'/.*?/.*?\.db', '/path/to/database.db', masked_message)
            
            # Mask user IDs in error messages
            masked_message = re.sub(r'user_id\s*=\s*\d+', 'user_id = ***', masked_message)
            
            # Mask any potential passwords or keys
            masked_message = re.sub(r'password["\']?\s*[:=]\s*["\']?[^"\']+["\']?', 'password = ***', masked_message)
            masked_message = re.sub(r'api_key["\']?\s*[:=]\s*["\']?[^"\']+["\']?', 'api_key = ***', masked_message)
            
            return masked_message
            
        except Exception as e:
            logger.error(f"Error masking sensitive error details: {e}")
            return "An error occurred (details masked for security)"
