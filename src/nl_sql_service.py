from anthropic import Anthropic
from flask import current_app
import json
import re
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from src.models import db, User, Transaction, InitialBalance, Role, Permission
from src.sql_security import SQLSecurityValidator
import logging

logger = logging.getLogger(__name__)

class NLSQLChatbot:
    """
    Natural Language to SQL chatbot service for financial data analysis.
    Converts natural language queries into safe SQL statements and executes them.
    """
    
    def __init__(self, api_key: str):
        """Initialize the chatbot with Anthropic API key."""
        self.anthropic = Anthropic(api_key=api_key)
        self.security_validator = SQLSecurityValidator()
        self.cache = {}  # Simple in-memory cache for query results
        self.cache_ttl = current_app.config.get('CHATBOT_CACHE_TTL', 1800)  # 30 minutes default
        self.cache_enabled = current_app.config.get('CHATBOT_CACHE_ENABLED', True)
        
    def get_database_schema(self) -> Dict[str, Any]:
        """
        Generate comprehensive database schema information for AI context.
        Includes table structures, relationships, and sample data.
        """
        try:
            schema_info = {
                'tables': {},
                'relationships': [],
                'business_rules': [],
                'sample_data': {},
                'column_descriptions': {}
            }
            
            # Get all table information
            tables = ['user', 'transaction', 'initial_balance', 'role', 'permission', 'user_roles', 'role_permissions']
            
            for table_name in tables:
                try:
                    # Get table structure
                    result = db.session.execute(f"PRAGMA table_info({table_name})")
                    columns = result.fetchall()
                    
                    table_info = {
                        'columns': [],
                        'primary_key': None,
                        'foreign_keys': []
                    }
                    
                    for col in columns:
                        column_info = {
                            'name': col[1],
                            'type': col[2],
                            'not_null': bool(col[3]),
                            'default_value': col[4],
                            'primary_key': bool(col[5])
                        }
                        table_info['columns'].append(column_info)
                        
                        if column_info['primary_key']:
                            table_info['primary_key'] = column_info['name']
                    
                    schema_info['tables'][table_name] = table_info
                    
                    # Get sample data (limit to 3 rows for context)
                    try:
                        sample_result = db.session.execute(f"SELECT * FROM {table_name} LIMIT 3")
                        sample_rows = sample_result.fetchall()
                        schema_info['sample_data'][table_name] = [
                            dict(zip([col[1] for col in columns], row)) 
                            for row in sample_rows
                        ]
                    except Exception as e:
                        logger.warning(f"Could not get sample data for {table_name}: {e}")
                        schema_info['sample_data'][table_name] = []
                        
                except Exception as e:
                    logger.warning(f"Could not get schema for table {table_name}: {e}")
                    continue
            
            # Define business rules and relationships
            schema_info['relationships'] = [
                {
                    'parent_table': 'user',
                    'child_table': 'transaction',
                    'relationship': 'one_to_many',
                    'foreign_key': 'user_id',
                    'description': 'Each user can have multiple transactions'
                },
                {
                    'parent_table': 'user',
                    'child_table': 'initial_balance',
                    'relationship': 'one_to_one',
                    'foreign_key': 'user_id',
                    'description': 'Each user has one initial balance record'
                },
                {
                    'parent_table': 'user',
                    'child_table': 'user_roles',
                    'relationship': 'many_to_many',
                    'through_table': 'user_roles',
                    'description': 'Users can have multiple roles'
                }
            ]
            
            # Business rules and constraints
            schema_info['business_rules'] = [
                'Transactions must belong to a valid user',
                'Transaction amounts can be positive (income) or negative (expenses)',
                'Transaction types include: Cash-customer, Salary-suppliers, Income-tax, etc.',
                'Users can only access their own transaction data unless they are super_admin',
                'Date format is YYYY-MM-DD for all date fields',
                'Amounts are stored as FLOAT with 2 decimal precision'
            ]
            
            # Column descriptions for better AI understanding
            schema_info['column_descriptions'] = {
                'user': {
                    'id': 'Unique user identifier',
                    'username': 'User login name',
                    'password': 'Hashed password (not accessible)'
                },
                'transaction': {
                    'id': 'Unique transaction identifier',
                    'user_id': 'ID of the user who owns this transaction',
                    'date': 'Transaction date in YYYY-MM-DD format',
                    'description': 'Transaction description or memo',
                    'amount': 'Transaction amount (positive for income, negative for expenses)',
                    'type': 'Transaction category (Cash-customer, Salary-suppliers, etc.)'
                },
                'initial_balance': {
                    'id': 'Unique balance record identifier',
                    'user_id': 'ID of the user',
                    'balance': 'Initial cash balance amount'
                }
            }
            
            return schema_info
            
        except Exception as e:
            logger.error(f"Error generating database schema: {e}")
            return {'error': f'Failed to generate schema: {str(e)}'}
    
    def process_natural_language_query(self, query: str, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a natural language query and return formatted results.
        
        Args:
            query: Natural language query from user
            user_context: User information including ID, role, and permissions
            
        Returns:
            Dictionary containing query results, SQL used, and explanations
        """
        try:
            # Validate input
            if not query or not query.strip():
                return {'error': 'Query cannot be empty'}
            
            # Check cache first if enabled
            if self.cache_enabled:
                cache_key = f"{user_context['user_id']}_{hash(query)}"
                if cache_key in self.cache:
                    cached_entry = self.cache[cache_key]
                    # Check if cache entry is still valid
                    if datetime.now().timestamp() - cached_entry['timestamp'] < self.cache_ttl:
                        cached_result = cached_entry['data'].copy()
                        cached_result['from_cache'] = True
                        # Ensure warnings are included in cached results
                        if 'warnings' not in cached_result:
                            cached_result['warnings'] = []
                        return cached_result
                    else:
                        # Remove expired cache entry
                        del self.cache[cache_key]
            
            # Get database schema for AI context
            schema_context = self.get_database_schema()
            if 'error' in schema_context:
                return schema_context
            
            # Generate SQL query using AI
            sql_result = self.generate_sql_query(query, schema_context, user_context)
            if 'error' in sql_result:
                return sql_result
            
            # Execute the SQL query safely
            execution_result = self.execute_safe_query(sql_result['sql'], user_context)
            if 'error' in execution_result:
                return execution_result
            
            # Format results for user consumption
            formatted_results = self.format_query_results(
                execution_result['data'], 
                query, 
                sql_result['sql'],
                user_context
            )
            
            # Cache the result if enabled
            result = {
                'query': query,
                'sql': sql_result['sql'],
                'results': formatted_results,
                'explanation': sql_result['explanation'],
                'execution_time': execution_result['execution_time'],
                'row_count': len(execution_result['data']),
                'from_cache': False,
                'warnings': sql_result.get('warnings', [])
            }
            
            if self.cache_enabled:
                self.cache[cache_key] = {
                    'data': result,
                    'timestamp': datetime.now().timestamp()
                }
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing natural language query: {e}")
            return {'error': f'Query processing failed: {str(e)}'}
    
    def generate_sql_query(self, nl_query: str, schema_context: Dict[str, Any], user_permissions: Dict[str, Any]) -> Dict[str, Any]:
        """
        Use Claude to convert natural language to SQL with schema context.
        
        Args:
            nl_query: Natural language query
            schema_context: Database schema information
            user_permissions: User role and permission information
            
        Returns:
            Dictionary containing SQL query and explanation
        """
        try:
            # Build comprehensive prompt for AI
            prompt = f"""You are a financial database expert. Convert the following natural language query into a safe SQL statement.

DATABASE SCHEMA:
{json.dumps(schema_context, indent=2)}

USER CONTEXT:
- User ID: {user_permissions['user_id']}
- User Role: {user_permissions['role']}
- Can Access All Data: {user_permissions.get('can_access_all_data', False)}

NATURAL LANGUAGE QUERY:
"{nl_query}"

REQUIREMENTS:
1. Generate ONLY a SELECT statement (no INSERT, UPDATE, DELETE, DROP, etc.)
2. Use proper SQLite syntax
3. Include appropriate WHERE clauses for data security
4. If user is not super_admin, add "WHERE user_id = {user_permissions['user_id']}" to restrict data access
5. Use proper table joins when needed
6. Include ORDER BY for meaningful results
7. Limit results to 100 rows maximum using LIMIT clause
8. Use proper column names from the schema
9. Handle date comparisons properly (use date strings in YYYY-MM-DD format)

COMMON QUERY PATTERNS:
- "Show me all transactions" → SELECT * FROM transaction WHERE user_id = {user_permissions['user_id']} ORDER BY date DESC
- "What was my total income last month?" → SELECT SUM(amount) as total_income FROM transaction WHERE user_id = {user_permissions['user_id']} AND amount > 0 AND date >= '2024-01-01' AND date < '2024-02-01'
- "Show transactions by type" → SELECT type, COUNT(*) as count, SUM(amount) as total FROM transaction WHERE user_id = {user_permissions['user_id']} GROUP BY type ORDER BY total DESC
- "Find my highest expense" → SELECT * FROM transaction WHERE user_id = {user_permissions['user_id']} AND amount < 0 ORDER BY amount ASC LIMIT 1

RESPONSE FORMAT (JSON):
{{
    "sql": "SELECT statement here",
    "explanation": "Brief explanation of what this query does",
    "confidence": 95,
    "warnings": ["Any warnings about the query"]
}}

Respond ONLY with the JSON object. No additional text or markdown."""

            # Call Anthropic API with config values
            model = current_app.config['ANTHROPIC_MODEL_CONFIGS']['chatbot_model']
            max_tokens = current_app.config['ANTHROPIC_MAX_TOKENS']['chatbot']
            timeout = current_app.config['ANTHROPIC_TIMEOUT_SETTINGS']['chatbot_timeout']
            
            # Apply timeout if supported by the SDK
            try:
                message = self.anthropic.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    messages=[{"role": "user", "content": prompt}],
                    timeout=timeout
                )
            except TypeError:
                # Fallback if timeout parameter is not supported
                message = self.anthropic.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    messages=[{"role": "user", "content": prompt}]
                )
            
            response_text = message.content[0].text.strip()
            
            # Clean response if it has markdown
            if response_text.startswith('```json'):
                response_text = response_text.split('```json')[1].split('```')[0].strip()
            elif response_text.startswith('```'):
                response_text = response_text.split('```')[1].split('```')[0].strip()
            
            # Parse JSON response
            result = json.loads(response_text)
            
            # Validate the generated SQL
            validation_result = self.security_validator.validate_sql_safety(result['sql'])
            if not validation_result['is_safe']:
                return {'error': f'Generated SQL failed safety validation: {validation_result["reason"]}'}
            
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error in SQL generation: {e}")
            return {'error': 'AI response format error - please try again'}
        except Exception as e:
            logger.error(f"Error generating SQL query: {e}")
            return {'error': f'SQL generation failed: {str(e)}'}
    
    def execute_safe_query(self, sql_query: str, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute SQL query with security validation and user permission enforcement.
        
        Args:
            sql_query: SQL query to execute
            user_context: User information and permissions
            
        Returns:
            Dictionary containing query results and execution metadata
        """
        try:
            start_time = datetime.now()
            
            # Final security validation
            validation_result = self.security_validator.validate_sql_safety(sql_query)
            if not validation_result['is_safe']:
                return {'error': f'Query failed security validation: {validation_result["reason"]}'}
            
            # Apply user data filtering if needed
            if not user_context.get('can_access_all_data', False):
                filtered_sql = self.security_validator.apply_user_data_filter(sql_query, user_context['user_id'])
                if filtered_sql != sql_query:
                    sql_query = filtered_sql
            
            # Enforce server-side LIMIT fallback
            max_rows = current_app.config.get('CHATBOT_MAX_RESULTS', 1000)
            sql_query = self.security_validator.add_query_limits(sql_query, max_rows=max_rows)
            
            # Enforce query timeout
            query_timeout = current_app.config.get('CHATBOT_QUERY_TIMEOUT', 30)
            
            # Execute query with timeout handling
            try:
                import signal
                import threading
                from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
                
                def execute_query():
                    return db.session.execute(sql_query)
                
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(execute_query)
                    try:
                        result = future.result(timeout=query_timeout)
                        data = result.fetchall()
                    except FutureTimeoutError:
                        # Handle timeout error
                        error_result = self.security_validator.handle_sql_execution_errors(
                            Exception(f"Query timeout after {query_timeout} seconds"),
                            {'query': sql_query, 'user_id': user_context['user_id']}
                        )
                        return {'error': error_result['user_message']}
                        
            except Exception as e:
                # Fallback to regular execution if timeout handling fails
                logger.warning(f"Timeout handling failed, falling back to regular execution: {e}")
                result = db.session.execute(sql_query)
                data = result.fetchall()
            
            # Convert to list of dictionaries for JSON serialization
            columns = result.keys()
            formatted_data = [dict(zip(columns, row)) for row in data]
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Log query execution for audit
            self.security_validator.log_sql_query_execution(
                user_context['user_id'], 
                sql_query, 
                len(formatted_data), 
                execution_time
            )
            
            return {
                'data': formatted_data,
                'execution_time': execution_time,
                'row_count': len(formatted_data)
            }
            
        except Exception as e:
            logger.error(f"Error executing SQL query: {e}")
            return {'error': f'Query execution failed: {str(e)}'}
    
    def format_query_results(self, results: List[Dict[str, Any]], original_query: str, sql_query: str, user_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format query results for user-friendly display.
        
        Args:
            results: Raw query results
            original_query: Original natural language query
            sql_query: SQL query that was executed
            user_context: User context information
            
        Returns:
            Formatted results with explanations and insights
        """
        try:
            if not results:
                return {
                    'message': 'No results found for your query.',
                    'suggestions': [
                        'Try broadening your search criteria',
                        'Check if the date range is correct',
                        'Verify you have data for the requested period'
                    ],
                    'data': []
                }
            
            # Basic formatting
            formatted_data = []
            for row in results:
                formatted_row = {}
                for key, value in row.items():
                    # Format currency amounts
                    if key.lower() in ['amount', 'total', 'sum', 'avg', 'balance'] and isinstance(value, (int, float)):
                        formatted_row[key] = f"${value:,.2f}"
                    # Format dates
                    elif key.lower() in ['date', 'created_at', 'updated_at'] and value:
                        try:
                            if isinstance(value, str) and len(value) == 10:  # YYYY-MM-DD format
                                formatted_row[key] = value
                            else:
                                formatted_row[key] = str(value)
                        except:
                            formatted_row[key] = str(value)
                    else:
                        formatted_row[key] = value
                formatted_data.append(formatted_row)
            
            # Generate insights based on results
            insights = self.generate_result_insights(results, original_query)
            
            return {
                'data': formatted_data,
                'insights': insights,
                'summary': {
                    'total_rows': len(results),
                    'query_type': self.identify_query_type(sql_query),
                    'execution_successful': True
                },
                'suggestions': self.generate_query_suggestions(original_query, results)
            }
            
        except Exception as e:
            logger.error(f"Error formatting query results: {e}")
            return {
                'data': results,
                'error': f'Result formatting error: {str(e)}',
                'insights': [],
                'summary': {'total_rows': len(results) if results else 0}
            }
    
    def generate_result_insights(self, results: List[Dict[str, Any]], original_query: str) -> List[str]:
        """Generate insights and analysis from query results."""
        insights = []
        
        if not results:
            return insights
        
        try:
            # Analyze numerical data
            numerical_columns = []
            for key in results[0].keys():
                if any(key.lower().endswith(suffix) for suffix in ['amount', 'total', 'sum', 'avg', 'count', 'balance']):
                    numerical_columns.append(key)
            
            for col in numerical_columns:
                values = [row[col] for row in results if isinstance(row[col], (int, float))]
                if values:
                    total = sum(values)
                    avg = total / len(values)
                    max_val = max(values)
                    min_val = min(values)
                    
                    insights.append(f"Total {col}: ${total:,.2f}")
                    insights.append(f"Average {col}: ${avg:,.2f}")
                    insights.append(f"Highest {col}: ${max_val:,.2f}")
                    insights.append(f"Lowest {col}: ${min_val:,.2f}")
            
            # Analyze patterns
            if 'type' in results[0]:
                type_counts = {}
                for row in results:
                    t_type = row.get('type', 'Unknown')
                    type_counts[t_type] = type_counts.get(t_type, 0) + 1
                
                most_common = max(type_counts.items(), key=lambda x: x[1])
                insights.append(f"Most common transaction type: {most_common[0]} ({most_common[1]} transactions)")
            
            # Date analysis
            if 'date' in results[0]:
                dates = [row['date'] for row in results if row['date']]
                if dates:
                    dates.sort()
                    insights.append(f"Date range: {dates[0]} to {dates[-1]}")
            
        except Exception as e:
            logger.warning(f"Error generating insights: {e}")
            insights.append("Unable to generate detailed insights for this query")
        
        return insights
    
    def identify_query_type(self, sql_query: str) -> str:
        """Identify the type of query for better user understanding."""
        sql_lower = sql_query.lower()
        
        if 'sum(' in sql_lower or 'total' in sql_lower:
            return 'Aggregation Query'
        elif 'count(' in sql_lower:
            return 'Count Query'
        elif 'group by' in sql_lower:
            return 'Grouping Query'
        elif 'order by' in sql_lower:
            return 'Sorted Query'
        elif 'where' in sql_lower:
            return 'Filtered Query'
        else:
            return 'Data Retrieval Query'
    
    def generate_query_suggestions(self, original_query: str, results: List[Dict[str, Any]]) -> List[str]:
        """Generate helpful suggestions based on the query and results."""
        suggestions = []
        
        if not results:
            suggestions.extend([
                "Try a broader date range",
                "Check if you have transactions in the specified category",
                "Verify the spelling of transaction descriptions"
            ])
        else:
            suggestions.extend([
                "Try adding date filters to narrow down results",
                "Use 'GROUP BY' to see summary statistics",
                "Add 'ORDER BY' to sort results meaningfully"
            ])
        
        # Add specific suggestions based on query content
        query_lower = original_query.lower()
        if 'income' in query_lower:
            suggestions.append("Try 'show me my expenses' to see spending patterns")
        elif 'expense' in query_lower:
            suggestions.append("Try 'show me my income' to see earning patterns")
        elif 'month' in query_lower:
            suggestions.append("Try 'show me this year' for a broader view")
        
        return suggestions
    
    def get_query_examples(self) -> List[Dict[str, str]]:
        """Get example queries to help users understand the system."""
        return [
            {
                'category': 'Basic Queries',
                'examples': [
                    'Show me all my transactions',
                    'What was my total income last month?',
                    'Show me my highest expense',
                    'List all transactions from this year'
                ]
            },
            {
                'category': 'Analysis Queries',
                'examples': [
                    'Show me transactions by type',
                    'What is my average monthly income?',
                    'Show me my spending by month',
                    'Find transactions over $1000'
                ]
            },
            {
                'category': 'Time-based Queries',
                'examples': [
                    'Show me transactions from last week',
                    'What did I spend in January?',
                    'Show me my income for Q1',
                    'Find transactions from yesterday'
                ]
            },
            {
                'category': 'Comparison Queries',
                'examples': [
                    'Compare my income vs expenses',
                    'Show me spending by category',
                    'Find my top 10 transactions',
                    'Show me transactions by amount range'
                ]
            }
        ]
    
    def clear_cache(self, user_id: Optional[int] = None):
        """Clear query cache, optionally for a specific user."""
        if user_id:
            # Remove cache entries for specific user
            keys_to_remove = [key for key in self.cache.keys() if key.startswith(f"{user_id}_")]
            for key in keys_to_remove:
                del self.cache[key]
        else:
            # Clear entire cache
            self.cache.clear()
        
        logger.info(f"Cache cleared for user {user_id if user_id else 'all users'}")
    
    def cleanup_expired_cache(self):
        """Remove expired cache entries."""
        if not self.cache_enabled:
            return
        
        current_time = datetime.now().timestamp()
        expired_keys = []
        
        for key, entry in self.cache.items():
            if current_time - entry['timestamp'] >= self.cache_ttl:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.cache[key]
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
