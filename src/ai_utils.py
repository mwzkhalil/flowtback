"""
AI Utilities Module for Advanced Financial Analytics

This module provides comprehensive utilities to support the advanced AI features
in the financial tracking application. It includes data preparation, validation,
caching, rate limiting, and security functions.
"""

import json
import hashlib
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from functools import wraps
from flask import current_app, g, jsonify
import os

# Configure logging
logger = logging.getLogger(__name__)

# In-memory cache for AI results (in production, use Redis or similar)
_ai_cache = {}
_rate_limit_tracker = {}
_usage_analytics = {}

class AIUtils:
    """Utility class for AI feature support functions"""
    
    @staticmethod
    def build_transaction_history(transactions: List[Any]) -> List[Dict[str, Any]]:
        """Build standardized transaction history for AI routes.
        
        Accepts a list of ORM model instances or dicts and returns a list of dicts
        with keys: date (YYYY-MM-DD), amount, type, description.
        Handles date fields that may be strings or datetime/date objects.
        """
        history: List[Dict[str, Any]] = []
        for t in transactions or []:
            try:
                # Extract raw fields from object or dict
                if hasattr(t, 'date'):
                    raw_date = getattr(t, 'date', None)
                    amount = getattr(t, 'amount', 0)
                    txn_type = getattr(t, 'type', '')
                    description = getattr(t, 'description', '')
                else:
                    raw_date = t.get('date') if isinstance(t, dict) else None
                    amount = t.get('amount') if isinstance(t, dict) else 0
                    txn_type = t.get('type') if isinstance(t, dict) else ''
                    description = t.get('description') if isinstance(t, dict) else ''

                # Normalize date to YYYY-MM-DD string without altering semantics
                if isinstance(raw_date, str):
                    date_str = raw_date
                else:
                    try:
                        date_str = raw_date.strftime('%Y-%m-%d') if raw_date else ''
                    except Exception:
                        # Fallback: best-effort string cast
                        date_str = str(raw_date) if raw_date is not None else ''

                history.append({
                    'date': date_str,
                    'amount': amount,
                    'type': txn_type,
                    'description': description
                })
            except Exception:
                # Skip malformed entries silently to preserve current behavior
                continue
        return history
    
    @staticmethod
    def prepare_transaction_data_for_ai(transactions: List[Any]) -> List[Dict[str, Any]]:
        """
        Format transaction data for AI analysis
        
        Args:
            transactions: List of transaction objects
            
        Returns:
            List of formatted transaction dictionaries
        """
        try:
            formatted_data = []
            for transaction in transactions:
                # Handle date formatting
                if hasattr(transaction, 'date'):
                    if isinstance(transaction.date, str):
                        date_str = transaction.date
                    else:
                        date_str = transaction.date.strftime('%Y-%m-%d')
                else:
                    date_str = str(transaction.get('date', ''))
                
                formatted_transaction = {
                    'transaction_id': getattr(transaction, 'id', transaction.get('id', '')),
                    'date': date_str,
                    'description': getattr(transaction, 'description', transaction.get('description', '')),
                    'amount': float(getattr(transaction, 'amount', transaction.get('amount', 0))),
                    'type': getattr(transaction, 'type', transaction.get('type', '')),
                    'user_id': getattr(transaction, 'user_id', transaction.get('user_id', ''))
                }
                formatted_data.append(formatted_transaction)
            
            return formatted_data
        except Exception as e:
            logger.error(f"Error preparing transaction data: {str(e)}")
            return []
    
    @staticmethod
    def sanitize_ai_input(data: Any) -> Any:
        """
        Clean and validate input data for AI processing
        
        Args:
            data: Input data to sanitize
            
        Returns:
            Sanitized data
        """
        try:
            if isinstance(data, str):
                # Remove potentially harmful characters
                return data.replace('\x00', '').strip()
            elif isinstance(data, dict):
                return {k: AIUtils.sanitize_ai_input(v) for k, v in data.items()}
            elif isinstance(data, list):
                return [AIUtils.sanitize_ai_input(item) for item in data]
            else:
                return data
        except Exception as e:
            logger.error(f"Error sanitizing AI input: {str(e)}")
            return data
    
    @staticmethod
    def format_ai_response(response: Any, response_type: str) -> Dict[str, Any]:
        """
        Standardize AI response formatting
        
        Args:
            response: Raw AI response
            response_type: Type of response (categorization, risk_assessment, etc.)
            
        Returns:
            Standardized response dictionary
        """
        try:
            formatted_response = {
                'response_type': response_type,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'success',
                'data': response
            }
            
            # Add metadata based on response type
            if response_type == 'categorization':
                formatted_response['metadata'] = {
                    'total_transactions': len(response.get('categorizations', [])),
                    'high_confidence_count': response.get('summary', {}).get('high_confidence_count', 0)
                }
            elif response_type == 'risk_assessment':
                formatted_response['metadata'] = {
                    'risk_level': response.get('risk_summary', {}).get('risk_level', 'Unknown'),
                    'overall_score': response.get('risk_summary', {}).get('overall_risk_score', 0)
                }
            elif response_type == 'anomaly_detection':
                formatted_response['metadata'] = {
                    'total_anomalies': response.get('anomaly_summary', {}).get('total_anomalies', 0),
                    'critical_count': response.get('anomaly_summary', {}).get('critical_count', 0)
                }
            
            return formatted_response
        except Exception as e:
            logger.error(f"Error formatting AI response: {str(e)}")
            return {
                'response_type': response_type,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'error',
                'error': str(e),
                'data': response
            }
    
    @staticmethod
    def calculate_confidence_scores(predictions: List[Dict], historical_data: List[Dict]) -> List[Dict]:
        """
        Calculate confidence metrics for AI predictions
        
        Args:
            predictions: List of prediction dictionaries
            historical_data: Historical data for comparison
            
        Returns:
            Predictions with confidence scores
        """
        try:
            enhanced_predictions = []
            for prediction in predictions:
                # Calculate confidence based on historical accuracy
                confidence = 85  # Base confidence
                
                # Adjust based on historical data availability
                if len(historical_data) > 100:
                    confidence += 10
                elif len(historical_data) > 50:
                    confidence += 5
                
                # Adjust based on prediction complexity
                if prediction.get('complexity', 'low') == 'high':
                    confidence -= 10
                elif prediction.get('complexity', 'low') == 'medium':
                    confidence -= 5
                
                # Ensure confidence is within bounds
                confidence = max(0, min(100, confidence))
                
                prediction['confidence_score'] = confidence
                enhanced_predictions.append(prediction)
            
            return enhanced_predictions
        except Exception as e:
            logger.error(f"Error calculating confidence scores: {str(e)}")
            return predictions
    
    @staticmethod
    def validate_ai_predictions(predictions: List[Dict], business_rules: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate AI outputs against business logic
        
        Args:
            predictions: AI predictions to validate
            business_rules: Business rules to apply
            
        Returns:
            Validation results
        """
        try:
            validation_results = {
                'valid_predictions': [],
                'invalid_predictions': [],
                'warnings': [],
                'total_validated': len(predictions)
            }
            
            for prediction in predictions:
                is_valid = True
                warnings = []
                
                # Check amount ranges
                if 'amount' in prediction:
                    amount = prediction['amount']
                    min_amount = business_rules.get('min_amount', 0)
                    max_amount = business_rules.get('max_amount', float('inf'))
                    
                    if amount < min_amount or amount > max_amount:
                        is_valid = False
                        warnings.append(f"Amount {amount} outside valid range [{min_amount}, {max_amount}]")
                
                # Check category validity
                if 'category' in prediction:
                    valid_categories = business_rules.get('valid_categories', [])
                    if valid_categories and prediction['category'] not in valid_categories:
                        is_valid = False
                        warnings.append(f"Invalid category: {prediction['category']}")
                
                # Check confidence threshold
                confidence = prediction.get('confidence_score', 0)
                min_confidence = business_rules.get('min_confidence', 70)
                if confidence < min_confidence:
                    warnings.append(f"Low confidence score: {confidence} < {min_confidence}")
                
                if is_valid:
                    validation_results['valid_predictions'].append(prediction)
                else:
                    validation_results['invalid_predictions'].append({
                        'prediction': prediction,
                        'warnings': warnings
                    })
                
                validation_results['warnings'].extend(warnings)
            
            return validation_results
        except Exception as e:
            logger.error(f"Error validating AI predictions: {str(e)}")
            return {'error': str(e), 'valid_predictions': [], 'invalid_predictions': predictions}
    
    @staticmethod
    def merge_ai_insights(multiple_analyses: List[Dict]) -> Dict[str, Any]:
        """
        Combine insights from multiple AI analyses
        
        Args:
            multiple_analyses: List of analysis results
            
        Returns:
            Merged insights
        """
        try:
            if not multiple_analyses:
                return {'error': 'No analyses to merge'}
            
            merged_insights = {
                'combined_analysis': {
                    'total_analyses': len(multiple_analyses),
                    'analysis_types': [analysis.get('type', 'unknown') for analysis in multiple_analyses],
                    'timestamp': datetime.utcnow().isoformat()
                },
                'key_findings': [],
                'recommendations': [],
                'risk_factors': [],
                'confidence_scores': []
            }
            
            # Merge key findings
            for analysis in multiple_analyses:
                findings = analysis.get('key_findings', [])
                if isinstance(findings, list):
                    merged_insights['key_findings'].extend(findings)
                elif isinstance(findings, str):
                    merged_insights['key_findings'].append(findings)
            
            # Merge recommendations
            for analysis in multiple_analyses:
                recommendations = analysis.get('recommendations', [])
                if isinstance(recommendations, list):
                    merged_insights['recommendations'].extend(recommendations)
                elif isinstance(recommendations, str):
                    merged_insights['recommendations'].append(recommendations)
            
            # Remove duplicates
            merged_insights['key_findings'] = list(set(merged_insights['key_findings']))
            merged_insights['recommendations'] = list(set(merged_insights['recommendations']))
            
            return merged_insights
        except Exception as e:
            logger.error(f"Error merging AI insights: {str(e)}")
            return {'error': str(e)}
    
    @staticmethod
    def batch_ai_requests(requests: List[Dict], batch_size: int = 5) -> List[List[Dict]]:
        """
        Optimize AI API calls for bulk operations
        
        Args:
            requests: List of AI requests
            batch_size: Maximum requests per batch
            
        Returns:
            List of batched requests
        """
        try:
            batches = []
            for i in range(0, len(requests), batch_size):
                batch = requests[i:i + batch_size]
                batches.append(batch)
            return batches
        except Exception as e:
            logger.error(f"Error batching AI requests: {str(e)}")
            return [requests]
    
    @staticmethod
    def cache_ai_results(cache_key: str, result: Any, ttl: int = 3600) -> bool:
        """
        Cache expensive AI computations
        
        Args:
            cache_key: Unique cache key
            result: Result to cache
            ttl: Time to live in seconds
            
        Returns:
            True if cached successfully
        """
        try:
            cache_entry = {
                'data': result,
                'timestamp': time.time(),
                'ttl': ttl
            }
            _ai_cache[cache_key] = cache_entry
            return True
        except Exception as e:
            logger.error(f"Error caching AI results: {str(e)}")
            return False
    
    @staticmethod
    def get_cached_ai_results(cache_key: str) -> Optional[Any]:
        """
        Retrieve cached AI results
        
        Args:
            cache_key: Cache key to retrieve
            
        Returns:
            Cached result or None
        """
        try:
            if cache_key not in _ai_cache:
                return None
            
            cache_entry = _ai_cache[cache_key]
            current_time = time.time()
            
            # Check if cache entry has expired
            if current_time - cache_entry['timestamp'] > cache_entry['ttl']:
                del _ai_cache[cache_key]
                return None
            
            return cache_entry['data']
        except Exception as e:
            logger.error(f"Error retrieving cached AI results: {str(e)}")
            return None
    
    @staticmethod
    def rate_limit_ai_calls(user_id: int, feature_type: str) -> bool:
        """
        Implement rate limiting for AI features
        
        Args:
            user_id: User ID
            feature_type: Type of AI feature
            
        Returns:
            True if request is allowed
        """
        try:
            current_time = time.time()
            user_key = f"{user_id}_{feature_type}"
            
            # Get rate limits from configuration
            rate_limits = current_app.config.get('AI_RATE_LIMITS', {
                'categorization': 100,  # per hour
                'risk_assessment': 20,
                'anomaly_detection': 30,
                'advanced_forecast': 15,
                'custom_insights': 50
            })
            
            limit = rate_limits.get(feature_type, 10)  # Default limit
            
            if user_key not in _rate_limit_tracker:
                _rate_limit_tracker[user_key] = []
            
            # Clean old entries (older than 1 hour)
            _rate_limit_tracker[user_key] = [
                timestamp for timestamp in _rate_limit_tracker[user_key]
                if current_time - timestamp < 3600
            ]
            
            # Check if limit exceeded
            if len(_rate_limit_tracker[user_key]) >= limit:
                return False
            
            # Add current request
            _rate_limit_tracker[user_key].append(current_time)
            return True
        except Exception as e:
            logger.error(f"Error in rate limiting: {str(e)}")
            return True  # Allow on error
    
    @staticmethod
    def apply_business_rules_to_ai_output(ai_output: Dict[str, Any], rules: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply business constraints to AI suggestions
        
        Args:
            ai_output: AI-generated output
            rules: Business rules to apply
            
        Returns:
            Modified output with business rules applied
        """
        try:
            modified_output = ai_output.copy()
            
            # Apply confidence thresholds
            min_confidence = rules.get('min_confidence', 70)
            if 'categorizations' in modified_output:
                for categorization in modified_output['categorizations']:
                    if categorization.get('confidence_score', 0) < min_confidence:
                        categorization['status'] = 'low_confidence'
                        categorization['requires_review'] = True
            
            # Apply amount limits
            max_amount = rules.get('max_single_transaction', 100000)
            if 'anomalies' in modified_output:
                for anomaly in modified_output['anomalies']:
                    if anomaly.get('amount', 0) > max_amount:
                        anomaly['severity'] = 'critical'
                        anomaly['auto_flagged'] = True
            
            # Apply category restrictions
            allowed_categories = rules.get('allowed_categories', [])
            if allowed_categories and 'categorizations' in modified_output:
                for categorization in modified_output['categorizations']:
                    if categorization.get('suggested_category') not in allowed_categories:
                        categorization['suggested_category'] = 'Other-cfo'
                        categorization['modified_by_rules'] = True
            
            return modified_output
        except Exception as e:
            logger.error(f"Error applying business rules: {str(e)}")
            return ai_output
    
    @staticmethod
    def generate_ai_audit_trail(user_id: int, feature_used: str, input_data: Any, output_data: Any) -> Dict[str, Any]:
        """
        Log AI usage for compliance
        
        Args:
            user_id: User ID
            feature_used: AI feature name
            input_data: Input data to AI
            output_data: Output from AI
            
        Returns:
            Audit trail entry
        """
        try:
            audit_entry = {
                'user_id': user_id,
                'feature_used': feature_used,
                'timestamp': datetime.utcnow().isoformat(),
                'input_hash': hashlib.sha256(str(input_data).encode()).hexdigest()[:16],
                'output_hash': hashlib.sha256(str(output_data).encode()).hexdigest()[:16],
                'input_size': len(str(input_data)),
                'output_size': len(str(output_data)),
                'session_id': getattr(g, 'session_id', 'unknown')
            }
            
            # Store in usage analytics
            if user_id not in _usage_analytics:
                _usage_analytics[user_id] = []
            _usage_analytics[user_id].append(audit_entry)
            
            # Log to application logger
            logger.info(f"AI audit: User {user_id} used {feature_used}")
            
            return audit_entry
        except Exception as e:
            logger.error(f"Error generating AI audit trail: {str(e)}")
            return {'error': str(e)}
    
    @staticmethod
    def validate_ai_feature_access(user: Any, feature_name: str) -> bool:
        """
        Additional validation for AI feature access
        
        Args:
            user: User object
            feature_name: Name of AI feature
            
        Returns:
            True if access is allowed
        """
        try:
            # Check if AI features are enabled
            if not current_app.config.get('AI_FEATURES_ENABLED', True):
                return False
            
            # Check user role (should be handled by decorators, but double-check)
            if not hasattr(user, 'roles') or not user.roles:
                return False
            
            # Check if user has super_admin role
            super_admin_role = any(role.name == 'super_admin' for role in user.roles)
            if not super_admin_role:
                return False
            
            # Check feature-specific permissions
            feature_permissions = current_app.config.get('AI_FEATURE_PERMISSIONS', {})
            required_permission = feature_permissions.get(feature_name, 'super_admin')
            
            if required_permission == 'super_admin':
                return super_admin_role
            
            return True
        except Exception as e:
            logger.error(f"Error validating AI feature access: {str(e)}")
            return False
    
    @staticmethod
    def handle_ai_service_errors(error: Exception, context: str) -> Dict[str, Any]:
        """
        Standardized AI error handling
        
        Args:
            error: Exception that occurred
            context: Context where error occurred
            
        Returns:
            Error response dictionary
        """
        try:
            error_response = {
                'error_type': type(error).__name__,
                'error_message': str(error),
                'context': context,
                'timestamp': datetime.utcnow().isoformat(),
                'suggestion': 'Please try again or contact support if the issue persists'
            }
            
            # Add specific suggestions based on error type
            if 'API' in str(error):
                error_response['suggestion'] = 'API service may be temporarily unavailable'
            elif 'JSON' in str(error):
                error_response['suggestion'] = 'Response format error - please try again'
            elif 'timeout' in str(error).lower():
                error_response['suggestion'] = 'Request timed out - please try with smaller data set'
            
            # Log the error
            logger.error(f"AI service error in {context}: {str(error)}")
            
            return error_response
        except Exception as e:
            logger.error(f"Error in error handling: {str(e)}")
            return {'error': 'Unknown error occurred'}
    
    @staticmethod
    def monitor_ai_performance(feature_name: str, execution_time: float, success: bool) -> None:
        """
        Track AI feature performance
        
        Args:
            feature_name: Name of AI feature
            execution_time: Time taken in seconds
            success: Whether operation was successful
        """
        try:
            performance_entry = {
                'feature': feature_name,
                'execution_time': execution_time,
                'success': success,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Store performance data (in production, use proper monitoring service)
            logger.info(f"AI performance: {feature_name} - {execution_time:.2f}s - {'Success' if success else 'Failed'}")
        except Exception as e:
            logger.error(f"Error monitoring AI performance: {str(e)}")
    
    @staticmethod
    def generate_ai_usage_reports(time_period: str = 'daily') -> Dict[str, Any]:
        """
        Generate usage analytics for AI features
        
        Args:
            time_period: Time period for report (daily, weekly, monthly)
            
        Returns:
            Usage report
        """
        try:
            current_time = time.time()
            period_seconds = {
                'daily': 86400,
                'weekly': 604800,
                'monthly': 2592000
            }.get(time_period, 86400)
            
            cutoff_time = current_time - period_seconds
            
            # Filter usage data by time period
            recent_usage = {}
            for user_id, usage_list in _usage_analytics.items():
                recent_usage[user_id] = [
                    entry for entry in usage_list
                    if datetime.fromisoformat(entry['timestamp']).timestamp() > cutoff_time
                ]
            
            # Generate report
            report = {
                'time_period': time_period,
                'total_users': len(recent_usage),
                'total_requests': sum(len(usage) for usage in recent_usage.values()),
                'feature_usage': {},
                'top_users': [],
                'generated_at': datetime.utcnow().isoformat()
            }
            
            # Count feature usage
            feature_counts = {}
            for usage_list in recent_usage.values():
                for entry in usage_list:
                    feature = entry['feature_used']
                    feature_counts[feature] = feature_counts.get(feature, 0) + 1
            
            report['feature_usage'] = feature_counts
            
            # Top users by request count
            user_counts = [(user_id, len(usage)) for user_id, usage in recent_usage.items()]
            user_counts.sort(key=lambda x: x[1], reverse=True)
            report['top_users'] = user_counts[:10]
            
            return report
        except Exception as e:
            logger.error(f"Error generating AI usage reports: {str(e)}")
            return {'error': str(e)}
    
    @staticmethod
    def anonymize_data_for_ai(data: Any, anonymization_level: str = 'medium') -> Any:
        """
        Protect sensitive data in AI requests
        
        Args:
            data: Data to anonymize
            anonymization_level: Level of anonymization (low, medium, high)
            
        Returns:
            Anonymized data
        """
        try:
            if anonymization_level == 'low':
                return data
            elif anonymization_level == 'medium':
                # Anonymize user IDs and personal information
                if isinstance(data, dict):
                    anonymized = data.copy()
                    if 'user_id' in anonymized:
                        anonymized['user_id'] = f"user_{hash(str(anonymized['user_id'])) % 10000}"
                    if 'username' in anonymized:
                        anonymized['username'] = f"user_{hash(str(anonymized['username'])) % 10000}"
                    return anonymized
                return data
            elif anonymization_level == 'high':
                # Remove all personally identifiable information
                if isinstance(data, dict):
                    anonymized = {}
                    sensitive_keys = ['user_id', 'username', 'email', 'name', 'address']
                    for key, value in data.items():
                        if key not in sensitive_keys:
                            anonymized[key] = value
                    return anonymized
                return {}
            
            return data
        except Exception as e:
            logger.error(f"Error anonymizing data: {str(e)}")
            return data
    
    @staticmethod
    def validate_data_privacy_compliance(data: Any, feature_type: str) -> bool:
        """
        Ensure privacy compliance
        
        Args:
            data: Data to validate
            feature_type: Type of AI feature
            
        Returns:
            True if compliant
        """
        try:
            # Check for sensitive data
            sensitive_patterns = ['ssn', 'credit_card', 'password', 'secret']
            data_str = str(data).lower()
            
            for pattern in sensitive_patterns:
                if pattern in data_str:
                    logger.warning(f"Sensitive data detected in {feature_type} request")
                    return False
            
            return True
        except Exception as e:
            logger.error(f"Error validating privacy compliance: {str(e)}")
            return False
    
    @staticmethod
    def encrypt_ai_cache_data(data: Any) -> str:
        """
        Secure cached AI results
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data string
        """
        try:
            # Simple encoding (in production, use proper encryption)
            import base64
            data_str = json.dumps(data)
            encoded = base64.b64encode(data_str.encode()).decode()
            return encoded
        except Exception as e:
            logger.error(f"Error encrypting cache data: {str(e)}")
            return str(data)


# Decorator for AI feature rate limiting
def ai_rate_limit(feature_type: str):
    """
    Decorator to apply rate limiting to AI features
    
    Args:
        feature_type: Type of AI feature for rate limiting
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Get current user (assuming it's available in context)
            from flask_login import current_user
            if current_user.is_authenticated:
                if not AIUtils.rate_limit_ai_calls(current_user.id, feature_type):
                    return jsonify({'error': 'Rate limit exceeded for AI feature'}), 429
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Decorator for AI performance monitoring
def monitor_ai_performance(feature_name: str):
    """
    Decorator to monitor AI feature performance
    
    Args:
        feature_name: Name of AI feature to monitor
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            success = True
            
            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                raise e
            finally:
                execution_time = time.time() - start_time
                AIUtils.monitor_ai_performance(feature_name, execution_time, success)
        
        return wrapper
    return decorator
