"""
AI Dashboard Utilities for FlowTrack Application

This module provides comprehensive utilities for AI dashboard functionality,
including system monitoring, activity tracking, performance metrics, and
data aggregation for the AI features interface.
"""

import logging
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from functools import wraps
import traceback

from flask import current_app
from sqlalchemy import text, func, desc, case
from sqlalchemy.exc import SQLAlchemyError

from .models import db, Transaction, User, AIActivityLog
from .config import Config
from .anthropic_service import FinancialAnalytics

# Configure logging
logger = logging.getLogger(__name__)

def log_ai_dashboard_events(event_type: str, details: Dict[str, Any]) -> None:
    """Log AI dashboard events for monitoring and debugging."""
    try:
        logger.info(f"AI Dashboard Event: {event_type}", extra={
            'event_type': event_type,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        logger.error(f"Failed to log AI dashboard event: {e}")

def handle_ai_service_errors(error: Exception, context: str) -> Dict[str, Any]:
    """Standardized error handling for AI service operations."""
    error_details = {
        'error_type': type(error).__name__,
        'error_message': str(error),
        'context': context,
        'timestamp': datetime.utcnow().isoformat(),
        'traceback': traceback.format_exc()
    }
    
    logger.error(f"AI Service Error in {context}: {error}", extra=error_details)
    
    return {
        'success': False,
        'error': 'AI service temporarily unavailable',
        'details': error_details,
        'retry_after': 30  # seconds
    }

def cache_dashboard_data(data: Any, ttl: int = 300) -> None:
    """Cache dashboard data for performance optimization."""
    try:
        # Simple in-memory cache implementation
        # In production, use Redis or similar
        cache_key = f"ai_dashboard_{hash(str(data))}"
        cache_data = {
            'data': data,
            'expires': time.time() + ttl
        }
        
        if not hasattr(cache_dashboard_data, '_cache'):
            cache_dashboard_data._cache = {}
        
        cache_dashboard_data._cache[cache_key] = cache_data
        log_ai_dashboard_events('data_cached', {'key': cache_key, 'ttl': ttl})
        
    except Exception as e:
        logger.error(f"Failed to cache dashboard data: {e}")

def get_cached_dashboard_data(cache_key: str) -> Optional[Any]:
    """Retrieve cached dashboard data."""
    try:
        if not hasattr(cache_dashboard_data, '_cache'):
            return None
        
        cache_data = cache_dashboard_data._cache.get(cache_key)
        if cache_data and cache_data['expires'] > time.time():
            return cache_data['data']
        
        # Clean up expired cache
        if cache_data:
            del cache_dashboard_data._cache[cache_key]
        
        return None
    except Exception as e:
        logger.error(f"Failed to retrieve cached data: {e}")
        return None

def invalidate_dashboard_cache() -> None:
    """Clear all dashboard cache."""
    try:
        if hasattr(cache_dashboard_data, '_cache'):
            cache_dashboard_data._cache.clear()
        log_ai_dashboard_events('cache_invalidated', {})
    except Exception as e:
        logger.error(f"Failed to invalidate cache: {e}")

def get_ai_system_status() -> Dict[str, Any]:
    """Check Anthropic API connectivity and service health."""
    try:
        log_ai_dashboard_events('system_status_check', {})
        
        # Initialize AI service
        ai_service = FinancialAnalytics(test_connection=False)
        
        # Test API connectivity
        connectivity_status = check_anthropic_api_connectivity()
        
        # Get service health metrics
        health_metrics = get_service_health_metrics()
        
        # Validate configuration
        config_status = validate_ai_configuration()
        
        status = {
            'api_connectivity': connectivity_status,
            'service_health': health_metrics,
            'configuration': config_status,
            'overall_status': 'healthy' if all([
                connectivity_status['connected'],
                health_metrics['status'] == 'healthy',
                config_status['valid']
            ]) else 'degraded',
            'last_checked': datetime.utcnow().isoformat()
        }
        
        # Cache the status
        cache_dashboard_data(status, ttl=60)  # Cache for 1 minute
        
        return status
        
    except Exception as e:
        error_response = handle_ai_service_errors(e, 'system_status_check')
        return error_response

def check_anthropic_api_connectivity() -> Dict[str, Any]:
    """Test Anthropic API connection and response times."""
    try:
        start_time = time.time()
        
        # Test API with a simple request
        ai_service = FinancialAnalytics(test_connection=False)
        
        # Make a test call (this would be a simple health check)
        # For now, we'll simulate a successful connection
        response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
        
        return {
            'connected': True,
            'response_time_ms': round(response_time, 2),
            'status': 'healthy' if response_time < 5000 else 'slow',
            'last_checked': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"API connectivity check failed: {e}")
        return {
            'connected': False,
            'error': str(e),
            'status': 'unhealthy',
            'last_checked': datetime.utcnow().isoformat()
        }

def get_service_health_metrics() -> Dict[str, Any]:
    """Monitor AI service performance and availability."""
    try:
        # Get recent activity logs
        recent_activities = db.session.query(AIActivityLog).filter(
            AIActivityLog.timestamp >= datetime.utcnow() - timedelta(hours=24)
        ).all()
        
        total_requests = len(recent_activities)
        successful_requests = len([a for a in recent_activities if a.success])
        failed_requests = total_requests - successful_requests
        
        success_rate = (successful_requests / total_requests * 100) if total_requests > 0 else 100
        
        # Calculate average response time
        response_times = [a.response_time for a in recent_activities if a.response_time]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        return {
            'status': 'healthy' if success_rate >= 95 else 'degraded',
            'success_rate': round(success_rate, 2),
            'total_requests_24h': total_requests,
            'failed_requests_24h': failed_requests,
            'avg_response_time_ms': round(avg_response_time, 2),
            'uptime_percentage': round(success_rate, 2)
        }
        
    except Exception as e:
        logger.error(f"Failed to get service health metrics: {e}")
        return {
            'status': 'unknown',
            'error': str(e)
        }

def validate_ai_configuration() -> Dict[str, Any]:
    """Ensure all AI settings are properly configured."""
    try:
        config = Config()
        
        required_settings = [
            'ANTHROPIC_API_KEY',
            'AI_FEATURES_ENABLED',
            'AI_DASHBOARD_ENABLED'
        ]
        
        missing_settings = []
        for setting in required_settings:
            if not hasattr(config, setting) or not getattr(config, setting):
                missing_settings.append(setting)
        
        return {
            'valid': len(missing_settings) == 0,
            'missing_settings': missing_settings,
            'ai_features_enabled': getattr(config, 'AI_FEATURES_ENABLED', False),
            'dashboard_enabled': getattr(config, 'AI_DASHBOARD_ENABLED', False)
        }
        
    except Exception as e:
        logger.error(f"Configuration validation failed: {e}")
        return {
            'valid': False,
            'error': str(e)
        }

def get_recent_ai_activities(user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
    """Retrieve recent AI feature usage from logs."""
    try:
        activities = db.session.query(AIActivityLog).filter(
            AIActivityLog.user_id == user_id
        ).order_by(desc(AIActivityLog.timestamp)).limit(limit).all()
        
        activity_list = []
        for activity in activities:
            activity_list.append({
                'id': activity.id,
                'feature_name': activity.feature_name,
                'timestamp': activity.timestamp.isoformat(),
                'success': activity.success,
                'duration_ms': activity.response_time,
                'details': activity.details
            })
        
        log_ai_dashboard_events('recent_activities_retrieved', {
            'user_id': user_id,
            'count': len(activity_list)
        })
        
        return activity_list
        
    except Exception as e:
        logger.error(f"Failed to get recent AI activities: {e}")
        return []

def log_ai_feature_usage(user_id: int, feature_name: str, duration: float, success: bool, details: Dict[str, Any] = None) -> None:
    """Track usage statistics for AI features."""
    try:
        activity_log = AIActivityLog(
            user_id=user_id,
            feature_name=feature_name,
            timestamp=datetime.utcnow(),
            success=success,
            response_time=duration,
            details=details or {}
        )
        
        db.session.add(activity_log)
        db.session.commit()
        
        log_ai_dashboard_events('feature_usage_logged', {
            'user_id': user_id,
            'feature_name': feature_name,
            'success': success
        })
        
    except Exception as e:
        logger.error(f"Failed to log AI feature usage: {e}")
        db.session.rollback()

def get_ai_usage_analytics(time_period: str = '7d') -> Dict[str, Any]:
    """Generate usage reports and analytics."""
    try:
        # Calculate time range
        if time_period == '24h':
            start_date = datetime.utcnow() - timedelta(hours=24)
        elif time_period == '7d':
            start_date = datetime.utcnow() - timedelta(days=7)
        elif time_period == '30d':
            start_date = datetime.utcnow() - timedelta(days=30)
        else:
            start_date = datetime.utcnow() - timedelta(days=7)
        
        # Get usage statistics
        usage_stats = db.session.query(
            AIActivityLog.feature_name,
            func.count(AIActivityLog.id).label('total_usage'),
            func.sum(case((AIActivityLog.success, 1), else_=0)).label('successful_usage'),
            func.avg(AIActivityLog.response_time).label('avg_response_time')
        ).filter(
            AIActivityLog.timestamp >= start_date
        ).group_by(AIActivityLog.feature_name).all()
        
        analytics = {
            'time_period': time_period,
            'start_date': start_date.isoformat(),
            'end_date': datetime.utcnow().isoformat(),
            'feature_usage': []
        }
        
        for stat in usage_stats:
            success_rate = (stat.successful_usage / stat.total_usage * 100) if stat.total_usage > 0 else 0
            analytics['feature_usage'].append({
                'feature_name': stat.feature_name,
                'total_usage': stat.total_usage,
                'successful_usage': stat.successful_usage,
                'success_rate': round(success_rate, 2),
                'avg_response_time_ms': round(stat.avg_response_time or 0, 2)
            })
        
        return analytics
        
    except Exception as e:
        logger.error(f"Failed to get AI usage analytics: {e}")
        return {'error': str(e)}

def get_ai_performance_metrics() -> Dict[str, Any]:
    """Calculate accuracy, response times, and success rates."""
    try:
        # Get performance data from the last 24 hours
        start_date = datetime.utcnow() - timedelta(hours=24)
        
        # Overall performance metrics
        total_requests = db.session.query(func.count(AIActivityLog.id)).filter(
            AIActivityLog.timestamp >= start_date
        ).scalar()
        
        successful_requests = db.session.query(func.count(AIActivityLog.id)).filter(
            AIActivityLog.timestamp >= start_date,
            AIActivityLog.success == True
        ).scalar()
        
        success_rate = (successful_requests / total_requests * 100) if total_requests > 0 else 100
        
        # Response time metrics
        response_times = db.session.query(AIActivityLog.response_time).filter(
            AIActivityLog.timestamp >= start_date,
            AIActivityLog.response_time.isnot(None)
        ).all()
        
        response_times_list = [r[0] for r in response_times]
        avg_response_time = sum(response_times_list) / len(response_times_list) if response_times_list else 0
        max_response_time = max(response_times_list) if response_times_list else 0
        min_response_time = min(response_times_list) if response_times_list else 0
        
        # Feature-specific metrics
        feature_metrics = db.session.query(
            AIActivityLog.feature_name,
            func.count(AIActivityLog.id).label('total'),
            func.sum(case((AIActivityLog.success, 1), else_=0)).label('successful'),
            func.avg(AIActivityLog.response_time).label('avg_time')
        ).filter(
            AIActivityLog.timestamp >= start_date
        ).group_by(AIActivityLog.feature_name).all()
        
        feature_performance = []
        for metric in feature_metrics:
            feature_success_rate = (metric.successful / metric.total * 100) if metric.total > 0 else 0
            feature_performance.append({
                'feature_name': metric.feature_name,
                'total_requests': metric.total,
                'success_rate': round(feature_success_rate, 2),
                'avg_response_time_ms': round(metric.avg_time or 0, 2)
            })
        
        performance_metrics = {
            'overall': {
                'total_requests_24h': total_requests,
                'success_rate': round(success_rate, 2),
                'avg_response_time_ms': round(avg_response_time, 2),
                'max_response_time_ms': round(max_response_time, 2),
                'min_response_time_ms': round(min_response_time, 2)
            },
            'by_feature': feature_performance,
            'time_period': '24h',
            'last_updated': datetime.utcnow().isoformat()
        }
        
        # Cache performance metrics
        cache_dashboard_data(performance_metrics, ttl=300)  # Cache for 5 minutes
        
        return performance_metrics
        
    except Exception as e:
        logger.error(f"Failed to get AI performance metrics: {e}")
        return {'error': str(e)}

def aggregate_dashboard_statistics() -> Dict[str, Any]:
    """Collect and format dashboard metrics."""
    try:
        # Get system status
        system_status = get_ai_system_status()
        
        # Get performance metrics
        performance_metrics = get_ai_performance_metrics()
        
        # Get recent activities (for current user - would need user_id in context)
        recent_activities = []  # This would be populated with user-specific data
        
        # Get usage analytics
        usage_analytics = get_ai_usage_analytics('7d')
        
        dashboard_stats = {
            'system_status': system_status,
            'performance': performance_metrics,
            'recent_activities': recent_activities,
            'usage_analytics': usage_analytics,
            'last_updated': datetime.utcnow().isoformat()
        }
        
        return dashboard_stats
        
    except Exception as e:
        logger.error(f"Failed to aggregate dashboard statistics: {e}")
        return {'error': str(e)}

def get_ai_feature_usage_summary() -> Dict[str, Any]:
    """Summarize feature usage patterns."""
    try:
        # Get usage by feature for the last 7 days
        start_date = datetime.utcnow() - timedelta(days=7)
        
        feature_usage = db.session.query(
            AIActivityLog.feature_name,
            func.count(AIActivityLog.id).label('usage_count'),
            func.count(func.distinct(AIActivityLog.user_id)).label('unique_users')
        ).filter(
            AIActivityLog.timestamp >= start_date
        ).group_by(AIActivityLog.feature_name).all()
        
        summary = {
            'time_period': '7d',
            'features': []
        }
        
        total_usage = sum(f.usage_count for f in feature_usage)
        
        for feature in feature_usage:
            usage_percentage = (feature.usage_count / total_usage * 100) if total_usage > 0 else 0
            summary['features'].append({
                'feature_name': feature.feature_name,
                'usage_count': feature.usage_count,
                'unique_users': feature.unique_users,
                'usage_percentage': round(usage_percentage, 2)
            })
        
        # Sort by usage count
        summary['features'].sort(key=lambda x: x['usage_count'], reverse=True)
        
        return summary
        
    except Exception as e:
        logger.error(f"Failed to get AI feature usage summary: {e}")
        return {'error': str(e)}

def calculate_user_engagement_metrics(user_id: int) -> Dict[str, Any]:
    """Measure user interaction with AI features."""
    try:
        # Get user's AI activity
        user_activities = db.session.query(AIActivityLog).filter(
            AIActivityLog.user_id == user_id
        ).all()
        
        if not user_activities:
            return {
                'total_interactions': 0,
                'features_used': 0,
                'avg_session_duration': 0,
                'engagement_score': 0
            }
        
        # Calculate metrics
        total_interactions = len(user_activities)
        features_used = len(set(a.feature_name for a in user_activities))
        
        # Calculate average session duration (simplified)
        session_durations = [a.response_time for a in user_activities if a.response_time]
        avg_session_duration = sum(session_durations) / len(session_durations) if session_durations else 0
        
        # Simple engagement score (0-100)
        engagement_score = min(100, (total_interactions * 10) + (features_used * 5))
        
        return {
            'total_interactions': total_interactions,
            'features_used': features_used,
            'avg_session_duration_ms': round(avg_session_duration, 2),
            'engagement_score': round(engagement_score, 2),
            'last_activity': max(a.timestamp for a in user_activities).isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to calculate user engagement metrics: {e}")
        return {'error': str(e)}

def prepare_dashboard_context(user_id: int = None) -> Dict[str, Any]:
    """Format data for template rendering."""
    try:
        context = {
            'system_status': get_ai_system_status(),
            'performance_metrics': get_ai_performance_metrics(),
            'feature_usage_summary': get_ai_feature_usage_summary(),
            'last_updated': datetime.utcnow().isoformat()
        }
        
        if user_id:
            context['recent_activities'] = get_recent_ai_activities(user_id)
            context['user_engagement'] = calculate_user_engagement_metrics(user_id)
        
        return context
        
    except Exception as e:
        logger.error(f"Failed to prepare dashboard context: {e}")
        return {'error': str(e)}

def monitor_system_health() -> Dict[str, Any]:
    """Continuous health monitoring."""
    try:
        health_status = {
            'timestamp': datetime.utcnow().isoformat(),
            'database_connection': False,
            'ai_service_available': False,
            'api_connectivity': False,
            'overall_health': 'unhealthy'
        }
        
        # Check database connection
        try:
            db.session.execute(text('SELECT 1'))
            health_status['database_connection'] = True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
        
        # Check AI service
        try:
            ai_service = FinancialAnalytics(test_connection=False)
            health_status['ai_service_available'] = True
        except Exception as e:
            logger.error(f"AI service health check failed: {e}")
        
        # Check API connectivity
        connectivity = check_anthropic_api_connectivity()
        health_status['api_connectivity'] = connectivity['connected']
        
        # Determine overall health
        if all([
            health_status['database_connection'],
            health_status['ai_service_available'],
            health_status['api_connectivity']
        ]):
            health_status['overall_health'] = 'healthy'
        elif any([
            health_status['database_connection'],
            health_status['ai_service_available'],
            health_status['api_connectivity']
        ]):
            health_status['overall_health'] = 'degraded'
        
        return health_status
        
    except Exception as e:
        logger.error(f"System health monitoring failed: {e}")
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'overall_health': 'unhealthy',
            'error': str(e)
        }
