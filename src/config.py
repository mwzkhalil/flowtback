import os
from dotenv import load_dotenv

# Load .env file explicitly at the start
load_dotenv()

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, '..', 'instance', 'flowtrack.db')

class Config:
    """
    Configuration class for FlowTrack application.
    Organized into logical sections with clear comments and no duplicate keys.
    """
    
    # ========================================
    # CORE APPLICATION SETTINGS
    # ========================================
    
    # Flask Core Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-default-secret-key-for-development'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + db_path
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Enterprise Account/Signup Controls
    PUBLIC_SIGNUP_ENABLED = False
    DEFAULT_SUBSCRIPTION_TIER = os.environ.get('DEFAULT_SUBSCRIPTION_TIER', 'free')
    ADMIN_RATE_LIMIT_PER_MINUTE = int(os.environ.get('ADMIN_RATE_LIMIT_PER_MINUTE', 60))
    TEMP_PASSWORD_LENGTH = int(os.environ.get('TEMP_PASSWORD_LENGTH', 12))

    
    # File Upload Configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
    
    # ========================================
    # API CONFIGURATION
    # ========================================
    
    # Anthropic API Configuration
    ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY')
    if not ANTHROPIC_API_KEY:
        print("WARNING: ANTHROPIC_API_KEY not found in environment variables")
    
    # Anthropic Model Configuration
    stable_model = os.environ.get('ANTHROPIC_DEFAULT_MODEL') or 'claude-opus-4-1-20250805'
    ANTHROPIC_MODEL_CONFIGS = {
        'default_model': stable_model,
        'categorization_model': os.environ.get('ANTHROPIC_CATEGORIZATION_MODEL', stable_model),
        'risk_assessment_model': os.environ.get('ANTHROPIC_RISK_ASSESSMENT_MODEL', stable_model),
        'anomaly_detection_model': os.environ.get('ANTHROPIC_ANOMALY_DETECTION_MODEL', stable_model),
        'advanced_forecast_model': os.environ.get('ANTHROPIC_ADVANCED_FORECAST_MODEL', stable_model),
        'custom_insights_model': os.environ.get('ANTHROPIC_CUSTOM_INSIGHTS_MODEL', stable_model),
        'chatbot_model': os.environ.get('ANTHROPIC_CHATBOT_MODEL', stable_model)
    }
    
    # Anthropic Token Limits per Feature
    ANTHROPIC_MAX_TOKENS = {
        'categorization': int(os.environ.get('ANTHROPIC_MAX_TOKENS_CATEGORIZATION', 4000)),
        'risk_assessment': int(os.environ.get('ANTHROPIC_MAX_TOKENS_RISK_ASSESSMENT', 6000)),
        'anomaly_detection': int(os.environ.get('ANTHROPIC_MAX_TOKENS_ANOMALY_DETECTION', 5000)),
        'advanced_forecast': int(os.environ.get('ANTHROPIC_MAX_TOKENS_ADVANCED_FORECAST', 6000)),
        'custom_insights': int(os.environ.get('ANTHROPIC_MAX_TOKENS_CUSTOM_INSIGHTS', 6000)),
        'chatbot': int(os.environ.get('ANTHROPIC_MAX_TOKENS_CHATBOT', 2000))
    }
    
    # Anthropic Timeout Settings
    ANTHROPIC_TIMEOUT_SETTINGS = {
        'default_timeout': int(os.environ.get('ANTHROPIC_DEFAULT_TIMEOUT', 60)),  # seconds
        'categorization_timeout': int(os.environ.get('ANTHROPIC_CATEGORIZATION_TIMEOUT', 30)),
        'risk_assessment_timeout': int(os.environ.get('ANTHROPIC_RISK_ASSESSMENT_TIMEOUT', 60)),
        'anomaly_detection_timeout': int(os.environ.get('ANTHROPIC_ANOMALY_DETECTION_TIMEOUT', 45)),
        'advanced_forecast_timeout': int(os.environ.get('ANTHROPIC_ADVANCED_FORECAST_TIMEOUT', 90)),
        'custom_insights_timeout': int(os.environ.get('ANTHROPIC_CUSTOM_INSIGHTS_TIMEOUT', 60)),
        'chatbot_timeout': int(os.environ.get('ANTHROPIC_CHATBOT_TIMEOUT', 30))
    }
    
    # Anthropic Retry Configuration
    ANTHROPIC_RETRY_SETTINGS = {
        'max_retries': int(os.environ.get('ANTHROPIC_MAX_RETRIES', 3)),
        'retry_delay': int(os.environ.get('ANTHROPIC_RETRY_DELAY', 2)),  # seconds
        'backoff_factor': float(os.environ.get('ANTHROPIC_BACKOFF_FACTOR', 2.0))
    }
    
    # ========================================
    # AI FEATURE CONFIGURATION
    # ========================================
    
    # AI Feature Toggles
    AI_FEATURES_ENABLED = os.environ.get('AI_FEATURES_ENABLED', 'true').lower() == 'true'
    AI_DASHBOARD_ENABLED = os.environ.get('AI_DASHBOARD_ENABLED', 'true').lower() == 'true'
    CHATBOT_ENABLED = os.environ.get('CHATBOT_ENABLED', 'true').lower() == 'true'
    
    # AI Rate Limits (requests per hour per user)
    AI_RATE_LIMITS = {
        'categorization': int(os.environ.get('AI_RATE_LIMIT_CATEGORIZATION', 100)),
        'risk_assessment': int(os.environ.get('AI_RATE_LIMIT_RISK_ASSESSMENT', 20)),
        'anomaly_detection': int(os.environ.get('AI_RATE_LIMIT_ANOMALY_DETECTION', 30)),
        'advanced_forecast': int(os.environ.get('AI_RATE_LIMIT_ADVANCED_FORECAST', 15)),
        'custom_insights': int(os.environ.get('AI_RATE_LIMIT_CUSTOM_INSIGHTS', 50)),
        'chatbot': int(os.environ.get('AI_RATE_LIMIT_CHATBOT', 200))
    }
    
    # AI Cache Settings (TTL in seconds)
    AI_CACHE_TTL = {
        'categorization': int(os.environ.get('AI_CACHE_TTL_CATEGORIZATION', 3600)),  # 1 hour
        'risk_assessment': int(os.environ.get('AI_CACHE_TTL_RISK_ASSESSMENT', 1800)),  # 30 minutes
        'anomaly_detection': int(os.environ.get('AI_CACHE_TTL_ANOMALY_DETECTION', 900)),  # 15 minutes
        'advanced_forecast': int(os.environ.get('AI_CACHE_TTL_ADVANCED_FORECAST', 3600)),  # 1 hour
        'custom_insights': int(os.environ.get('AI_CACHE_TTL_CUSTOM_INSIGHTS', 1800)),  # 30 minutes
        'chatbot': int(os.environ.get('AI_CACHE_TTL_CHATBOT', 1800))  # 30 minutes
    }
    
    # AI Batch Sizes for bulk operations
    AI_BATCH_SIZES = {
        'categorization': int(os.environ.get('AI_BATCH_SIZE_CATEGORIZATION', 50)),
        'risk_assessment': int(os.environ.get('AI_BATCH_SIZE_RISK_ASSESSMENT', 10)),
        'anomaly_detection': int(os.environ.get('AI_BATCH_SIZE_ANOMALY_DETECTION', 100)),
        'advanced_forecast': int(os.environ.get('AI_BATCH_SIZE_ADVANCED_FORECAST', 1)),
        'custom_insights': int(os.environ.get('AI_BATCH_SIZE_CUSTOM_INSIGHTS', 5)),
        'chatbot': int(os.environ.get('AI_BATCH_SIZE_CHATBOT', 1))
    }
    
    # AI Model Configuration
    AI_DEFAULT_MODEL = os.environ.get('AI_DEFAULT_MODEL', 'claude-3-opus-20240229')
    AI_FALLBACK_MODEL = os.environ.get('AI_FALLBACK_MODEL', 'claude-3-haiku-20240307')
    AI_MAX_TOKENS = int(os.environ.get('AI_MAX_TOKENS', 4000))
    AI_TEMPERATURE = float(os.environ.get('AI_TEMPERATURE', 0.1))
    
    # ========================================
    # AI DASHBOARD CONFIGURATION
    # ========================================
    
    # Dashboard Refresh and Caching
    AI_DASHBOARD_REFRESH_INTERVAL = int(os.environ.get('AI_DASHBOARD_REFRESH_INTERVAL', 30))  # seconds
    AI_DASHBOARD_CACHE_TTL = int(os.environ.get('AI_DASHBOARD_CACHE_TTL', 300))  # 5 minutes
    AI_DASHBOARD_MAX_ACTIVITIES = int(os.environ.get('AI_DASHBOARD_MAX_ACTIVITIES', 10))
    AI_DASHBOARD_PERFORMANCE_WINDOW = int(os.environ.get('AI_DASHBOARD_PERFORMANCE_WINDOW', 24))  # hours
    
    # ========================================
    # AI SERVICE CONFIGURATION
    # ========================================
    
    # Service Timeout and Retry Settings
    AI_SERVICE_TIMEOUT = int(os.environ.get('AI_SERVICE_TIMEOUT', 30))  # seconds
    AI_SERVICE_RETRY_ATTEMPTS = int(os.environ.get('AI_SERVICE_RETRY_ATTEMPTS', 3))
    AI_SERVICE_HEALTH_CHECK_INTERVAL = int(os.environ.get('AI_SERVICE_HEALTH_CHECK_INTERVAL', 60))  # seconds
    AI_SERVICE_FALLBACK_ENABLED = os.environ.get('AI_SERVICE_FALLBACK_ENABLED', 'true').lower() == 'true'
    
    # ========================================
    # AI FEATURE-SPECIFIC CONFIGURATION
    # ========================================
    
    # Risk Assessment Configuration
    AI_RISK_ASSESSMENT_CONFIG = {
        'enable_stress_testing': os.environ.get('AI_RISK_STRESS_TESTING', 'true').lower() == 'true',
        'enable_monte_carlo': os.environ.get('AI_RISK_MONTE_CARLO', 'true').lower() == 'true',
        'confidence_threshold': float(os.environ.get('AI_RISK_CONFIDENCE_THRESHOLD', 0.8)),
        'max_scenarios': int(os.environ.get('AI_RISK_MAX_SCENARIOS', 10))
    }
    
    # Anomaly Detection Configuration
    AI_ANOMALY_DETECTION_CONFIG = {
        'sensitivity': float(os.environ.get('AI_ANOMALY_SENSITIVITY', 0.1)),
        'min_confidence': float(os.environ.get('AI_ANOMALY_MIN_CONFIDENCE', 0.7)),
        'enable_ml_patterns': os.environ.get('AI_ANOMALY_ML_PATTERNS', 'true').lower() == 'true',
        'enable_behavioral_analysis': os.environ.get('AI_ANOMALY_BEHAVIORAL', 'true').lower() == 'true'
    }
    
    # Anomaly Detection Sensitivity Settings
    AI_ANOMALY_DETECTION_SENSITIVITY = {
        'amount_deviation_threshold': float(os.environ.get('AI_AMOUNT_DEVIATION_THRESHOLD', 3.0)),  # standard deviations
        'frequency_deviation_threshold': float(os.environ.get('AI_FREQUENCY_DEVIATION_THRESHOLD', 2.0)),
        'time_deviation_threshold': int(os.environ.get('AI_TIME_DEVIATION_THRESHOLD', 4)),  # hours
        'geographic_deviation_threshold': float(os.environ.get('AI_GEOGRAPHIC_DEVIATION_THRESHOLD', 500.0))  # miles
    }
    
    # Forecasting Configuration
    AI_FORECASTING_CONFIG = {
        'forecast_horizon_days': int(os.environ.get('AI_FORECAST_HORIZON', 90)),
        'confidence_intervals': os.environ.get('AI_FORECAST_CONFIDENCE_INTERVALS', '90,95,99').split(','),
        'enable_scenario_analysis': os.environ.get('AI_FORECAST_SCENARIOS', 'true').lower() == 'true',
        'seasonality_detection': os.environ.get('AI_FORECAST_SEASONALITY', 'true').lower() == 'true'
    }
    
    # ========================================
    # AI BUSINESS LOGIC CONFIGURATION
    # ========================================
    
    # Confidence Thresholds per Feature
    AI_CONFIDENCE_THRESHOLDS = {
        'categorization': float(os.environ.get('AI_CONFIDENCE_THRESHOLD_CATEGORIZATION', 80.0)),
        'risk_assessment': float(os.environ.get('AI_CONFIDENCE_THRESHOLD_RISK_ASSESSMENT', 75.0)),
        'anomaly_detection': float(os.environ.get('AI_CONFIDENCE_THRESHOLD_ANOMALY_DETECTION', 70.0)),
        'advanced_forecast': float(os.environ.get('AI_CONFIDENCE_THRESHOLD_ADVANCED_FORECAST', 85.0)),
        'custom_insights': float(os.environ.get('AI_CONFIDENCE_THRESHOLD_CUSTOM_INSIGHTS', 75.0))
    }
    
    # Business Rules for AI Output Validation
    AI_BUSINESS_RULES = {
        'min_amount': float(os.environ.get('AI_MIN_AMOUNT', 0.01)),
        'max_amount': float(os.environ.get('AI_MAX_AMOUNT', 1000000.0)),
        'min_confidence': float(os.environ.get('AI_MIN_CONFIDENCE', 70.0)),
        'max_single_transaction': float(os.environ.get('AI_MAX_SINGLE_TRANSACTION', 100000.0)),
        'valid_categories': [
            'Cash-customer', 'Salary-suppliers', 'Income-tax', 'Other-cfo',
            'Buy-property-equipments', 'Sell-property-equipments', 'Buy-investment', 'Sell-investment', 'Other-cfi',
            'Issue-shares', 'borrowings', 'Repay-borrowings', 'Pay-dividends', 'Interest-paid', 'Other-cff'
        ]
    }
    
    # Custom Rules for Transaction Categorization
    AI_CATEGORIZATION_RULES = {
        'income_keywords': ['salary', 'wage', 'payment', 'invoice', 'revenue', 'income', 'earnings'],
        'expense_keywords': ['purchase', 'payment', 'bill', 'expense', 'cost', 'fee', 'charge'],
        'investment_keywords': ['investment', 'stock', 'bond', 'fund', 'portfolio', 'trading'],
        'tax_keywords': ['tax', 'irs', 'federal', 'state', 'withholding', 'deduction']
    }
    
    # ========================================
    # AI USAGE LIMITS AND PERMISSIONS
    # ========================================
    
    # AI Feature Permissions (role-based access)
    AI_FEATURE_PERMISSIONS = {
        'categorization': 'super_admin',
        'risk_assessment': 'super_admin',
        'anomaly_detection': 'super_admin',
        'advanced_forecast': 'super_admin',
        'custom_insights': 'super_admin',
        'ai_dashboard': 'super_admin',
        'chatbot': 'super_admin'
    }
    
    # AI Feature Usage Limits
    AI_FEATURE_USAGE_LIMITS = {
        'daily_limit': int(os.environ.get('AI_DAILY_USAGE_LIMIT', 1000)),
        'monthly_limit': int(os.environ.get('AI_MONTHLY_USAGE_LIMIT', 30000)),
        'per_user_daily_limit': int(os.environ.get('AI_PER_USER_DAILY_LIMIT', 100)),
        'per_user_monthly_limit': int(os.environ.get('AI_PER_USER_MONTHLY_LIMIT', 3000))
    }
    
    # ========================================
    # AI MONITORING AND PERFORMANCE
    # ========================================
    
    # Performance Monitoring Configuration
    AI_PERFORMANCE_MONITORING_ENABLED = os.environ.get('AI_PERFORMANCE_MONITORING_ENABLED', 'true').lower() == 'true'
    AI_PERFORMANCE_METRICS_RETENTION = int(os.environ.get('AI_PERFORMANCE_METRICS_RETENTION', 30))  # days
    AI_PERFORMANCE_ALERT_THRESHOLDS = {
        'response_time_ms': int(os.environ.get('AI_PERFORMANCE_ALERT_RESPONSE_TIME', 5000)),
        'error_rate_percent': float(os.environ.get('AI_PERFORMANCE_ALERT_ERROR_RATE', 5.0)),
        'success_rate_percent': float(os.environ.get('AI_PERFORMANCE_ALERT_SUCCESS_RATE', 95.0))
    }
    AI_PERFORMANCE_REPORTING_INTERVAL = int(os.environ.get('AI_PERFORMANCE_REPORTING_INTERVAL', 3600))  # seconds
    
    # Usage Analytics Configuration
    AI_USAGE_ANALYTICS_ENABLED = os.environ.get('AI_USAGE_ANALYTICS_ENABLED', 'true').lower() == 'true'
    AI_ERROR_REPORTING_ENABLED = os.environ.get('AI_ERROR_REPORTING_ENABLED', 'true').lower() == 'true'
    
    # ========================================
    # AI ERROR HANDLING AND LOGGING
    # ========================================
    
    # Error Handling Configuration
    AI_ERROR_LOGGING_LEVEL = os.environ.get('AI_ERROR_LOGGING_LEVEL', 'INFO').upper()
    AI_ERROR_NOTIFICATION_ENABLED = os.environ.get('AI_ERROR_NOTIFICATION_ENABLED', 'true').lower() == 'true'
    AI_ERROR_RETRY_DELAY = int(os.environ.get('AI_ERROR_RETRY_DELAY', 1000))  # milliseconds
    AI_ERROR_MAX_LOG_SIZE = int(os.environ.get('AI_ERROR_MAX_LOG_SIZE', 10000))  # entries
    
    # ========================================
    # AI SECURITY AND PRIVACY
    # ========================================
    
    # Security Configuration
    AI_AUDIT_LOGGING_ENABLED = os.environ.get('AI_AUDIT_LOGGING_ENABLED', 'true').lower() == 'true'
    AI_DATA_ENCRYPTION_ENABLED = os.environ.get('AI_DATA_ENCRYPTION_ENABLED', 'false').lower() == 'true'
    AI_ACCESS_LOGGING_ENABLED = os.environ.get('AI_ACCESS_LOGGING_ENABLED', 'true').lower() == 'true'
    AI_SECURITY_MONITORING_ENABLED = os.environ.get('AI_SECURITY_MONITORING_ENABLED', 'true').lower() == 'true'
    
    # Privacy and Data Protection
    AI_DATA_ANONYMIZATION_LEVEL = os.environ.get('AI_DATA_ANONYMIZATION_LEVEL', 'medium')  # low, medium, high
    AI_CACHE_ENCRYPTION_ENABLED = os.environ.get('AI_CACHE_ENCRYPTION_ENABLED', 'true').lower() == 'true'
    
    # ========================================
    # AI USER INTERFACE CONFIGURATION
    # ========================================
    
    # UI Theme and Behavior
    AI_UI_THEME = os.environ.get('AI_UI_THEME', 'default')
    AI_UI_ANIMATION_ENABLED = os.environ.get('AI_UI_ANIMATION_ENABLED', 'true').lower() == 'true'
    AI_UI_NOTIFICATION_DURATION = int(os.environ.get('AI_UI_NOTIFICATION_DURATION', 5000))  # milliseconds
    AI_UI_AUTO_REFRESH_ENABLED = os.environ.get('AI_UI_AUTO_REFRESH_ENABLED', 'true').lower() == 'true'
    
    # ========================================
    # CHATBOT CONFIGURATION
    # ========================================
    
    # Chatbot Core Settings
    CHATBOT_MAX_QUERY_LENGTH = int(os.environ.get('CHATBOT_MAX_QUERY_LENGTH', 500))
    CHATBOT_MAX_RESULTS = int(os.environ.get('CHATBOT_MAX_RESULTS', 1000))
    CHATBOT_QUERY_TIMEOUT = int(os.environ.get('CHATBOT_QUERY_TIMEOUT', 30))
    
    # Chatbot Security Configuration
    CHATBOT_ALLOWED_TABLES = [
        'user', 'transaction', 'initial_balance', 'role', 'permission', 
        'user_roles', 'role_permissions'
    ]
    CHATBOT_ALLOWED_OPERATIONS = [
        'SELECT', 'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'GROUP BY', 'ORDER BY', 'WHERE', 'HAVING'
    ]
    CHATBOT_MAX_EXECUTION_TIME = int(os.environ.get('CHATBOT_MAX_EXECUTION_TIME', 30))
    CHATBOT_RESULT_ANONYMIZATION = os.environ.get('CHATBOT_RESULT_ANONYMIZATION', 'medium')
    
    # Query Validation Settings
    CHATBOT_SQL_VALIDATION_ENABLED = os.environ.get('CHATBOT_SQL_VALIDATION_ENABLED', 'true').lower() == 'true'
    CHATBOT_INJECTION_DETECTION_ENABLED = os.environ.get('CHATBOT_INJECTION_DETECTION_ENABLED', 'true').lower() == 'true'
    CHATBOT_QUERY_LOGGING_ENABLED = os.environ.get('CHATBOT_QUERY_LOGGING_ENABLED', 'true').lower() == 'true'
    
    # Chatbot Performance Settings
    CHATBOT_CACHE_ENABLED = os.environ.get('CHATBOT_CACHE_ENABLED', 'true').lower() == 'true'
    CHATBOT_CACHE_TTL = int(os.environ.get('CHATBOT_CACHE_TTL', 1800))  # 30 minutes
    CHATBOT_RATE_LIMIT_PER_USER = int(os.environ.get('CHATBOT_RATE_LIMIT_PER_USER', 200))
    
    # Chatbot Business Logic Configuration
    CHATBOT_DEFAULT_DATE_RANGE = os.environ.get('CHATBOT_DEFAULT_DATE_RANGE', '12 months')
    CHATBOT_CURRENCY_FORMAT = os.environ.get('CHATBOT_CURRENCY_FORMAT', 'USD')
    CHATBOT_DATE_FORMAT = os.environ.get('CHATBOT_DATE_FORMAT', 'YYYY-MM-DD')
    
    # ========================================
    # DEVELOPMENT AND TESTING SETTINGS
    # ========================================
    
    # Development/Testing Toggles
    AI_MOCK_RESPONSES_ENABLED = os.environ.get('AI_MOCK_RESPONSES_ENABLED', 'false').lower() == 'true'
    AI_DEBUG_LOGGING_ENABLED = os.environ.get('AI_DEBUG_LOGGING_ENABLED', 'false').lower() == 'true'
    AI_TEST_MODE_ENABLED = os.environ.get('AI_TEST_MODE_ENABLED', 'false').lower() == 'true'
    
    # ========================================
    # CONFIGURATION INITIALIZATION LOGGING
    # ========================================
    
    # Enhanced debugging information
    print(f"Configuration initialized:")
    print(f"- Database path: {db_path}")
    print(f"- Anthropic API Key status: {'Set' if ANTHROPIC_API_KEY else 'Not set'}")
    print(f"- API Key length: {len(ANTHROPIC_API_KEY) if ANTHROPIC_API_KEY else 0}")
    print(f"- AI Features Enabled: {AI_FEATURES_ENABLED}")
    print(f"- AI Rate Limits: {AI_RATE_LIMITS}")
    print(f"- AI Cache TTL: {AI_CACHE_TTL}")
    print(f"- AI Model Configs: {ANTHROPIC_MODEL_CONFIGS}")
    print(f"- AI Performance Monitoring: {AI_PERFORMANCE_MONITORING_ENABLED}")
    print(f"- AI Audit Logging: {AI_AUDIT_LOGGING_ENABLED}")
    print(f"- Chatbot Enabled: {CHATBOT_ENABLED}")
    print(f"- Chatbot Rate Limit: {CHATBOT_RATE_LIMIT_PER_USER}")

def create_app():
    """Create and configure Flask application"""
    from flask import Flask
    from src.models import db
    from flask_migrate import Migrate
    from flask_login import LoginManager
    
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')
    app.config.from_object(Config)
    
    db.init_app(app)
    migrate = Migrate(app, db)
    
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'
    
    return app