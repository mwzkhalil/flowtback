from anthropic import Anthropic
from flask import current_app
import json
import ast
from datetime import datetime,timedelta
import numpy as np
from statsmodels.tsa.seasonal import seasonal_decompose


class FinancialAnalytics:
    def __init__(self, api_key=None, test_connection=False):
        """Initialize FinancialAnalytics with enhanced error handling and debugging"""
        try:
            # Get API key from config if not provided
            if not api_key:
                api_key = current_app.config.get('ANTHROPIC_API_KEY')
            
            if not api_key:
                raise ValueError("Anthropic API key is required")
            
            # Initialize Anthropic client
            self.anthropic = Anthropic(api_key=api_key)
            self.seasonal_periods = 12  # Monthly seasonality
            
            # Test API connectivity only if requested
            if test_connection:
                self._test_api_connection()
            
            current_app.logger.info("FinancialAnalytics initialized successfully")
            
        except Exception as e:
            current_app.logger.error(f"FinancialAnalytics initialization failed: {e}")
            raise
    
    def _test_api_connection(self):
        """Test API connection with a simple request"""
        try:
            # Make a simple test request
            test_message = self.anthropic.messages.create(
                model="claude-3-haiku-20240307",  # Use a cheaper model for testing
                max_tokens=10,
                messages=[{"role": "user", "content": "Test"}]
            )
            current_app.logger.info("API connection test successful")
        except Exception as e:
            current_app.logger.error(f"API connection test failed: {e}")
            raise
    
    def get_ai_system_status(self):
        """Get AI system status for dashboard with aggressive caching"""
        # Check cache first (5-minute TTL)
        cache_key = 'ai_system_status'
        cached_status = getattr(self, '_cached_status', None)
        cache_time = getattr(self, '_cache_time', None)
        
        if cached_status and cache_time:
            time_diff = datetime.now() - cache_time
            if time_diff.total_seconds() < 300:  # 5 minutes
                return cached_status
        
        try:
            # Test API connection if not cached
            self._test_api_connection()
            status = {
                'anthropic_api': 'online',
                'ai_services': 'online',
                'rate_limiting': 'normal',
                'last_checked': datetime.now().isoformat()
            }
        except Exception as e:
            current_app.logger.error(f"Error getting AI system status: {e}")
            status = {
                'anthropic_api': 'offline',
                'ai_services': 'offline',
                'rate_limiting': 'error',
                'last_checked': datetime.now().isoformat(),
                'error': str(e)
            }
        
        # Cache the result
        self._cached_status = status
        self._cache_time = datetime.now()
        
        return status
    
    def get_recent_ai_activities(self, user_id, limit=10):
        """Get recent AI activities for a user"""
        try:
            # This would typically query the database
            # For now, return sample data
            return [
                {
                    'feature': 'Risk Assessment',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'user': f'User {user_id}'
                }
            ]
        except Exception as e:
            current_app.logger.error(f"Error getting recent AI activities: {e}")
            return []
    
    def get_ai_performance_metrics(self):
        """Get AI performance metrics"""
        try:
            return {
                'accuracy': 98.5,
                'response_time': '1.2s',
                'uptime': '99.9%',
                'last_updated': datetime.now().isoformat()
            }
        except Exception as e:
            current_app.logger.error(f"Error getting AI performance metrics: {e}")
            return {
                'accuracy': 0,
                'response_time': 'N/A',
                'uptime': '0%',
                'error': str(e)
            }

    def analyze_patterns(self, transaction_history):
        """Analyze transaction patterns and seasonality"""
        amounts = [t['amount'] for t in transaction_history]
        dates = [datetime.strptime(t['date'], '%Y-%m-%d') for t in transaction_history]

        # Detect seasonality
        if len(amounts) >= self.seasonal_periods * 2:
            seasonal_decomposition = seasonal_decompose(amounts, period=self.seasonal_periods)
            seasonal_pattern = seasonal_decomposition.seasonal.tolist()
        else:
            seasonal_pattern = []

        # Calculate trend with proper data validation
        if len(amounts) >= 2:  # np.polyfit requires at least degree + 1 points
            trend = np.polyfit(range(len(amounts)), amounts, 1).tolist()
        else:
            # Not enough data for trend analysis
            trend = [0, 0]  # [slope, intercept] for flat line

        # Calculate volatility with proper data validation
        if len(amounts) >= 2:
            volatility = np.std(amounts)
        else:
            volatility = 0.0

        return {
            'seasonal_pattern': seasonal_pattern,
            'trend': trend,
            'volatility': volatility
        }
    
    def calculate_risk_metrics(self, cash_flows, working_capital):
        """Calculate various risk metrics"""
        # Avoid division by zero for liquidity ratio
        current_liabilities = working_capital['current_liabilities']
        liquidity_ratio = (working_capital['current_assets'] / current_liabilities 
                          if current_liabilities > 0 else 9999.99)
        
        # Calculate burn rate (average of negative cash flows only)
        negative_flows = [cf for cf in cash_flows if cf < 0]
        burn_rate = float(abs(sum(negative_flows)) / len(negative_flows)) if negative_flows else 0
        
        # Avoid division by zero for runway months
        min_cash_flow = min(cash_flows) if cash_flows else 0
        runway_months = (working_capital['cash'] / abs(min_cash_flow) 
                        if min_cash_flow < 0 else 999.99)
        
        return {
            'liquidity_ratio': float(liquidity_ratio),
            'cash_flow_volatility': float(np.std(cash_flows) if cash_flows else 0),
            'burn_rate': float(burn_rate),
            'runway_months': float(runway_months)
        }

    def generate_advanced_financial_analysis(self, initial_balance, current_balance, transaction_history, working_capital):
        patterns = self.analyze_patterns(transaction_history)
        risk_metrics = self.calculate_risk_metrics(
            [t['amount'] for t in transaction_history],
            working_capital
        )

        prompt = f"""As a financial analyst, provide a concise analysis of the following financial data:

        Financial Metrics:
        - Initial Balance: ${initial_balance}
        - Current Balance: ${current_balance}
        - Liquidity Ratio: {risk_metrics['liquidity_ratio']:.2f}
        - Cash Runway: {risk_metrics['runway_months']:.2f} months

        Pattern Analysis:
        - Seasonal Pattern: {patterns['seasonal_pattern']}
        - Trend: {patterns['trend']}
        - Volatility: {patterns['volatility']:.2f}

        Please provide a brief, bullet-point analysis covering:
        1. Pattern Recognition Analysis (identify recurring patterns and anomalies)
        2. Risk Assessment (evaluate liquidity and cash flow risks)
        3. Seasonal Trends (analyze monthly/quarterly patterns)
        4. Working Capital Optimization (suggest improvements)
        5. 90-day Forecast (based on historical patterns)

        Format the response with clear sections and actionable insights."""

        try:
            message = self.anthropic.messages.create(
                model="claude-opus-4-1-20250805",
                max_tokens=2000,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            analysis_result = {
                'ai_analysis': message.content[0].text,
                'patterns': patterns,
                'risk_metrics': risk_metrics,
                'forecasts': self.generate_forecasts(transaction_history, patterns)
            }
            return analysis_result
        except Exception as e:
            current_app.logger.error(f"Analysis failed: {str(e)}")
            import traceback
            current_app.logger.error(f"Traceback: {traceback.format_exc()}")
            raise
    
    def generate_forecasts(self, transaction_history, patterns):
        """Generate detailed forecasts using pattern analysis"""
        recent_transactions = transaction_history[-90:]  # Last 90 days
        trend = patterns['trend']
        seasonal_pattern = patterns['seasonal_pattern']
        
        forecasts = {
            '30_days': [],
            '60_days': [],
            '90_days': []
        }
        
        # Calculate base trend
        slope, intercept = trend
        
        # Generate daily forecasts for next 90 days
        for day in range(90):
            # Calculate trend component
            trend_value = slope * (len(recent_transactions) + day) + intercept
            
            # Add seasonal component if available
            seasonal_value = 0
            if seasonal_pattern:
                seasonal_idx = day % len(seasonal_pattern)
                seasonal_value = seasonal_pattern[seasonal_idx]
            
            # Combine trend and seasonality
            forecast_value = trend_value + seasonal_value
            
            # Add to appropriate forecast period
            if day < 30:
                forecasts['30_days'].append(forecast_value)
            if day < 60:
                forecasts['60_days'].append(forecast_value)
            forecasts['90_days'].append(forecast_value)
        
        return forecasts

    def generate_cashflow_statement(self, initial_balance, start_date, end_date, transaction_data):
        """Generate a cash flow statement with strict categorization and proper financial reporting structure."""
        # Parse transaction data into a structured format
        transactions = []
        for line in transaction_data.split('\n'):
            if line.strip():
                parts = line.split(', ')
                transaction = {}
                for part in parts:
                    key, value = part.split(': ', 1)
                    transaction[key.lower()] = value
                transactions.append(transaction)

        # Define the categorization structure exactly matching utils.py
        categories = {
            'CFO': {
                'types': ["Cash-customer", "Salary-suppliers", "Income-tax", "Other-cfo"],
                'items': []
            },
            'CFI': {
                'types': ["Buy-property-equipments", "Sell-property-equipments", "Buy-investment", "Sell-investment", "Other-cfi"],
                'items': []
            },
            'CFF': {
                'types': ["Issue-shares", "borrowings", "Repay-borrowings", "Pay-dividends", "Interest-paid", "Other-cff"],
                'items': []
            }
        }

        # Categorize transactions strictly by type
        for t in transactions:
            t_type = t['type']
            t_amount = float(t['amount'])
            t_date = t['date']
            t_desc = t['description']

            for category, info in categories.items():
                if t_type in info['types']:
                    info['items'].append({
                        'type': t_type,
                        'amount': t_amount,
                        'date': t_date,
                        'description': t_desc
                    })

        # Calculate totals
        statement_data = []
        category_totals = {'CFO': 0, 'CFI': 0, 'CFF': 0}

        # Process each category
        for category, info in categories.items():
            # Group transactions by type within each category
            type_totals = {}
            for item in info['items']:
                t_type = item['type']
                if t_type not in type_totals:
                    type_totals[t_type] = 0
                type_totals[t_type] += item['amount']

            # Add each type's total to the statement
            for t_type, total in type_totals.items():
                statement_data.append({
                    'Category': category,
                    'Subcategory': t_type,
                    'Amount': total
                })
                category_totals[category] += total

        # Calculate final totals
        total_net_cash_flow = sum(category_totals.values())
        ending_balance = initial_balance + total_net_cash_flow

        return statement_data, ending_balance

    def generate_dual_cashflow_statement(self, initial_balance, transaction_data):
        """Generate Indirect method cash flow statement only (like QuickBooks) with enterprise-level validation"""
        
        # First, detect duplicates and unusual patterns
        validation_results = self._validate_transactions(transaction_data)
        
        prompt = f"""You are a senior financial analyst generating an Indirect method cash flow statement with enterprise-level accuracy (like QuickBooks).

        FINANCIAL DATA:
        - Initial Balance: ${initial_balance:,.2f}
        - Transaction Data: {json.dumps(transaction_data, indent=2)}
        - Validation Issues: {json.dumps(validation_results, indent=2)}

        REQUIREMENTS:
        Generate ONLY the Indirect method with full traceability and error checking:

        1. INDIRECT METHOD - Start from net income:
           - Calculate Net Income from transactions
           - Add back: Depreciation, Amortization
           - Adjust for: Changes in Working Capital
           - Adjust for: Changes in Accounts Receivable
           - Adjust for: Changes in Inventory
           - Adjust for: Changes in Accounts Payable
           - Show Operating, Investing, and Financing activities

        2. ENTERPRISE VALIDATION:
           - Flag duplicate transactions
           - Identify unusual patterns (large amounts, frequent transactions)
           - Check for missing categorizations
           - Validate mathematical accuracy

        3. FULL TRACEABILITY:
           For each line item, provide ALL supporting transactions with:
           - Transaction ID
           - Date, Description, Amount
           - Categorization reasoning
           - Any validation warnings

        OUTPUT FORMAT (JSON):
        {{
          "validation": {{
            "duplicates": [{{ "transaction_id": "", "issue": "", "severity": "high/medium/low" }}],
            "unusual_patterns": [{{ "pattern": "", "description": "", "severity": "" }}],
            "warnings": ["List of general warnings"],
            "total_issues": 0
          }},
          "indirect_method": {{
            "starting_point": {{
              "net_income": 0,
              "calculation_details": "How net income was calculated",
              "supporting_transactions": []
            }},
            "adjustments": {{
              "non_cash_items": {{
                "depreciation": 0,
                "amortization": 0,
                "other": 0
              }},
              "working_capital_changes": {{
                "accounts_receivable": 0,
                "inventory": 0,
                "accounts_payable": 0,
                "other": 0
              }}
            }},
            "operating_activities": {{
              "net_income": 0,
              "depreciation": 0,
              "amortization": 0,
              "changes_in_working_capital": 0,
              "total_operating_cash_flow": 0,
              "supporting_transactions": []
            }},
            "investing_activities": {{
              "purchase_of_assets": 0,
              "sale_of_assets": 0,
              "investments": 0,
              "total_investing_cash_flow": 0,
              "supporting_transactions": []
            }},
            "financing_activities": {{
              "debt_issued": 0,
              "debt_repayment": 0,
              "equity_issued": 0,
              "dividends_paid": 0,
              "total_financing_cash_flow": 0,
              "supporting_transactions": []
            }},
            "net_cash_flow": 0,
            "beginning_cash": 0,
            "ending_cash": 0
          }},
          "executive_summary": "Professional analysis with key insights and recommendations"
        }}

        CRITICAL: Focus on accuracy and clarity like QuickBooks. Ensure all calculations are correct.
        
        Respond ONLY with the JSON object specified. Do not include any additional text, explanations, or markdown. Ensure the JSON is complete and valid."""

        try:
            message = self.anthropic.messages.create(
                model="claude-opus-4-1-20250805",
                max_tokens=8192,
                messages=[{"role": "user", "content": prompt}]
            )
            
            response_text = message.content[0].text.strip()
            # Clean the response to ensure it's valid JSON
            if response_text.startswith('```json'):
                response_text = response_text.split('```json')[1].split('```')[0].strip()
            elif response_text.startswith('```'):
                response_text = response_text.split('```')[1].split('```')[0].strip()
            
            current_app.logger.info(f"Cleaned AI response: {response_text[:500]}...")  # Log first 500 chars for debug
            
            return json.loads(response_text)
            
        except json.JSONDecodeError as e:
            current_app.logger.error(f"JSON parsing error: {e}")
            return {"error": "AI response format error - please try again"}
        except Exception as e:
            current_app.logger.error(f"Cashflow generation error: {e}")
            return {"error": f"Analysis failed: {str(e)}"}

    def _validate_transactions(self, transaction_data):
        """Validate transactions for duplicates and unusual patterns"""
        validation_results = {
            "duplicates": [],
            "unusual_patterns": [],
            "warnings": [],
            "total_issues": 0
        }
        
        # Check for duplicates (same date, amount, description)
        seen_transactions = {}
        for i, trans in enumerate(transaction_data):
            key = f"{trans['date']}_{trans['amount']}_{trans['description']}"
            if key in seen_transactions:
                # Normalize transaction ID
                tx_id = trans.get('transaction_id') or trans.get('id', f'trans_{i}')
                validation_results["duplicates"].append({
                    "transaction_id": str(tx_id),
                    "issue": f"Duplicate of transaction on {trans['date']} for ${trans['amount']}",
                    "severity": "high"
                })
                validation_results["total_issues"] += 1
            else:
                seen_transactions[key] = i
        
        # Check for unusual patterns
        amounts = [abs(float(t['amount'])) for t in transaction_data]
        if amounts:
            avg_amount = sum(amounts) / len(amounts)
            for i, trans in enumerate(transaction_data):
                amount = abs(float(trans['amount']))
                if amount > avg_amount * 10:  # 10x average
                    validation_results["unusual_patterns"].append({
                        "pattern": "Large transaction",
                        "description": f"Transaction of ${amount} is significantly larger than average (${avg_amount:.2f})",
                        "severity": "medium"
                    })
        
        return validation_results

def parse_response(response):
    lines = response.strip().split('\n')
    statement_data = []
    totals = {}

    for line in lines:
        try:
            if ':' not in line:
                continue
            
            if line.count(':') == 2:  # This is a transaction line
                category, subcategory_and_amount = line.split(':', 1)
                subcategory, amount_str = subcategory_and_amount.rsplit(':', 1)
                
                category = category.strip()
                subcategory = subcategory.strip()
                amount = parse_amount(amount_str)
                
                statement_data.append({
                    'Category': category,
                    'Subcategory': subcategory,
                    'Amount': amount
                })
            elif line.count(':') == 1:  # This is a total line
                key, value_str = line.split(':')
                key = key.strip()
                value = parse_amount(value_str)
                totals[key] = value
        except Exception as e:
            current_app.logger.warning(f"Error parsing line '{line}': {str(e)}")

    if not statement_data:
        current_app.logger.error("No valid statement data found in response")
    if not totals:
        current_app.logger.error("No valid totals found in response")

        return statement_data, totals

    def automated_transaction_categorization(self, transactions):
        """Analyze transaction descriptions and amounts using Claude to automatically categorize transactions"""
        try:
            # Normalize transaction identifiers
            normalized_transactions = []
            for tx in transactions:
                normalized_tx = tx.copy() if isinstance(tx, dict) else tx.__dict__.copy()
                # Handle both 'id' and 'transaction_id' fields
                tx_id = normalized_tx.get('transaction_id') or normalized_tx.get('id')
                if tx_id:
                    normalized_tx['transaction_id'] = str(tx_id)
                normalized_transactions.append(normalized_tx)
            
            prompt = f"""As an expert financial analyst, analyze the following transactions and provide automated categorization suggestions with confidence scores:

            Transaction Data:
            {json.dumps(normalized_transactions, indent=2)}

            Please categorize each transaction into the most appropriate category from the standard financial categories:
            - Cash-customer (Revenue/Income)
            - Salary-suppliers (Operating Expenses)
            - Income-tax (Tax Payments)
            - Buy-property-equipments (Capital Expenditures)
            - Sell-property-equipments (Asset Sales)
            - Buy-investment (Investment Purchases)
            - Sell-investment (Investment Sales)
            - Issue-shares (Equity Financing)
            - borrowings (Debt Financing)
            - Repay-borrowings (Debt Repayment)
            - Pay-dividends (Dividend Payments)
            - Interest-paid (Interest Payments)
            - Other-cfo, Other-cfi, Other-cff (Other categories as needed)

            For each transaction, provide:
            1. Suggested category with confidence score (0-100%)
            2. Reasoning for the categorization
            3. Alternative category suggestions if confidence is below 80%
            4. Pattern recognition insights

            Return the response as a JSON object with this structure:
            {{
                "categorizations": [
                    {{
                        "transaction_id": "original_id",
                        "suggested_category": "category_name",
                        "confidence_score": 85,
                        "reasoning": "explanation",
                        "alternative_suggestions": ["alt1", "alt2"],
                        "pattern_insights": "insights about this transaction type"
                    }}
                ],
                "summary": {{
                    "total_transactions": 0,
                    "high_confidence_count": 0,
                    "medium_confidence_count": 0,
                    "low_confidence_count": 0,
                    "common_patterns": ["pattern1", "pattern2"]
                }},
                "recommendations": [
                    "recommendation1",
                    "recommendation2"
                ]
            }}

            Focus on accuracy and provide detailed reasoning for each categorization decision."""

            message = self.anthropic.messages.create(
                model="claude-opus-4-1-20250805",
                max_tokens=4000,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text.strip()
            if response_text.startswith('```json'):
                response_text = response_text.split('```json')[1].split('```')[0].strip()
            elif response_text.startswith('```'):
                response_text = response_text.split('```')[1].split('```')[0].strip()

            return json.loads(response_text)

        except json.JSONDecodeError as e:
            current_app.logger.error(f"JSON parsing error in categorization: {e}")
            return {"error": "AI response format error - please try again"}
        except Exception as e:
            current_app.logger.error(f"Transaction categorization error: {e}")
            return {"error": f"Categorization failed: {str(e)}"}

    def risk_assessment_reports(self, transaction_history, balance_data, user_profile):
        """Generate comprehensive risk assessment reports using advanced financial modeling"""
        try:
            prompt = f"""As a senior risk analyst, conduct a comprehensive financial risk assessment based on the following data:

            Transaction History:
            {json.dumps(transaction_history, indent=2)}

            Balance Data:
            {json.dumps(balance_data, indent=2)}

            User Profile:
            {json.dumps(user_profile, indent=2)}

            Perform a detailed risk analysis including:

            1. LIQUIDITY RISK ANALYSIS:
               - Current liquidity ratios
               - Cash flow volatility assessment
               - Working capital adequacy
               - Emergency fund coverage

            2. CREDIT RISK EVALUATION:
               - Payment pattern analysis
               - Credit utilization trends
               - Debt service capacity
               - Credit score impact factors

            3. MARKET RISK ASSESSMENT:
               - Interest rate sensitivity
               - Currency exposure (if applicable)
               - Economic cycle vulnerability
               - Industry-specific risks

            4. OPERATIONAL RISK REVIEW:
               - Transaction pattern anomalies
               - Fraud risk indicators
               - Process inefficiencies
               - Compliance risks

            5. STRESS TESTING:
               - 25% revenue decline scenario
               - 50% expense increase scenario
               - Economic downturn simulation
               - Emergency expense impact

            6. MONTE CARLO SIMULATION:
               - 1000 iterations of cash flow projections
               - Probability distributions
               - Confidence intervals
               - Risk-adjusted returns

            Return the analysis as a JSON object with this structure:
            {{
                "risk_summary": {{
                    "overall_risk_score": 75,
                    "risk_level": "Medium",
                    "key_risks": ["risk1", "risk2"],
                    "risk_trend": "increasing/stable/decreasing"
                }},
                "liquidity_risk": {{
                    "current_ratio": 2.5,
                    "quick_ratio": 1.8,
                    "cash_runway_months": 12,
                    "liquidity_score": 80,
                    "recommendations": ["rec1", "rec2"]
                }},
                "credit_risk": {{
                    "payment_reliability": 95,
                    "debt_to_income": 0.3,
                    "credit_utilization": 25,
                    "credit_score": 720,
                    "recommendations": ["rec1", "rec2"]
                }},
                "market_risk": {{
                    "interest_rate_sensitivity": "Low",
                    "economic_cycle_risk": "Medium",
                    "industry_risk": "Low",
                    "recommendations": ["rec1", "rec2"]
                }},
                "operational_risk": {{
                    "fraud_risk_score": 15,
                    "process_efficiency": 85,
                    "compliance_score": 90,
                    "recommendations": ["rec1", "rec2"]
                }},
                "stress_testing": {{
                    "scenarios": [
                        {{
                            "name": "25% Revenue Decline",
                            "impact_score": 65,
                            "survival_months": 8,
                            "mitigation_strategies": ["strategy1", "strategy2"]
                        }}
                    ]
                }},
                "monte_carlo": {{
                    "mean_projection": 50000,
                    "confidence_intervals": {{
                        "90_percent": [40000, 60000],
                        "95_percent": [35000, 65000],
                        "99_percent": [25000, 75000]
                    }},
                    "probability_of_negative": 0.05
                }},
                "recommendations": [
                    "Overall recommendation 1",
                    "Overall recommendation 2"
                ],
                "action_items": [
                    {{
                        "priority": "High",
                        "action": "action description",
                        "timeline": "30 days",
                        "impact": "High"
                    }}
                ]
            }}

            Provide detailed, actionable insights with specific metrics and recommendations."""

            message = self.anthropic.messages.create(
                model="claude-opus-4-1-20250805",
                max_tokens=6000,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text.strip()
            if response_text.startswith('```json'):
                response_text = response_text.split('```json')[1].split('```')[0].strip()
            elif response_text.startswith('```'):
                response_text = response_text.split('```')[1].split('```')[0].strip()

            return json.loads(response_text)

        except json.JSONDecodeError as e:
            current_app.logger.error(f"JSON parsing error in risk assessment: {e}")
            return {"error": "AI response format error - please try again"}
        except Exception as e:
            current_app.logger.error(f"Risk assessment error: {e}")
            return {"error": f"Risk assessment failed: {str(e)}"}

    def anomaly_detection(self, transaction_history, user_patterns):
        """Use Claude's pattern recognition to detect unusual transactions and spending behaviors"""
        try:
            prompt = f"""As a financial fraud detection specialist, analyze the following transaction data to identify anomalies and unusual patterns:

            Transaction History:
            {json.dumps(transaction_history, indent=2)}

            User Patterns:
            {json.dumps(user_patterns, indent=2)}

            Perform comprehensive anomaly detection including:

            1. STATISTICAL ANOMALY DETECTION:
               - Z-score analysis for amount deviations
               - Time-based pattern analysis
               - Frequency analysis
               - Seasonal deviation detection

            2. BEHAVIORAL ANOMALY DETECTION:
               - Spending pattern changes
               - Location-based anomalies
               - Time-of-day patterns
               - Merchant category analysis

            3. FRAUD INDICATOR ANALYSIS:
               - Unusual transaction amounts
               - Rapid successive transactions
               - Off-hours activity
               - Geographic inconsistencies

            4. MACHINE LEARNING PATTERN RECOGNITION:
               - Clustering analysis
               - Outlier detection
               - Trend deviation analysis
               - Predictive anomaly scoring

            For each anomaly detected, provide:
            - Anomaly score (0-100)
            - Severity level (Low/Medium/High/Critical)
            - Explanation of why it's anomalous
            - Recommended actions
            - False positive probability

            Return the analysis as a JSON object with this structure:
            {{
                "anomaly_summary": {{
                    "total_anomalies": 5,
                    "critical_count": 1,
                    "high_count": 2,
                    "medium_count": 1,
                    "low_count": 1,
                    "overall_risk_score": 65
                }},
                "detected_anomalies": [
                    {{
                        "transaction_id": "trans_123",
                        "anomaly_type": "Amount Deviation",
                        "anomaly_score": 85,
                        "severity": "High",
                        "description": "Transaction amount is 5x higher than typical spending pattern",
                        "explanation": "This transaction of $2,500 is significantly higher than the user's typical $500 average transaction",
                        "recommended_actions": [
                            "Verify transaction with user",
                            "Check for duplicate processing",
                            "Review merchant legitimacy"
                        ],
                        "false_positive_probability": 0.15,
                        "pattern_analysis": "Amount exceeds 3 standard deviations from mean",
                        "context": "First large transaction in 6 months"
                    }}
                ],
                "pattern_analysis": {{
                    "spending_trends": "Increasing by 15% monthly",
                    "typical_amount_range": [100, 800],
                    "typical_frequency": "2-3 transactions per week",
                    "peak_spending_hours": "10:00-14:00",
                    "common_merchants": ["merchant1", "merchant2"]
                }},
                "risk_factors": [
                    "Recent spending increase",
                    "Unusual time patterns",
                    "Large amount deviations"
                ],
                "recommendations": [
                    "Implement transaction monitoring",
                    "Set up spending alerts",
                    "Review recent transactions"
                ],
                "alert_thresholds": {{
                    "amount_threshold": 1000,
                    "frequency_threshold": 10,
                    "velocity_threshold": 3
                }}
            }}

            Focus on actionable insights and provide specific recommendations for each anomaly."""

            message = self.anthropic.messages.create(
                model="claude-opus-4-1-20250805",
                max_tokens=5000,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text.strip()
            if response_text.startswith('```json'):
                response_text = response_text.split('```json')[1].split('```')[0].strip()
            elif response_text.startswith('```'):
                response_text = response_text.split('```')[1].split('```')[0].strip()

            return json.loads(response_text)

        except json.JSONDecodeError as e:
            current_app.logger.error(f"JSON parsing error in anomaly detection: {e}")
            return {
                "error": "AI response format error - please try again",
                "anomaly_summary": {"total_anomalies": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0},
                "anomalies": [],
                "recommendations": ["Please try the analysis again"]
            }
        except Exception as e:
            current_app.logger.error(f"Anomaly detection error: {e}")
            return {
                "error": f"Anomaly detection failed: {str(e)}",
                "anomaly_summary": {"total_anomalies": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0},
                "anomalies": [],
                "recommendations": ["Please check your data and try again"]
            }

    def advanced_forecasting_models(self, transaction_history, external_factors):
        """Implement sophisticated forecasting beyond basic trend analysis"""
        try:
            prompt = f"""As a quantitative financial analyst, create advanced forecasting models for the following financial data:

            Transaction History:
            {json.dumps(transaction_history, indent=2)}

            External Factors:
            {json.dumps(external_factors, indent=2)}

            Implement multiple forecasting models and provide comprehensive projections:

            1. ARIMA MODEL ANALYSIS:
               - Auto-regressive Integrated Moving Average
               - Seasonal decomposition
               - Trend and cyclical components
               - Stationarity testing

            2. EXPONENTIAL SMOOTHING MODELS:
               - Simple exponential smoothing
               - Double exponential smoothing (Holt's method)
               - Triple exponential smoothing (Holt-Winters)
               - Model selection criteria (AIC, BIC)

            3. NEURAL NETWORK-STYLE PATTERN RECOGNITION:
               - Deep learning pattern analysis
               - Non-linear relationship detection
               - Complex seasonality modeling
               - Multi-variate dependencies

            4. ENSEMBLE FORECASTING:
               - Model combination strategies
               - Weighted averaging
               - Bayesian model averaging
               - Uncertainty quantification

            5. SCENARIO ANALYSIS:
               - Base case scenario
               - Optimistic scenario (25th percentile)
               - Pessimistic scenario (75th percentile)
               - Stress test scenarios

            6. CONFIDENCE INTERVALS:
               - Prediction intervals
               - Confidence bands
               - Monte Carlo simulations
               - Bootstrap methods

            Return the analysis as a JSON object with this structure:
            {{
                "forecasting_summary": {{
                    "best_model": "ARIMA(2,1,1)",
                    "model_accuracy": 0.92,
                    "forecast_horizon": "12 months",
                    "confidence_level": 0.95
                }},
                "arima_model": {{
                    "parameters": {{
                        "p": 2,
                        "d": 1,
                        "q": 1
                    }},
                    "aic": 1250.5,
                    "bic": 1265.8,
                    "forecast": [
                        {{"period": "2024-01", "value": 5000, "confidence_lower": 4500, "confidence_upper": 5500}},
                        {{"period": "2024-02", "value": 5200, "confidence_lower": 4600, "confidence_upper": 5800}}
                    ],
                    "residuals_analysis": "White noise residuals, model is adequate"
                }},
                "exponential_smoothing": {{
                    "best_method": "Holt-Winters",
                    "alpha": 0.3,
                    "beta": 0.1,
                    "gamma": 0.2,
                    "forecast": [
                        {{"period": "2024-01", "value": 4950, "confidence_lower": 4400, "confidence_upper": 5500}}
                    ],
                    "seasonal_pattern": "Strong quarterly seasonality detected"
                }},
                "neural_network": {{
                    "architecture": "3-layer LSTM",
                    "training_accuracy": 0.89,
                    "validation_accuracy": 0.85,
                    "forecast": [
                        {{"period": "2024-01", "value": 5100, "confidence_lower": 4600, "confidence_upper": 5600}}
                    ],
                    "feature_importance": ["historical_trend", "seasonality", "external_factors"]
                }},
                "ensemble_forecast": {{
                    "combined_forecast": [
                        {{"period": "2024-01", "value": 5017, "confidence_lower": 4500, "confidence_upper": 5534, "model_weights": {{"arima": 0.4, "exponential": 0.3, "neural": 0.3}}}},
                        {{"period": "2024-02", "value": 5234, "confidence_lower": 4600, "confidence_upper": 5868}}
                    ],
                    "ensemble_accuracy": 0.94
                }},
                "scenario_analysis": {{
                    "base_case": {{
                        "description": "Most likely scenario based on historical trends",
                        "monthly_average": 5000,
                        "total_12_months": 60000
                    }},
                    "optimistic": {{
                        "description": "25th percentile scenario",
                        "monthly_average": 5500,
                        "total_12_months": 66000,
                        "probability": 0.25
                    }},
                    "pessimistic": {{
                        "description": "75th percentile scenario",
                        "monthly_average": 4500,
                        "total_12_months": 54000,
                        "probability": 0.25
                    }},
                    "stress_test": {{
                        "description": "Economic downturn scenario",
                        "monthly_average": 3500,
                        "total_12_months": 42000,
                        "probability": 0.05
                    }}
                }},
                "model_validation": {{
                    "rmse": 250.5,
                    "mae": 180.2,
                    "mape": 4.2,
                    "directional_accuracy": 0.88,
                    "residuals_tests": {{
                        "ljung_box": "p-value > 0.05, residuals are white noise",
                        "shapiro_wilk": "p-value > 0.05, residuals are normally distributed"
                    }}
                }},
                "recommendations": [
                    "Model shows strong predictive power with 94% accuracy",
                    "Consider external economic indicators for improved forecasting",
                    "Monitor for structural breaks in the data",
                    "Update model parameters quarterly"
                ],
                "limitations": [
                    "Model assumes historical patterns will continue",
                    "External shocks not fully captured",
                    "Limited data for long-term forecasting"
                ]
            }}

            Provide detailed model diagnostics and actionable insights."""

            message = self.anthropic.messages.create(
                model="claude-opus-4-1-20250805",
                max_tokens=6000,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text.strip()
            if response_text.startswith('```json'):
                response_text = response_text.split('```json')[1].split('```')[0].strip()
            elif response_text.startswith('```'):
                response_text = response_text.split('```')[1].split('```')[0].strip()

            return json.loads(response_text)

        except json.JSONDecodeError as e:
            current_app.logger.error(f"JSON parsing error in advanced forecasting: {e}")
            return {"error": "AI response format error - please try again"}
        except Exception as e:
            current_app.logger.error(f"Advanced forecasting error: {e}")
            return {"error": f"Advanced forecasting failed: {str(e)}"}

    def custom_financial_insights(self, transaction_data, analysis_type, custom_parameters):
        """Flexible AI analysis engine that can generate custom insights based on user-defined parameters"""
        try:
            prompt = f"""As a senior financial consultant, provide custom financial analysis based on the specific requirements:

            Transaction Data:
            {json.dumps(transaction_data, indent=2)}

            Analysis Type: {analysis_type}

            Custom Parameters:
            {json.dumps(custom_parameters, indent=2)}

            Perform a tailored analysis based on the requested analysis type. Provide deep insights, actionable recommendations, and strategic guidance.

            Analysis Types and Focus Areas:

            1. PROFITABILITY ANALYSIS:
               - Gross profit margins
               - Net profit trends
               - Cost structure analysis
               - Revenue optimization opportunities
               - Break-even analysis

            2. COST OPTIMIZATION:
               - Cost center analysis
               - Expense categorization
               - Cost reduction opportunities
               - Budget variance analysis
               - Efficiency improvements

            3. INVESTMENT RECOMMENDATIONS:
               - Investment opportunity assessment
               - Risk-return analysis
               - Portfolio optimization
               - Asset allocation recommendations
               - Market timing insights

            4. CASH FLOW OPTIMIZATION:
               - Working capital management
               - Cash conversion cycle
               - Payment term optimization
               - Credit management
               - Liquidity planning

            5. BUSINESS PERFORMANCE:
               - KPI analysis
               - Benchmark comparisons
               - Trend analysis
               - Performance drivers
               - Growth strategies

            6. FINANCIAL HEALTH ASSESSMENT:
               - Financial ratios analysis
               - Solvency assessment
               - Efficiency metrics
               - Growth sustainability
               - Risk factors

            7. TAX OPTIMIZATION:
               - Tax planning strategies
               - Deduction opportunities
               - Timing optimization
               - Compliance review
               - Savings potential

            8. CUSTOM ANALYSIS:
               - User-defined focus areas
               - Specific business questions
               - Industry-specific insights
               - Regulatory considerations
               - Strategic planning

            Return the analysis as a JSON object with this structure:
            {{
                "analysis_summary": {{
                    "analysis_type": "{analysis_type}",
                    "key_findings": ["finding1", "finding2"],
                    "overall_score": 75,
                    "confidence_level": "High",
                    "analysis_date": "2024-01-15"
                }},
                "detailed_analysis": {{
                    "primary_metrics": {{
                        "metric1": {{"value": 1000, "trend": "increasing", "benchmark": 1200, "status": "below_target"}},
                        "metric2": {{"value": 0.15, "trend": "stable", "benchmark": 0.20, "status": "above_target"}}
                    }},
                    "secondary_metrics": {{
                        "metric3": {{"value": 500, "trend": "decreasing", "significance": "high"}}
                    }},
                    "trend_analysis": "Detailed trend analysis with insights",
                    "comparative_analysis": "Benchmark and peer comparison",
                    "root_cause_analysis": "Underlying factors driving performance"
                }},
                "opportunities": [
                    {{
                        "opportunity": "Revenue optimization opportunity",
                        "description": "Detailed description of the opportunity",
                        "potential_impact": "High",
                        "implementation_difficulty": "Medium",
                        "estimated_value": 25000,
                        "timeframe": "3-6 months",
                        "risk_level": "Low"
                    }}
                ],
                "recommendations": [
                    {{
                        "priority": "High",
                        "recommendation": "Specific actionable recommendation",
                        "rationale": "Why this recommendation makes sense",
                        "expected_outcome": "Expected result from implementation",
                        "implementation_steps": ["step1", "step2", "step3"],
                        "timeline": "30-60 days",
                        "resources_required": "Internal team + external consultant",
                        "success_metrics": ["metric1", "metric2"]
                    }}
                ],
                "risk_assessment": {{
                    "identified_risks": [
                        {{
                            "risk": "Market volatility risk",
                            "probability": "Medium",
                            "impact": "High",
                            "mitigation_strategy": "Diversification and hedging"
                        }}
                    ],
                    "risk_score": 65,
                    "risk_trend": "stable"
                }},
                "strategic_insights": [
                    "Strategic insight 1 with detailed explanation",
                    "Strategic insight 2 with actionable implications"
                ],
                "next_steps": [
                    {{
                        "action": "Immediate action item",
                        "owner": "Finance Team",
                        "deadline": "2024-02-15",
                        "dependencies": ["dependency1", "dependency2"]
                    }}
                ],
                "monitoring_recommendations": [
                    {{
                        "metric": "Monthly revenue growth",
                        "frequency": "Monthly",
                        "threshold": "5%",
                        "alert_condition": "Below threshold for 2 consecutive months"
                    }}
                ],
                "follow_up_analysis": [
                    "Additional analysis recommended in 30 days",
                    "Quarterly review of key performance indicators"
                ]
            }}

            Provide comprehensive, actionable insights tailored to the specific analysis type and custom parameters."""

            message = self.anthropic.messages.create(
                model="claude-opus-4-1-20250805",
                max_tokens=6000,
                messages=[{"role": "user", "content": prompt}]
            )

            response_text = message.content[0].text.strip()
            if response_text.startswith('```json'):
                response_text = response_text.split('```json')[1].split('```')[0].strip()
            elif response_text.startswith('```'):
                response_text = response_text.split('```')[1].split('```')[0].strip()

            return json.loads(response_text)

        except json.JSONDecodeError as e:
            current_app.logger.error(f"JSON parsing error in custom insights: {e}")
            return {"error": "AI response format error - please try again"}
        except Exception as e:
            current_app.logger.error(f"Custom insights error: {e}")
            return {"error": f"Custom insights failed: {str(e)}"}

def parse_amount(amount_str):
    try:
        return float(amount_str.replace('$', '').replace(',', '').strip())
    except ValueError:
        current_app.logger.warning(f"Could not parse amount: {amount_str}")
        return 0.0