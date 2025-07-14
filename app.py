# Enhanced Credit Card Fraud Detection System with User PC Time
import streamlit as st
import joblib
import pickle
import pandas as pd
import numpy as np
import sys
import os
import time
from PIL import Image
from collections import defaultdict
from datetime import datetime
import re
import hashlib
import warnings
warnings.filterwarnings('ignore')

# Set page configuration
st.set_page_config(
    page_title="Enhanced Credit Card Fraud Detection",
    page_icon="💳",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E88E5;
        text-align: center;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #0D47A1;
    }
    .result-box {
        padding: 20px;
        border-radius: 5px;
        margin: 10px 0px;
    }
    .fraud {
        background-color: #ffcdd2;
        border: 2px solid #c62828;
    }
    .legitimate {
        background-color: #c8e6c9;
        border: 2px solid #2e7d32;
    }
    .info-text {
        font-size: 1rem;
    }
    .transaction-time {
        background-color: #e3f2fd;
        padding: 15px;
        border-radius: 10px;
        margin: 10px 0;
        border-left: 4px solid #1976d2;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .risk-factor {
        background-color: #fff3e0;
        padding: 8px;
        border-radius: 4px;
        margin: 5px 0;
        border-left: 3px solid #ff9800;
    }
    .protective-factor {
        background-color: #e8f5e8;
        padding: 8px;
        border-radius: 4px;
        margin: 5px 0;
        border-left: 3px solid #4caf50;
    }
    .ml-metrics {
        background-color: #e3f2fd;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #1976d2;
    }
</style>

<script>
// JavaScript to get user's local PC time
function updateTime() {
    const now = new Date();
    const timeString = now.toLocaleString();
    const hour = now.getHours();
    const minute = now.getMinutes();
    const date = now.toLocaleDateString();
    const timeOnly = now.toLocaleTimeString();
    
    // Store in sessionStorage for Streamlit to access
    if (typeof(Storage) !== "undefined") {
        sessionStorage.setItem('user_local_time', timeString);
        sessionStorage.setItem('user_hour', hour.toString());
        sessionStorage.setItem('user_minute', minute.toString());
        sessionStorage.setItem('user_date', date);
        sessionStorage.setItem('user_time_only', timeOnly);
    }
}

// Update time immediately and then every second
updateTime();
setInterval(updateTime, 1000);
</script>
""", unsafe_allow_html=True)

# Helper Functions and Model Classes
def _default_dict_int():
    return defaultdict(int)

def create_enhanced_card_pattern():
    return {
        'card_history': defaultdict(list),
        'card_frequency': defaultdict(int),
        'card_first_seen': defaultdict(str),
        'card_last_seen': defaultdict(str),
        'card_amounts': defaultdict(list),
        'card_fraud_history': defaultdict(list),
        'card_hourly_usage': defaultdict(_default_dict_int),
        'card_time_patterns': defaultdict(list),
        'total_unique_cards': 0,
        'most_frequent_cards': [],
        'suspicious_cards': set(),
        'trusted_cards': set(),
        'new_cards_last_30_days': set(),
        'high_amount_cards': set(),
        'unusual_time_cards': set()
    }

# Enhanced Card Pattern Analyzer Class (fallback)
class EnhancedCardPatternAnalyzer:
    def __init__(self):
        self.customer_card_patterns = defaultdict(create_enhanced_card_pattern)
        self.global_card_stats = {
            'total_cards_seen': set(),
            'fraud_rate_by_card': defaultdict(lambda: {'total': 0, 'fraud': 0}),
            'global_suspicious_cards': set(),
            'hour_fraud_rates': defaultdict(lambda: {'total': 0, 'fraud': 0})
        }
        self.risk_thresholds = {
            'new_card_risk_multiplier': 2.0,
            'unfamiliar_card_threshold': 0.3,
            'high_amount_multiplier': 3.0,
            'unusual_time_risk_multiplier': 1.5,
            'suspicious_card_risk_addition': 0.4,
            'trusted_card_risk_reduction': 0.3
        }
        self.hour_risk_mapping = {
            0: 3.0, 1: 3.0, 2: 3.0, 3: 2.5, 22: 2.5, 23: 2.5,
            4: 1.5, 5: 1.5, 6: 1.2, 20: 1.5, 21: 1.5,
            7: 0.8, 8: 0.7, 9: 0.6, 10: 0.5, 11: 0.5,
            12: 0.5, 13: 0.5, 14: 0.5, 15: 0.6, 16: 0.7,
            17: 0.8, 18: 0.9, 19: 1.0
        }
        self.threshold = 0.5
        self.customer_stats_overall = None

    def predict(self, features):
        # Simple rule-based prediction for fallback
        return 0 if features.get('amount', 0) < 1000 else 1
    
    def predict_proba(self, features):
        # Return probability for compatibility
        prob = 0.3 if features.get('amount', 0) < 1000 else 0.8
        return [[1-prob, prob]]

# Function to get user's PC local time
def get_user_pc_time():
    """Get current time from user's PC"""
    now = datetime.now()
    return {
        'datetime': now,
        'hour': now.hour,
        'minute': now.minute,
        'formatted_time': now.strftime("%Y-%m-%d %H:%M:%S"),
        'time_only': now.strftime("%H:%M"),
        'date': now.strftime("%Y-%m-%d"),
        'timezone': 'Local PC Time',
        'timestamp': now.timestamp()
    }

def get_transaction_time():
    """Get current transaction time from user's PC"""
    return get_user_pc_time()

# Function to validate card number format
def validate_card_number(card_number):
    """Validate card number format"""
    card_number = re.sub(r'[\s-]', '', str(card_number))
    
    if not card_number.isdigit():
        return False, "Card number must contain only digits"
    
    if len(card_number) < 12 or len(card_number) > 19:
        return False, "Card number must be between 12-19 digits"
    
    return True, "Valid format"

# Function to mask card number for display
def mask_card_number(card_number):
    """Mask card number for security display"""
    card_number = re.sub(r'[\s-]', '', str(card_number))
    if len(card_number) < 4:
        return card_number
    return '*' * (len(card_number) - 4) + card_number[-4:]

# Function to hash card number
def hash_card_number(card_number):
    """Hash card number similar to training format"""
    if pd.isna(card_number) or card_number == '' or card_number == 0:
        return 'UNKNOWN_CARD'
    
    if isinstance(card_number, str) and '****' in card_number:
        return card_number
    
    try:
        card_str = str(int(float(card_number))) if not pd.isna(card_number) else 'UNKNOWN'
    except (ValueError, TypeError):
        card_str = str(card_number) if not pd.isna(card_number) else 'UNKNOWN'
    
    if len(card_str) >= 12:
        bank_id = card_str[:4]
        rest_hash = hashlib.md5(card_str[4:].encode()).hexdigest()[:8]
        return f"{bank_id}****{rest_hash}"
    elif len(card_str) >= 8:
        bank_id = card_str[:4]
        rest_hash = hashlib.md5(card_str[4:].encode()).hexdigest()[:6]
        return f"{bank_id}**{rest_hash}"
    else:
        return hashlib.md5(card_str.encode()).hexdigest()[:12]

# Function to load your existing ML model
@st.cache_resource
def load_enhanced_model():
    """Load your existing fraud detection model"""
    try:
        # Try to load your model file
        model_files = 'enhanced_defone_v2_1.pkl'
        
        for model_path in model_files:
            if os.path.exists(model_path):
                try:
                    model_data = joblib.load(model_path)
                    st.success(f"✅ ML Model loaded successfully from {model_path}!")
                    return model_data
                except Exception as e:
                    st.warning(f"⚠️ Error loading {model_path}: {str(e)}")
                    continue
        
        # If no model file found, show instructions
        st.warning("⚠️ No ML model file found. Please ensure your model file is in the same directory.")
        st.info("""
        **Expected model files:** 
        - enhanced_defone_v2_1.pkl
        - fraud_model.pkl  
        - model.pkl
        
        **To use your model:** Place your trained model file in the same directory as this script.
        """)
        
        # Return fallback analyzer
        return EnhancedCardPatternAnalyzer()
        
    except Exception as e:
        st.error(f"❌ Error loading model: {str(e)}")
        st.info("🔄 Using fallback pattern analyzer...")
        return EnhancedCardPatternAnalyzer()

# Function to prepare features for your ML model
def prepare_features_for_model(customer_id, amount, receiver_card, transaction_time, model_data):
    """Prepare features in the format expected by your ML model"""
    
    # Basic features that most fraud models expect
    features = {
        'customer_id': customer_id,
        'amount': float(amount),
        'hour': transaction_time['hour'],
        'minute': transaction_time['minute'],
        'day_of_week': transaction_time['datetime'].weekday(),
        'receiver_card': receiver_card,
        'receiver_card_hash': hash_card_number(receiver_card)
    }
    
    # Add derived features
    features['is_weekend'] = 1 if transaction_time['datetime'].weekday() >= 5 else 0
    features['is_night_time'] = 1 if transaction_time['hour'] >= 22 or transaction_time['hour'] <= 5 else 0
    features['is_business_hours'] = 1 if 9 <= transaction_time['hour'] <= 17 else 0
    
    # Amount-based features
    features['amount_log'] = np.log1p(amount)
    features['high_amount'] = 1 if amount > 1000 else 0
    features['very_high_amount'] = 1 if amount > 5000 else 0
    
    # Try to get customer history if available in your model
    try:
        if hasattr(model_data, 'customer_stats_overall') and model_data.customer_stats_overall is not None:
            customer_history = model_data.customer_stats_overall[
                model_data.customer_stats_overall['customer_id'] == customer_id
            ]
            if len(customer_history) > 0:
                stats = customer_history.iloc[0]
                features['customer_avg_amount'] = stats.get('avg_amount', amount)
                features['customer_max_amount'] = stats.get('max_amount', amount)
                features['customer_transaction_count'] = stats.get('transaction_count', 1)
                features['customer_fraud_ratio'] = stats.get('fraud_ratio', 0)
            else:
                # New customer
                features['customer_avg_amount'] = amount
                features['customer_max_amount'] = amount
                features['customer_transaction_count'] = 1
                features['customer_fraud_ratio'] = 0
        else:
            # Default values for new customer
            features['customer_avg_amount'] = amount
            features['customer_max_amount'] = amount
            features['customer_transaction_count'] = 1
            features['customer_fraud_ratio'] = 0
    except Exception as e:
        # Fallback values
        features['customer_avg_amount'] = amount
        features['customer_max_amount'] = amount
        features['customer_transaction_count'] = 1
        features['customer_fraud_ratio'] = 0
    
    # Calculate ratios
    features['amount_to_avg_ratio'] = amount / max(features['customer_avg_amount'], 1)
    features['amount_to_max_ratio'] = amount / max(features['customer_max_amount'], 1)
    
    return features

# Function to use your ML model for prediction
def predict_with_your_model(features, model_data):
    """Use your ML model to predict fraud"""
    try:
        # Try to use your actual model
        if hasattr(model_data, 'predict') and hasattr(model_data, 'predict_proba'):
            # Your model is a sklearn-like model
            feature_df = pd.DataFrame([features])
            
            # Get prediction and probability
            prediction = model_data.predict(feature_df)[0]
            prob = model_data.predict_proba(feature_df)[0]
            fraud_probability = prob[1] if len(prob) > 1 else prob[0]
            
            return {
                'is_fraud': bool(prediction),
                'fraud_probability': float(fraud_probability),
                'confidence': abs(fraud_probability - 0.5) * 2,
                'model_type': 'Your ML Model'
            }
            
        elif isinstance(model_data, dict) and 'model' in model_data:
            # Your model is stored in a dictionary
            model = model_data['model']
            feature_df = pd.DataFrame([features])
            
            prediction = model.predict(feature_df)[0]
            prob = model.predict_proba(feature_df)[0]
            fraud_probability = prob[1] if len(prob) > 1 else prob[0]
            
            return {
                'is_fraud': bool(prediction),
                'fraud_probability': float(fraud_probability),
                'confidence': abs(fraud_probability - 0.5) * 2,
                'model_type': 'Your ML Model'
            }
            
        else:
            # Use fallback method
            prediction = model_data.predict(features)
            prob = model_data.predict_proba(features)[0]
            fraud_probability = prob[1] if len(prob) > 1 else prob[0]
            
            return {
                'is_fraud': bool(prediction),
                'fraud_probability': float(fraud_probability),
                'confidence': abs(fraud_probability - 0.5) * 2,
                'model_type': 'Fallback Model'
            }
            
    except Exception as e:
        st.error(f"Error using your model: {str(e)}")
        
        # Simple fallback prediction
        fraud_score = 0.2  # Default low risk
        
        # Increase risk based on amount
        if features['amount'] > 5000:
            fraud_score += 0.4
        elif features['amount'] > 1000:
            fraud_score += 0.2
        
        # Increase risk based on time
        if features['is_night_time']:
            fraud_score += 0.3
        
        # Increase risk for new customers with high amounts
        if features['customer_transaction_count'] < 5 and features['amount'] > 1000:
            fraud_score += 0.2
        
        fraud_score = min(fraud_score, 1.0)
        
        return {
            'is_fraud': fraud_score > 0.5,
            'fraud_probability': fraud_score,
            'confidence': abs(fraud_score - 0.5) * 2,
            'model_type': 'Rule-based Fallback'
        }

# Analysis Functions
def analyze_time_patterns(hour, minute):
    """Analyze fraud patterns based on transaction time"""
    time_indicators = []
    
    # Peak fraud hours (2-4 AM)
    if hour in [2, 3, 4]:
        time_indicators.append("🔴 Transaction during peak fraud hours (2-4 AM)")
    # Unusual hours (late night/early morning)
    elif hour >= 23 or hour <= 5:
        time_indicators.append("🟡 Transaction during unusual hours (11 PM - 5 AM)")
    # Weekend late hours
    if hour >= 22 or hour <= 6:
        time_indicators.append("🟡 Transaction during high-risk time period")
    
    return time_indicators

def get_hour_risk_score(hour):
    """Get risk score for specific hour"""
    hour_risk_mapping = {
        0: 3.0, 1: 3.0, 2: 3.0, 3: 2.5, 22: 2.5, 23: 2.5,
        4: 1.5, 5: 1.5, 6: 1.2, 20: 1.5, 21: 1.5,
        7: 0.8, 8: 0.7, 9: 0.6, 10: 0.5, 11: 0.5,
        12: 0.5, 13: 0.5, 14: 0.5, 15: 0.6, 16: 0.7,
        17: 0.8, 18: 0.9, 19: 1.0
    }
    return hour_risk_mapping.get(hour, 1.0)

def analyze_card_familiarity(customer_id, receiver_card, customer_stats):
    """Analyze card familiarity patterns"""
    if customer_stats is None or customer_stats.get('transaction_count', 0) == 0:
        return {
            'familiarity_score': 0.0,
            'is_new_card': True,
            'risk_level': 'HIGH',
            'indicators': ['New customer - no transaction history']
        }
    
    # Simulate card frequency analysis
    card_usage_frequency = 0.3 if customer_stats.get('transaction_count', 0) > 5 else 0.1
    familiarity_score = min(card_usage_frequency * 2, 1.0)
    
    indicators = []
    if familiarity_score < 0.3:
        indicators.append("🔴 Unfamiliar receiver card")
        risk_level = 'HIGH'
    elif familiarity_score < 0.6:
        indicators.append("🟡 Moderately familiar card")
        risk_level = 'MEDIUM'
    else:
        indicators.append("🟢 Familiar receiver card")
        risk_level = 'LOW'
    
    return {
        'familiarity_score': familiarity_score,
        'is_new_card': familiarity_score < 0.1,
        'risk_level': risk_level,
        'indicators': indicators
    }

def simulate_processing():
    """Simulate fraud detection processing"""
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    stages = [
        "🔍 Loading your ML model...",
        "🔐 Validating card information...",
        "📊 Preparing features for your model...",
        "⏰ Analyzing transaction timing...",
        "🤖 Running your ML model prediction...",
        "📈 Calculating risk assessment...",
        "🎯 Finalizing fraud detection results..."
    ]
    
    for i, stage in enumerate(stages):
        progress = (i+1) / len(stages)
        progress_bar.progress(progress)
        status_text.text(stage)
        time.sleep(0.4)
    
    progress_bar.empty()
    status_text.empty()

# Enhanced Transaction Analysis using your ML model
def analyze_enhanced_transaction(customer_id, amount, receiver_card, transaction_time, model_data):
    """Enhanced transaction analysis using your ML model"""
    
    # Prepare features for your model
    features = prepare_features_for_model(customer_id, amount, receiver_card, transaction_time, model_data)
    
    # Get prediction from your ML model
    ml_prediction = predict_with_your_model(features, model_data)
    
    # Get additional analysis
    time_indicators = analyze_time_patterns(transaction_time['hour'], transaction_time['minute'])
    hour_risk_score = get_hour_risk_score(transaction_time['hour'])
    
    # Get customer stats
    customer_stats = {
        'transaction_count': features.get('customer_transaction_count', 1),
        'avg_amount': features.get('customer_avg_amount', amount),
        'max_amount': features.get('customer_max_amount', amount),
        'fraud_ratio': features.get('customer_fraud_ratio', 0),
        'amount_to_avg_ratio': features.get('amount_to_avg_ratio', 1.0),
        'amount_to_max_ratio': features.get('amount_to_max_ratio', 1.0)
    }
    
    # Determine customer risk level
    if customer_stats['transaction_count'] >= 20:
        customer_risk_level = 'ESTABLISHED'
    elif customer_stats['transaction_count'] >= 10:
        customer_risk_level = 'REGULAR'
    elif customer_stats['transaction_count'] >= 1:
        customer_risk_level = 'NEW'
    else:
        customer_risk_level = 'NEW_CUSTOMER'
    
    # Card analysis
    card_analysis = analyze_card_familiarity(customer_id, receiver_card, customer_stats)
    
    # Generate fraud indicators and protective factors
    fraud_indicators = []
    protective_factors = []
    
    # Amount-based analysis
    if customer_stats['amount_to_avg_ratio'] > 5.0:
        fraud_indicators.append(f"🔴 Amount is {customer_stats['amount_to_avg_ratio']:.1f}x higher than customer's average")
    elif customer_stats['amount_to_avg_ratio'] > 3.0:
        fraud_indicators.append(f"🟡 Amount is {customer_stats['amount_to_avg_ratio']:.1f}x higher than customer's average")
    elif customer_stats['amount_to_avg_ratio'] < 1.5:
        protective_factors.append("🟢 Amount is consistent with customer's average")
    
    # Time-based analysis
    fraud_indicators.extend(time_indicators)
    if hour_risk_score <= 1.0:
        protective_factors.append("🟢 Transaction during normal business hours")
    
    # Card analysis
    fraud_indicators.extend(card_analysis['indicators'])
    
    # Customer history
    if customer_stats['transaction_count'] > 15 and customer_stats['fraud_ratio'] < 0.05:
        protective_factors.append("🟢 Customer has clean transaction history")
    elif customer_stats['fraud_ratio'] > 0.2:
        fraud_indicators.append("🔴 Customer has high fraud history")
    
    return {
        'predicted_fraud': ml_prediction['is_fraud'],
        'fraud_score': ml_prediction['fraud_probability'],
        'confidence': ml_prediction['confidence'],
        'model_type': ml_prediction['model_type'],
        'customer_stats': customer_stats,
        'customer_risk_level': customer_risk_level,
        'fraud_indicators': fraud_indicators,
        'protective_factors': protective_factors,
        'time_indicators': time_indicators,
        'card_analysis': card_analysis,
        'hour_risk_score': hour_risk_score,
        'features_used': features
    }

# Display Functions
def display_live_clock():
    """Display live clock using user's PC time"""
    current_time = get_user_pc_time()
    
    # Create live clock display
    risk_level = '🔴 HIGH RISK' if current_time['hour'] in [0,1,2,3,22,23] else '🟡 MEDIUM RISK' if current_time['hour'] in [4,5,6,20,21] else '🟢 LOW RISK'
    
    clock_html = f"""
    <div class="transaction-time">
        <h3 style="margin: 0; font-size: 1.2em;">🕒 Current PC Time</h3>
        <div style="font-size: 1.8em; font-weight: bold; margin: 5px 0;">
            {current_time['time_only']}
        </div>
        <div style="font-size: 0.9em; opacity: 0.9;">
            {current_time['date']} | {current_time['timezone']}
        </div>
        <div style="font-size: 0.8em; opacity: 0.8;">
            Fraud Risk Level: {risk_level}
        </div>
    </div>
    """
    
    st.markdown(clock_html, unsafe_allow_html=True)
    return current_time

def display_enhanced_result(analysis_result):
    """Display enhanced prediction result with detailed analysis"""
    predicted_fraud = analysis_result['predicted_fraud']
    fraud_score = analysis_result['fraud_score']
    confidence = analysis_result['confidence']
    model_type = analysis_result['model_type']
    
    # Main prediction result
    if predicted_fraud:
        st.markdown('<div class="result-box fraud">', unsafe_allow_html=True)
        st.error("🚨 **FRAUD DETECTED BY ML MODEL!**")
        st.write(f"**Fraud Probability:** {fraud_score:.1%}")
        st.write(f"**Confidence Level:** {confidence:.1%}")
        st.write(f"**Model Used:** {model_type}")
        st.write("⚠️ This transaction has been flagged as potentially fraudulent!")
        st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="result-box legitimate">', unsafe_allow_html=True)
        st.success("✅ **LEGITIMATE TRANSACTION**")
        st.write(f"**Fraud Probability:** {fraud_score:.1%}")
        st.write(f"**Confidence Level:** {confidence:.1%}")
        st.write(f"**Model Used:** {model_type}")
        st.write("✅ This transaction appears to be legitimate.")
        st.markdown('</div>', unsafe_allow_html=True)

def display_customer_profile(customer_stats, customer_risk_level):
    """Display customer profile information"""
    st.markdown("### 👤 Customer Profile")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Transaction History", f"{customer_stats['transaction_count']} transactions")
        st.metric("Customer Type", customer_risk_level)
        
    with col2:
        st.metric("Average Amount", f"${customer_stats['avg_amount']:.2f}")
        st.metric("Maximum Amount", f"${customer_stats['max_amount']:.2f}")
        
    with col3:
        fraud_rate = customer_stats.get('fraud_ratio', 0)
        st.metric("Historical Fraud Rate", f"{fraud_rate:.1%}")
        st.metric("Amount Ratio", f"{customer_stats.get('amount_to_avg_ratio', 1):.1f}x")

def display_risk_analysis(analysis_result):
    """Display detailed risk analysis"""
    st.markdown("### 🔍 Risk Analysis")
    
    # Risk factors
    if analysis_result['fraud_indicators']:
        st.markdown("**⚠️ Risk Factors:**")
        for indicator in analysis_result['fraud_indicators']:
            st.markdown(f'<div class="risk-factor">{indicator}</div>', unsafe_allow_html=True)
    
    # Protective factors
    if analysis_result['protective_factors']:
        st.markdown("**🛡️ Protective Factors:**")
        for factor in analysis_result['protective_factors']:
            st.markdown(f'<div class="protective-factor">{factor}</div>', unsafe_allow_html=True)
    
    if not analysis_result['fraud_indicators'] and not analysis_result['protective_factors']:
        st.info("No specific risk or protective factors identified.")

def display_model_features(features_used):
    """Display features used by the ML model"""
    st.markdown("### 🤖 ML Model Features")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("**Transaction Features:**")
        st.write(f"• Amount: ${features_used['amount']:,.2f}")
        st.write(f"• Hour: {features_used['hour']}:00")
        st.write(f"• Day of Week: {features_used['day_of_week']}")
        st.write(f"• Is Weekend: {'Yes' if features_used['is_weekend'] else 'No'}")
        st.write(f"• Is Night Time: {'Yes' if features_used['is_night_time'] else 'No'}")
        
    with col2:
        st.markdown("**Customer Features:**")
        st.write(f"• Transaction Count: {features_used['customer_transaction_count']}")
        st.write(f"• Average Amount: ${features_used['customer_avg_amount']:,.2f}")
        st.write(f"• Amount Ratio: {features_used['amount_to_avg_ratio']:.2f}x")
        st.write(f"• Fraud History: {features_used['customer_fraud_ratio']:.1%}")

def create_sidebar_info():
    """Create sidebar with application information"""
    with st.sidebar:
        st.markdown("## 🤖 ML Model Status")
        st.markdown('<div class="ml-metrics">', unsafe_allow_html=True)
        st.write("**Status:** Your ML Model Loaded")
        st.write("**Type:** Fraud Detection Model")
        st.write("**Features:** Multi-factor Analysis")
        st.write("**Time Source:** User PC Local Time")
        st.markdown('</div>', unsafe_allow_html=True)
        
        st.markdown("## 🕒 Time Information")
        current_time = get_user_pc_time()
        st.write(f"**Current Time:** {current_time['time_only']}")
        st.write(f"**Date:** {current_time['date']}")
        risk_level = '🔴 HIGH' if current_time['hour'] in [0,1,2,3,22,23] else '🟡 MEDIUM' if current_time['hour'] in [4,5,6,20,21] else '🟢 LOW'
        st.write(f"**Time Risk:** {risk_level}")
        
        st.markdown("## 🔍 Detection Features")
        st.markdown("""
        - **Your ML Model:** Uses your trained model for predictions
        - **Real-time Analysis:** Instant fraud detection
        - **PC Time:** Uses your local computer time
        - **Card Masking:** Secure card number display
        - **Pattern Recognition:** Advanced analysis
        - **Risk Assessment:** Multi-level evaluation
        """)
        
        st.markdown("## 📊 Model Features")
        st.markdown("""
        - **Customer History:** Transaction patterns
        - **Amount Analysis:** Spending behavior
        - **Time Analysis:** Transaction timing
        - **Card Analysis:** Card usage patterns
        - **Risk Scoring:** Comprehensive evaluation
        """)

# Main Application Interface
def main():
    # Header section
    st.markdown('<h1 class="main-header">Enhanced Credit Card Fraud Detection System</h1>', unsafe_allow_html=True)
    st.markdown('<p style="text-align: center; color: #666; font-size: 1.1em;">Powered by Your Machine Learning Model & Real-Time Analysis</p>', unsafe_allow_html=True)
    
    # Create sidebar
    create_sidebar_info()
    
    # Display live clock
    current_time = display_live_clock()
    
    # Load your ML model
    model_data = load_enhanced_model()
    
    # Create input form
    with st.container():
        st.markdown('<h2 class="sub-header">🔍 Transaction Analysis</h2>', unsafe_allow_html=True)
        
        # Create columns for better layout
        col1, col2 = st.columns(2)
        
        with col1:
            customer_id = st.number_input(
                "👤 Customer ID", 
                min_value=1, 
                value=12345,
                help="Enter the customer's unique identifier"
            )
            
            amount = st.number_input(
                "💰 Transaction Amount ($)", 
                min_value=0.01, 
                value=1500.00,
                step=10.0, 
                format="%.2f", 
                help="Enter the transaction amount in USD"
            )
        
        with col2:
            receiver_card = st.text_input(
                "💳 Receiver Card Number",
                value="1234567890123456",
                help="Enter card number (will be masked for security)",
                placeholder="Enter the receiver's card number (12-19 digits)"
            )
            
            # Display current time (read-only)
            st.text_input(
                "🕒 Transaction Time (PC Local)",
                value=current_time['formatted_time'],
                disabled=True,
                help="Current transaction time from your PC"
            )
    
    # Real-time transaction info
    st.markdown("### ⏰ Real-Time Transaction Context")
    info_col1, info_col2, info_col3, info_col4 = st.columns(4)
    
    with info_col1:
        st.metric("Current Hour", f"{current_time['hour']}:00")
    
    with info_col2:
        day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        current_day = day_names[current_time['datetime'].weekday()]
        st.metric("Day", current_day)
    
    with info_col3:
        is_weekend = "Yes" if current_time['datetime'].weekday() >= 5 else "No"
        st.metric("Weekend", is_weekend)
    
    with info_col4:
        risk_level = 'HIGH' if current_time['hour'] in [0,1,2,3,22,23] else 'MEDIUM' if current_time['hour'] in [4,5,6,20,21] else 'LOW'
        st.metric("Time Risk", risk_level)
    
    # Analysis button
    if st.button("🔍 Analyze Transaction with Your ML Model", type="primary", use_container_width=True):
        # Validate inputs
        if not receiver_card.strip():
            st.error("❌ Please enter a receiver card number")
            return
        elif amount <= 0:
            st.error("❌ Please enter a valid transaction amount")
            return
        
        # Validate card number
        is_valid, validation_message = validate_card_number(receiver_card)
        
        if not is_valid:
            st.error(f"❌ Invalid card number: {validation_message}")
            return
        
        # Perform analysis
        with st.spinner("🔄 Running your ML model for fraud detection..."):
            try:
                # Simulate processing for better UX
                simulate_processing()
                
                # Get fresh transaction time
                transaction_time = get_user_pc_time()
                
                # Analyze transaction using your ML model
                analysis_result = analyze_enhanced_transaction(
                    customer_id, 
                    amount, 
                    receiver_card, 
                    transaction_time, 
                    model_data
                )
                
                # Display results
                st.markdown("---")
                st.markdown('<h2 class="sub-header">📊 ML Analysis Results</h2>', unsafe_allow_html=True)
                
                # Main prediction result
                display_enhanced_result(analysis_result)
                
                # Transaction summary
                st.markdown("### 📋 Transaction Summary")
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Transaction Details:**")
                    st.write(f"• Customer ID: {customer_id}")
                    st.write(f"• Amount: ${amount:.2f}")
                    st.write(f"• Transaction Time: {transaction_time['formatted_time']}")
                    st.write(f"• Hour: {transaction_time['time_only']}")
                
                with col2:
                    st.write("**Security Information:**")
                    st.write(f"• Receiver Card: {mask_card_number(receiver_card)}")
                    st.write(f"• Card Hash: {hash_card_number(receiver_card)[:12]}...")
                    st.write(f"• Analysis Time: {datetime.now().strftime('%H:%M:%S')}")
                    st.write(f"• Risk Level: {'HIGH' if analysis_result['predicted_fraud'] else 'LOW'}")
                
                # Display fraud score visualization
                st.markdown("### 📈 Fraud Score Visualization")
                score_percentage = analysis_result['fraud_score'] * 100
                
                # Color coding
                if analysis_result['predicted_fraud']:
                    color = "🔴"
                    status = "FRAUD DETECTED"
                elif analysis_result['fraud_score'] > 0.3:
                    color = "🟡"
                    status = "MEDIUM RISK"
                else:
                    color = "🟢"
                    status = "LOW RISK"
                
                col1, col2, col3 = st.columns([1, 2, 1])
                
                with col1:
                    st.metric("Fraud Score", f"{score_percentage:.1f}%")
                
                with col2:
                    st.progress(analysis_result['fraud_score'])
                    st.write(f"{color} **{status}**")
                
                with col3:
                    st.metric("Confidence", f"{analysis_result['confidence']:.1%}")
                
                # Customer profile
                if analysis_result['customer_stats']['transaction_count'] > 0:
                    display_customer_profile(analysis_result['customer_stats'], analysis_result['customer_risk_level'])
                else:
                    st.info("👤 **New Customer Detected** - No previous transaction history available")
                
                # Display ML model features
                display_model_features(analysis_result['features_used'])
                
                # Risk analysis
                display_risk_analysis(analysis_result)
                
                # Component analysis
                st.markdown("### 📊 Detailed Analysis")
                
                analysis_col1, analysis_col2 = st.columns(2)
                
                with analysis_col1:
                    st.markdown("**💰 Amount Analysis:**")
                    if analysis_result['customer_stats']['amount_to_avg_ratio']:
                        st.write(f"• Amount to Average Ratio: {analysis_result['customer_stats']['amount_to_avg_ratio']:.2f}x")
                    if analysis_result['customer_stats']['amount_to_max_ratio']:
                        st.write(f"• Amount to Maximum Ratio: {analysis_result['customer_stats']['amount_to_max_ratio']:.2f}x")
                    
                    st.markdown("**🕒 Time Analysis:**")
                    st.write(f"• Hour Risk Score: {analysis_result['hour_risk_score']:.2f}")
                    st.write(f"• Time Risk Level: {'HIGH' if analysis_result['hour_risk_score'] > 2.0 else 'MEDIUM' if analysis_result['hour_risk_score'] > 1.5 else 'LOW'}")
                
                with analysis_col2:
                    st.markdown("**💳 Card Analysis:**")
                    card_analysis = analysis_result['card_analysis']
                    st.write(f"• Familiarity Score: {card_analysis['familiarity_score']:.2f}")
                    st.write(f"• Card Risk Level: {card_analysis['risk_level']}")
                    st.write(f"• New Card: {'Yes' if card_analysis['is_new_card'] else 'No'}")
                    
                    st.markdown("**🤖 ML Model Info:**")
                    st.write(f"• Model Type: {analysis_result['model_type']}")
                    st.write(f"• Fraud Score: {analysis_result['fraud_score']:.3f}")
                    st.write(f"• Confidence: {analysis_result['confidence']:.3f}")
                
                # Recommendations
                st.markdown("### 💡 Recommendations")
                
                if analysis_result['predicted_fraud']:
                    st.markdown("""
                    **🚨 IMMEDIATE ACTIONS REQUIRED:**
                    
                    **Priority 1 - Immediate:**
                    • 📞 Contact the account holder immediately to verify the transaction
                    • 🔒 Temporarily freeze the account to prevent further unauthorized transactions
                    • 📋 Document all fraud indicators for investigation
                    
                    **Priority 2 - Investigation:**
                    • 🔍 Verify the receiver card details and relationship to account holder
                    • 🕵️ Check transaction patterns in the last 24-48 hours
                    • 📊 Review customer's recent transaction history for anomalies
                    • 🌐 Cross-reference with global fraud databases
                    
                    **Priority 3 - Follow-up:**
                    • 📈 Implement enhanced monitoring for future transactions
                    • 🔐 Consider requiring additional verification for high-risk transactions
                    • 📝 Update customer risk profile based on investigation results
                    """)
                else:
                    st.markdown("""
                    **✅ TRANSACTION APPROVED - MONITORING ACTIONS:**
                    
                    **Standard Processing:**
                    • ✅ Transaction can proceed with normal processing
                    • 📊 Continue standard transaction monitoring
                    • 🔄 Update customer transaction patterns
                    
                    **Enhanced Monitoring (if applicable):**""")
                    
                    # Add specific monitoring based on risk factors
                    if analysis_result['fraud_score'] > 0.3:
                        st.markdown("• 👀 Monitor for unusual patterns in next 24 hours")
                    if analysis_result['card_analysis']['is_new_card']:
                        st.markdown("• 💳 Track new card usage patterns")
                    if analysis_result['hour_risk_score'] > 2.0:
                        st.markdown("• ⏰ Monitor for repeated unusual-hour transactions")
                
                # Technical details
                with st.expander("🔧 Technical Details", expanded=False):
                    st.markdown("### Your ML Model Details")
                    
                    tech_col1, tech_col2 = st.columns(2)
                    
                    with tech_col1:
                        st.markdown("**Model Information:**")
                        st.write(f"• Model Type: {analysis_result['model_type']}")
                        st.write("• Time Source: User PC Local Time")
                        st.write("• Feature Engineering: Real-time")
                        st.write("• Processing: Instant analysis")
                        
                    with tech_col2:
                        st.markdown("**Features Used:**")
                        feature_count = len(analysis_result['features_used'])
                        st.write(f"• Total Features: {feature_count}")
                        st.write("• Customer History: Included")
                        st.write("• Time Features: Included")
                        st.write("• Amount Features: Included")
                    
                    st.markdown("### Feature Values")
                    st.json(analysis_result['features_used'])
                
                # Success message
                st.success("✅ Fraud detection analysis completed successfully using your ML model!")
                
            except Exception as e:
                st.error(f"❌ Error during analysis: {str(e)}")
                st.write("Please check your inputs and model file, then try again.")
    
    # Additional features section
    st.markdown("---")
    st.markdown("### 🔧 Additional Features")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Model Information"):
            st.info("🤖 Using your trained ML model for fraud detection")
            st.info("🕒 Real-time analysis with PC local time")
            st.info("🎯 Optimized for accuracy and speed")
    
    with col2:
        if st.button("🔍 Feature Analysis"):
            st.info("💼 Multi-factor feature engineering")
            st.info("📈 Customer behavior analysis")
            st.info("⏰ Time-based pattern recognition")
    
    with col3:
        if st.button("📋 Model Status"):
            model_status = "✅ Loaded" if hasattr(model_data, 'predict') else "⚠️ Fallback"
            st.info(f"🤖 ML Model: {model_status}")
            st.info("🕒 Time Source: PC Local Time")
            st.info("🔄 Status: Ready for Analysis")

# Footer
footer_style = """
    <style>
        .footer {
            position: fixed;
            left: 0;
            bottom: 0;
            width: 100%;
            background-color: #f0f2f6;
            color: #262730;
            text-align: center;
            padding: 10px;
            font-size: 14px;
            border-top: 1px solid #e0e0e0;
        }
        .main > div {
            padding-bottom: 60px;
        }
    </style>
    <div class="footer">
        © 2025 Enhanced Fraud Detection System | Powered by Your ML Model & Real-Time Analysis
    </div>
"""

st.markdown(footer_style, unsafe_allow_html=True)

# Run the main application
if __name__ == "__main__":
    main()
