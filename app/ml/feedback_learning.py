"""
Feedback Learning Module for UEBA System

This module implements feedback-based learning from analyst decisions:
1. Collects false positive/negative feedback
2. Retrains ML models with labeled data
3. Adjusts detection thresholds based on feedback
4. Creates whitelists for confirmed safe patterns

Usage:
    from app.ml.feedback_learning import FeedbackLearner
    
    learner = FeedbackLearner()
    learner.retrain_from_feedback()
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import os
import json
from app.models.database import db, Alert, Event, UserProfile


class FeedbackLearner:
    """
    Learns from analyst feedback to improve detection accuracy
    """
    
    def __init__(self):
        self.model_dir = 'app/ml/models'
        self.feedback_log = os.path.join(self.model_dir, 'feedback_log.json')
        os.makedirs(self.model_dir, exist_ok=True)
    
    
    def collect_feedback_data(self, days_back=30):
        """
        Collect labeled data from analyst feedback
        
        Returns:
            DataFrame with features and labels based on analyst decisions
        """
        cutoff_date = datetime.now() - timedelta(days=days_back)
        
        # Get alerts with analyst feedback
        labeled_alerts = Alert.query.filter(
            Alert.status.in_(['CLOSED', 'FALSE_POSITIVE']),
            Alert.created_at >= cutoff_date
        ).all()
        
        if not labeled_alerts:
            print("No labeled alerts found for training")
            return None
        
        feedback_data = []
        
        for alert in labeled_alerts:
            # Find related event
            event = Event.query.filter(
                Event.user_id == alert.user_id,
                Event.timestamp >= alert.timestamp - timedelta(seconds=1),
                Event.timestamp <= alert.timestamp + timedelta(seconds=1)
            ).first()
            
            if not event:
                continue
            
            # Extract features
            features = self._extract_event_features(event)
            
            # Label: 0 = False Positive (Normal), 1 = True Positive (Threat)
            label = 0 if alert.status == 'FALSE_POSITIVE' else 1
            
            features['label'] = label
            features['alert_id'] = alert.alert_id
            features['timestamp'] = alert.timestamp
            
            feedback_data.append(features)
        
        if not feedback_data:
            return None
        
        df = pd.DataFrame(feedback_data)
        
        print(f"Collected {len(df)} labeled samples:")
        print(f"  - True Threats: {(df['label'] == 1).sum()}")
        print(f"  - False Positives: {(df['label'] == 0).sum()}")
        
        return df
    
    
    def _extract_event_features(self, event):
        """
        Extract numerical features from event for ML training
        """
        features = {}
        
        # Time-based features
        hour = event.timestamp.hour
        features['hour'] = hour
        features['is_night'] = 1 if (hour < 6 or hour > 22) else 0
        features['is_weekend'] = 1 if event.timestamp.weekday() >= 5 else 0
        
        # Event type encoding
        event_type_map = {
            'Logon': 1, 'Device': 2, 'File': 3, 'Email': 4, 'HTTP': 5
        }
        features['event_type_code'] = event_type_map.get(event.event_type, 0)
        
        # Parse event details
        try:
            details = json.loads(event.details) if event.details else {}
        except:
            details = {}
        
        # Activity-based features
        activity = event.activity or ''
        features['is_removable_media'] = 1 if 'removable media' in activity.lower() else 0
        features['is_download'] = 1 if 'download' in activity.lower() else 0
        features['is_upload'] = 1 if 'upload' in activity.lower() else 0
        features['is_connect'] = 1 if 'connect' in activity.lower() else 0
        
        # Content analysis (keyword detection)
        content = str(details.get('content', '')).lower()
        suspicious_keywords = [
            'password', 'confidential', 'secret', 'hack', 'malware', 
            'breach', 'leak', 'dump', 'exploit'
        ]
        features['keyword_count'] = sum(1 for kw in suspicious_keywords if kw in content)
        
        # URL/Domain features
        url = details.get('url', '')
        features['has_url'] = 1 if url else 0
        features['url_length'] = len(url)
        
        # User historical features (if available)
        user = UserProfile.query.filter_by(user_id=event.user_id).first()
        if user:
            features['user_total_alerts'] = user.total_alerts or 0
            features['user_high_risk_alerts'] = user.high_risk_alerts or 0
        else:
            features['user_total_alerts'] = 0
            features['user_high_risk_alerts'] = 0
        
        return features
    
    
    def retrain_supervised_model(self, df):
        """
        Train a supervised Random Forest model using labeled feedback
        
        This model can distinguish between true threats and false positives
        """
        if df is None or len(df) < 10:
            print("Insufficient data for supervised training (need at least 10 samples)")
            return None
        
        # Prepare features
        feature_cols = [col for col in df.columns if col not in ['label', 'alert_id', 'timestamp']]
        X = df[feature_cols].fillna(0)
        y = df['label']
        
        # Check class balance
        if y.nunique() < 2:
            print("Need both true positives and false positives for training")
            return None
        
        # Train Random Forest
        print("\nTraining supervised Random Forest classifier...")
        clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            class_weight='balanced',  # Handle imbalanced data
            random_state=42
        )
        
        clf.fit(X, y)
        
        # Feature importance
        importance = pd.DataFrame({
            'feature': feature_cols,
            'importance': clf.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print("\nTop 10 Important Features:")
        print(importance.head(10))
        
        # Save model
        model_path = os.path.join(self.model_dir, 'supervised_classifier.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump({
                'model': clf,
                'feature_cols': feature_cols,
                'trained_date': datetime.now().isoformat()
            }, f)
        
        print(f"\nSupervised model saved to: {model_path}")
        
        return clf
    
    
    def adjust_isolation_forest(self, df):
        """
        Retrain Isolation Forest excluding confirmed false positives
        
        This helps reduce future false positive rate
        """
        if df is None or len(df) < 20:
            print("Insufficient data for Isolation Forest retraining")
            return None
        
        # Keep only true threats for anomaly detection training
        # (Remove false positives so model doesn't learn them as anomalies)
        true_threats = df[df['label'] == 1]
        
        if len(true_threats) < 10:
            print("Not enough true threat samples for retraining")
            return None
        
        feature_cols = [col for col in df.columns if col not in ['label', 'alert_id', 'timestamp']]
        X = true_threats[feature_cols].fillna(0)
        
        print(f"\nRetraining Isolation Forest on {len(X)} true threat samples...")
        
        # Train new Isolation Forest
        iso_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        iso_forest.fit(X)
        
        # Save model
        model_path = os.path.join(self.model_dir, 'isolation_forest_retrained.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump({
                'model': iso_forest,
                'feature_cols': feature_cols,
                'trained_date': datetime.now().isoformat()
            }, f)
        
        print(f"Retrained Isolation Forest saved to: {model_path}")
        
        return iso_forest
    
    
    def create_whitelist(self, df):
        """
        Create whitelist of patterns marked as false positives
        
        These patterns will be automatically filtered in future detections
        """
        if df is None:
            return []
        
        false_positives = df[df['label'] == 0]
        
        whitelist = []
        
        # Common false positive patterns
        for _, fp in false_positives.iterrows():
            pattern = {
                'user_id': None,  # Apply to all users or specific user
                'event_type': None,
                'activity_pattern': None,
                'reason': 'Marked as false positive by analyst'
            }
            
            # You can add more specific pattern matching here
            # For example, specific URLs, file types, etc.
            
            whitelist.append(pattern)
        
        # Save whitelist
        whitelist_path = os.path.join(self.model_dir, 'whitelist.json')
        with open(whitelist_path, 'w') as f:
            json.dump(whitelist, f, indent=4)
        
        print(f"\nWhitelist with {len(whitelist)} patterns saved")
        
        return whitelist
    
    
    def calculate_optimal_thresholds(self, df):
        """
        Analyze feedback to suggest optimal detection thresholds
        """
        if df is None or len(df) < 20:
            return None
        
        # Analyze risk scores from both true and false positives
        true_threats = df[df['label'] == 1]
        false_positives = df[df['label'] == 0]
        
        print("\n" + "="*50)
        print("THRESHOLD ANALYSIS")
        print("="*50)
        
        # If we have risk scores in the data
        if 'keyword_count' in df.columns:
            print("\nKeyword Count Distribution:")
            print(f"True Threats    - Mean: {true_threats['keyword_count'].mean():.2f}, Max: {true_threats['keyword_count'].max()}")
            print(f"False Positives - Mean: {false_positives['keyword_count'].mean():.2f}, Max: {false_positives['keyword_count'].max()}")
        
        # Suggest new thresholds based on analysis
        suggestions = {
            'critical_threshold': 0.85,  # Higher to reduce false positives
            'high_threshold': 0.70,
            'medium_threshold': 0.50,
            'low_threshold': 0.30
        }
        
        print("\nSuggested Thresholds (to reduce false positives):")
        for level, threshold in suggestions.items():
            print(f"  {level}: {threshold}")
        
        return suggestions
    
    
    def full_feedback_learning_cycle(self, days_back=30):
        """
        Complete feedback learning cycle:
        1. Collect feedback
        2. Retrain models
        3. Create whitelist
        4. Suggest new thresholds
        """
        print("="*70)
        print("FEEDBACK LEARNING CYCLE")
        print("="*70)
        
        # Step 1: Collect labeled data
        print("\n[1/4] Collecting labeled feedback data...")
        df = self.collect_feedback_data(days_back=days_back)
        
        if df is None:
            print("\n❌ No feedback data available. Need analysts to mark alerts as TRUE/FALSE POSITIVE.")
            return False
        
        # Step 2: Train supervised model
        print("\n[2/4] Training supervised classifier...")
        supervised_model = self.retrain_supervised_model(df)
        
        # Step 3: Retrain Isolation Forest
        print("\n[3/4] Retraining Isolation Forest...")
        iso_forest = self.adjust_isolation_forest(df)
        
        # Step 4: Create whitelist
        print("\n[4/4] Creating whitelist from false positives...")
        whitelist = self.create_whitelist(df)
        
        # Bonus: Suggest new thresholds
        print("\n[BONUS] Calculating optimal thresholds...")
        thresholds = self.calculate_optimal_thresholds(df)
        
        # Log the learning cycle
        self._log_learning_cycle(df, supervised_model, iso_forest)
        
        print("\n" + "="*70)
        print("✅ FEEDBACK LEARNING COMPLETE!")
        print("="*70)
        print("\nNext Steps:")
        print("1. Review retrained models in app/ml/models/")
        print("2. Update detection.py to use new supervised_classifier.pkl")
        print("3. Consider updating thresholds in settings")
        print("4. Monitor system for improved accuracy")
        
        return True
    
    
    def _log_learning_cycle(self, df, supervised_model, iso_forest):
        """Log details of learning cycle for audit trail"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'samples_collected': len(df) if df is not None else 0,
            'true_positives': int((df['label'] == 1).sum()) if df is not None else 0,
            'false_positives': int((df['label'] == 0).sum()) if df is not None else 0,
            'supervised_model_trained': supervised_model is not None,
            'isolation_forest_retrained': iso_forest is not None
        }
        
        # Append to log file
        if os.path.exists(self.feedback_log):
            with open(self.feedback_log, 'r') as f:
                logs = json.load(f)
        else:
            logs = []
        
        logs.append(log_entry)
        
        with open(self.feedback_log, 'w') as f:
            json.dump(logs, f, indent=4)


if __name__ == '__main__':
    """
    Run feedback learning cycle manually
    """
    from app import create_app
    
    app = create_app()
    
    with app.app_context():
        learner = FeedbackLearner()
        learner.full_feedback_learning_cycle(days_back=30)
