import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from pathlib import Path
from datetime import datetime
import json
import re
import os

def load_settings():
    """Load settings from JSON file"""
    settings_file = os.path.join('app', 'config', 'settings.json')
    
    # Create default settings if file doesn't exist
    if not os.path.exists(settings_file):
        os.makedirs(os.path.dirname(settings_file), exist_ok=True)
        default_settings = {
            "business_hours_start": 8,
            "business_hours_end": 18,
            "weekend_days": [5, 6],
            "critical_threshold": 0.9,
            "high_threshold": 0.7,
            "medium_threshold": 0.4,
            "low_threshold": 0.2
        }
        with open(settings_file, 'w') as f:
            json.dump(default_settings, f, indent=4)
        return default_settings
    
    with open(settings_file, 'r') as f:
        return json.load(f)

class AnomalyDetector:
    """Isolation Forest based anomaly detection"""
    
    def __init__(self, config):
        self.config = config
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = []
        self.is_trained = False
        # FIX: fixed bounds captured at training time, used for ALL future
        # normalization (including single-event predictions). Previously
        # min/max were recomputed per predict() call, which meant a batch
        # of size 1 always had min_score == max_score, forcing every live
        # event's anomaly score to 0.0 regardless of how anomalous it was.
        self.train_score_min = None
        self.train_score_max = None
        
    def train(self, X_train, feature_names):
        """Train Isolation Forest model"""
        print("Training Isolation Forest model...")
        print(f"Training samples: {X_train.shape[0]}")
        print(f"Features: {X_train.shape[1]}")
        
        # Store feature names
        self.feature_names = feature_names
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X_train)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=self.config['n_estimators'],
            contamination=self.config['contamination'],
            random_state=self.config['random_state'],
            max_samples=min(self.config.get('max_samples', 256), X_train.shape[0]),
            n_jobs=-1,
            verbose=1
        )
        
        self.model.fit(X_scaled)

        # FIX: capture the training set's score distribution ONCE.
        # All later predict() calls reuse these fixed bounds, instead of
        # recomputing min/max from whatever batch happens to be passed in.
        train_scores = self.model.score_samples(X_scaled)
        self.train_score_min = float(train_scores.min())
        self.train_score_max = float(train_scores.max())

        self.is_trained = True
        
        print("Model training completed!")
        print(f"Training score range captured: [{self.train_score_min:.4f}, {self.train_score_max:.4f}]")
        
        return self
    
    def predict(self, X):
        """Predict anomalies"""
        if not self.is_trained:
            raise ValueError("Model not trained yet!")
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Get predictions (-1 for anomaly, 1 for normal)
        predictions = self.model.predict(X_scaled)
        
        # Get anomaly scores (lower = more anomalous)
        scores = self.model.score_samples(X_scaled)
        
        # Convert to 0-1 range (higher = more anomalous)
        # Normalize scores to 0-1 range using FIXED training bounds
        anomaly_scores = self._normalize_scores(scores)
        
        return predictions, anomaly_scores
    
    def _normalize_scores(self, scores):
        """
        Normalize anomaly scores to 0-1 range using the FIXED score bounds
        captured during training (self.train_score_min / max), not the
        min/max of whatever batch is passed in here.

        This is what makes single-event (live) scoring meaningful: a batch
        of size 1 has no internal min/max to normalize against, so we must
        compare it against the training distribution instead.
        """
        if self.train_score_min is None or self.train_score_max is None:
            raise ValueError(
                "Training score bounds not set. Re-train the model or load "
                "a model file saved with the fixed save_model()/load_model()."
            )

        min_score = self.train_score_min
        max_score = self.train_score_max

        if max_score - min_score != 0:
            normalized = (max_score - scores) / (max_score - min_score)
        else:
            normalized = np.zeros_like(scores)

        # Scores outside the training range are possible for genuinely
        # extreme outliers — clip to keep anomaly scores in [0, 1].
        normalized = np.clip(normalized, 0.0, 1.0)

        return normalized
    
    def save_model(self, model_path, model_name='isolation_forest'):
        """Save trained model"""
        if not self.is_trained:
            raise ValueError("Model not trained yet!")
        
        model_path = Path(model_path)
        model_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save model
        model_file = model_path / f"{model_name}_{timestamp}.pkl"
        joblib.dump(self.model, model_file)
        
        # Save scaler
        scaler_file = model_path / f"{model_name}_scaler_{timestamp}.pkl"
        joblib.dump(self.scaler, scaler_file)
        
        # Save metadata
        metadata = {
            'model_name': model_name,
            'timestamp': timestamp,
            'feature_names': self.feature_names,
            'n_features': len(self.feature_names),
            'config': self.config,
            # FIX: persist the fixed normalization bounds so a freshly
            # loaded model still scores single live events correctly.
            'train_score_min': self.train_score_min,
            'train_score_max': self.train_score_max
        }
        
        metadata_file = model_path / f"{model_name}_metadata_{timestamp}.json"
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"Model saved to {model_file}")
        print(f"Scaler saved to {scaler_file}")
        print(f"Metadata saved to {metadata_file}")
        
        return {
            'model_file': str(model_file),
            'scaler_file': str(scaler_file),
            'metadata_file': str(metadata_file)
        }
    
    def load_model(self, model_file, scaler_file, metadata_file):
        """Load trained model"""
        self.model = joblib.load(model_file)
        self.scaler = joblib.load(scaler_file)
        
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        self.feature_names = metadata['feature_names']

        # FIX: load the fixed normalization bounds. Older metadata files
        # (saved before this fix) won't have these keys — fall back to
        # None and warn loudly, since predict() will raise instead of
        # silently returning zeroed-out scores.
        self.train_score_min = metadata.get('train_score_min')
        self.train_score_max = metadata.get('train_score_max')

        if self.train_score_min is None or self.train_score_max is None:
            print("⚠️  WARNING: metadata file has no train_score_min/max "
                  "(it was saved before the normalization fix). "
                  "Re-train and re-save the model, or run "
                  "recalibrate_score_bounds() with representative training "
                  "data before using predict() on single events.")

        self.is_trained = True
        
        print(f"Model loaded successfully!")
        print(f"Features: {len(self.feature_names)}")
        
        return self

    def recalibrate_score_bounds(self, X_reference):
        """
        One-time fix for models saved BEFORE this normalization fix existed
        (e.g. your current isolation_forest_20260110_201926.pkl).
        Pass in the same training feature matrix used originally (or a
        large representative sample) to recompute and store the bounds.
        """
        if self.model is None:
            raise ValueError("Load or train a model first.")
        X_scaled = self.scaler.transform(X_reference)
        scores = self.model.score_samples(X_scaled)
        self.train_score_min = float(scores.min())
        self.train_score_max = float(scores.max())
        print(f"Recalibrated score bounds: [{self.train_score_min:.4f}, {self.train_score_max:.4f}]")
        return self.train_score_min, self.train_score_max


class KeywordDetector:
    """Detect suspicious keywords with whole-word matching to avoid false positives"""
    
    def __init__(self, keywords):
        """
        Initialize with list of keywords
        
        Args:
            keywords: List of suspicious keywords (strings)
        """
        self.keywords = [k.lower() for k in keywords] if keywords else []
        
    def detect(self, text):
        """
        Detect suspicious keywords in text using whole-word matching
        
        Args:
            text: String to search for keywords
            
        Returns:
            tuple: (has_keyword: bool, found_keywords: list)
        """
        if not text:
            return False, []
        
        text_lower = text.lower()
        found_keywords = []
        
        for keyword in self.keywords:
            # Use word boundary regex to match whole words only
            # \b ensures we match whole words, not substrings
            # Example: \btor\b matches "tor" but not "tutorial" or "actor"
            pattern = r'\b' + re.escape(keyword) + r'\b'
            
            if re.search(pattern, text_lower):
                found_keywords.append(keyword)
        
        has_keyword = len(found_keywords) > 0
        return has_keyword, found_keywords
    
    def detect_in_event(self, event_details):
        """
        Detect keywords in event details (searches multiple fields)
        
        Args:
            event_details: Dict or JSON string of event details
            
        Returns:
            tuple: (has_keyword: bool, found_keywords: list, fields_matched: list)
        """
        # Parse event details
        try:
            if isinstance(event_details, str):
                details = json.loads(event_details)
            else:
                details = event_details
        except:
            return False, [], []
        
        # Fields to search for keywords
        searchable_fields = ['url', 'content', 'filename', 'activity', 
                            'to', 'from', 'subject', 'pc']
        
        all_found_keywords = []
        fields_matched = []
        
        for field in searchable_fields:
            if field in details and details[field]:
                has_keyword, found_keywords = self.detect(str(details[field]))
                if has_keyword:
                    all_found_keywords.extend(found_keywords)
                    fields_matched.append(field)
        
        # Remove duplicates while preserving order
        unique_keywords = list(dict.fromkeys(all_found_keywords))
        
        return len(unique_keywords) > 0, unique_keywords, fields_matched


class RiskScorer:
    """Calculate risk scores based on anomaly scores, keywords, and contextual factors"""
    
    def __init__(self, severity_weights, thresholds, keywords=None):
        self.severity_weights = severity_weights
        self.thresholds = thresholds
        self.keyword_detector = KeywordDetector(keywords) if keywords else None
        
        # Load business hours from settings
        settings = load_settings()
        self.business_hours_start = settings.get('business_hours_start', 8)
        self.business_hours_end = settings.get('business_hours_end', 18)
        self.weekend_days = settings.get('weekend_days', [5, 6])
    
    def reload_settings(self):
        """Reload settings from settings.json"""
        settings = load_settings()
        self.business_hours_start = settings.get('business_hours_start', 8)
        self.business_hours_end = settings.get('business_hours_end', 18)
        self.weekend_days = settings.get('weekend_days', [5, 6])
        self.thresholds = {
            'critical': settings.get('critical_threshold', 0.9),
            'high': settings.get('high_threshold', 0.7),
            'medium': settings.get('medium_threshold', 0.4),
            'low': settings.get('low_threshold', 0.2)
        }
        print("✅ RiskScorer settings reloaded")
        
    def calculate_risk_score(self, anomaly_score, event_details, user_profile=None, 
                            keyword_detection_enabled=True, ml_detection_enabled=True):
        """
        Calculate comprehensive risk score combining ML and keyword detection
        
        Args:
            anomaly_score: ML-based anomaly score (0-1)
            event_details: Event details dict or JSON string
            user_profile: Optional user profile for context
            keyword_detection_enabled: Whether to check for keywords
            ml_detection_enabled: Whether to use ML anomaly score
            
        Returns:
            dict with 'score', 'level', 'keywords_found', 'detection_method'
        """
        # Initialize scores
        ml_score = anomaly_score if ml_detection_enabled else 0
        keyword_score = 0
        keywords_found = []
        fields_matched = []
        
        # Keyword detection
        if keyword_detection_enabled and self.keyword_detector:
            has_keyword, keywords_found, fields_matched = self.keyword_detector.detect_in_event(event_details)
            if has_keyword:
                keyword_score = self.severity_weights.get('keyword_detected', 0.70)
        
        # Start with the higher of ML or keyword score
        risk_score = max(ml_score, keyword_score)
        
        # Parse event details for contextual adjustments
        try:
            details = json.loads(event_details) if isinstance(event_details, str) else event_details
        except:
            details = {}
        
        # Contextual adjustments (boost risk score)
        contextual_boost = 0
        
        # Track context for smart detection
        is_after_hours = False
        is_weekend = False
        
        # ========================================
        # TIME CONTEXT DETECTION
        # ========================================
        if 'timestamp' in details:
            timestamp = pd.to_datetime(details['timestamp'])
            hour = timestamp.hour
            day_of_week = timestamp.weekday()
            
            # Check if weekend (more suspicious than after-hours)
            is_weekend = day_of_week in self.weekend_days
            
            # Check if after hours on weekday (exclude weekend)
            is_after_hours = (hour < self.business_hours_start or 
                            hour >= self.business_hours_end) and not is_weekend
            
            event_type = details.get('event_type', '').upper()
            
            # WEEKEND ACTIVITY (Most suspicious - even during "business hours")
            if is_weekend:
                if event_type == 'LOGON':
                    contextual_boost += 0.30
                    print(f"   📅 Weekend LOGON detected (+0.30)")
                else:
                    contextual_boost += 0.50
                    print(f"   📅 Weekend {event_type} activity detected (+0.50)")
            
            # AFTER-HOURS WEEKDAY (Less suspicious than weekend)
            elif is_after_hours:
                if event_type == 'LOGON':
                    contextual_boost += 0.25
                    print(f"   ⏰ After-hours LOGON detected (+0.25)")
                else:
                    contextual_boost += 0.40
                    print(f"   ⏰ After-hours {event_type} activity detected (+0.40)")
        
        # Also check pre-calculated weekend flag for backwards compatibility
        elif 'is_weekend' in details and details['is_weekend']:
            is_weekend = True
            event_type = details.get('event_type', '').upper()
            if event_type == 'LOGON':
                contextual_boost += 0.30
                print(f"   📅 Weekend LOGON detected (+0.30)")
            else:
                contextual_boost += 0.50
                print(f"   📅 Weekend activity detected (+0.50)")
        
        # ========================================
        # USB/DEVICE DETECTION (CONTEXT-AWARE)
        # ========================================
        if 'event_type' in details and details['event_type'] == 'DEVICE':
            if is_weekend:
                # Weekend USB is VERY suspicious
                contextual_boost += 0.30  # Total: 0.50 + 0.30 = 0.80 HIGH
                print(f"   💾 Weekend USB/Device detected (+0.30 additional)")
            elif is_after_hours:
                # After-hours USB is suspicious
                contextual_boost += 0.30  # Total: 0.40 + 0.30 = 0.70 HIGH
                print(f"   💾 After-hours USB/Device detected (+0.30 additional)")
            else:
                # Business hours USB
                contextual_boost += 0.30
                print(f"   💾 USB/Device event detected (+0.30)")
        
        # ========================================
        # SUSPICIOUS URL DETECTION
        # ========================================
        if 'url' in details:
            url = details['url'].lower()
            suspicious_patterns = ['hack', 'crack', 'warez', 'torrent', 'leak', 'dump']
            if any(pattern in url for pattern in suspicious_patterns):
                contextual_boost += self.severity_weights.get('malicious_domain', 0.40)
                print(f"   🌐 Suspicious URL detected (+0.40)")
        
        # ========================================
        # SENSITIVE FILE ACCESS
        # ========================================
        if 'filename' in details:
            filename = details['filename'].lower()
            sensitive_keywords = ['confidential', 'secret', 'private', 'password', 'salary', 'financial']
            if any(keyword in filename for keyword in sensitive_keywords):
                contextual_boost += self.severity_weights.get('sensitive_file_access', 0.30)
                print(f"   📁 Sensitive file access detected (+0.30)")
        
        # ========================================
        # HIGH DATA VOLUME
        # ========================================
        if 'total_email_size' in details and details['total_email_size'] > 10000000:  # 10MB
            contextual_boost += self.severity_weights.get('unusual_data_volume', 0.25)
            print(f"   📊 High data volume detected (+0.25)")
        
        # Final risk score (capped at 1.0)
        final_risk_score = min(risk_score + contextual_boost, 1.0)
        
        # Determine detection method
        detection_method = []
        if keyword_score > 0:
            detection_method.append('keyword')
        if ml_score > 0:
            detection_method.append('ml')
        if contextual_boost > 0:
            detection_method.append('contextual')
        
        return {
            'score': final_risk_score,
            'level': self.get_risk_level(final_risk_score),
            'keywords_found': keywords_found,
            'fields_matched': fields_matched,
            'detection_method': '+'.join(detection_method) if detection_method else 'none',
            'ml_score': ml_score,
            'keyword_score': keyword_score,
            'contextual_boost': contextual_boost
        }
    
    def get_risk_level(self, risk_score):
        """Determine risk level from score (4 levels: CRITICAL, HIGH, MEDIUM, LOW)"""
        if risk_score >= self.thresholds.get('critical', 0.9):
            return 'CRITICAL'
        elif risk_score >= self.thresholds.get('high', 0.7):
            return 'HIGH'
        elif risk_score >= self.thresholds.get('medium', 0.4):
            return 'MEDIUM'
        elif risk_score >= self.thresholds.get('low', 0.2):
            return 'LOW'
        else:
            return 'NORMAL'
    
    def generate_alert_description(self, risk_result, event_details):
        """
        Generate human-readable alert description
        
        Args:
            risk_result: Dict from calculate_risk_score()
            event_details: Event details dict or JSON
            
        Returns:
            String description
        """
        try:
            details = json.loads(event_details) if isinstance(event_details, str) else event_details
        except:
            details = {}
        
        event_type = details.get('event_type', 'UNKNOWN')
        risk_level = risk_result['level']
        risk_score = risk_result['score']
        keywords = risk_result['keywords_found']
        
        # Base description
        descriptions = {
            'CRITICAL': f"CRITICAL: {event_type} activity with high threat indicators",
            'HIGH': f"HIGH RISK: Suspicious {event_type} activity detected",
            'MEDIUM': f"MEDIUM RISK: {event_type} anomaly detected",
            'LOW': f"LOW RISK: Minor {event_type} deviation from baseline"
        }
        
        base_description = descriptions.get(risk_level, f"{event_type} activity detected")
        base_description += f" (score: {risk_score:.3f})"
        
        # Add keyword information
        if keywords:
            base_description += f". Suspicious keywords detected: {', '.join(keywords)}"
        
        # Add specific details
        additional_info = []
        
        if 'url' in details and details['url']:
            url = details['url'][:100]  # Truncate long URLs
            additional_info.append(f"URL: {url}")
        
        if 'filename' in details and details['filename']:
            additional_info.append(f"File: {details['filename']}")
        
        if details.get('event_type') == 'DEVICE':
            additional_info.append("USB/External device activity")
        
        if 'pc' in details:
            additional_info.append(f"PC: {details['pc']}")
        
        if additional_info:
            base_description += ". " + ". ".join(additional_info)
        
        return base_description