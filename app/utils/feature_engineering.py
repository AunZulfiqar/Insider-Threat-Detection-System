import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
from collections import defaultdict

class FeatureEngineer:
    """Feature engineering for behavioral analysis"""
    
    def __init__(self):
        self.feature_names = []
    
    def extract_features_per_user(self, events_df, user_id):
        """Extract features for a specific user"""
        user_events = events_df[events_df['user'] == user_id].copy()
        
        if user_events.empty:
            return pd.DataFrame()
        
        # Group events by date for daily aggregates
        user_events['date'] = user_events['timestamp'].dt.date
        daily_groups = user_events.groupby('date')
        
        features_list = []
        
        for date, day_events in daily_groups:
            features = self._extract_daily_features(day_events, user_id, date)
            features_list.append(features)
        
        features_df = pd.DataFrame(features_list)
        return features_df
    
    def _extract_daily_features(self, day_events, user_id, date):
        """Extract features for a single day"""
        features = {
            'user': user_id,
            'date': date
        }
        
        # Temporal features
        features.update(self._temporal_features(day_events))
        
        # Activity count features
        features.update(self._activity_count_features(day_events))
        
        # Behavioral features
        features.update(self._behavioral_features(day_events))
        
        # Network/HTTP features
        features.update(self._network_features(day_events))
        
        # File access features
        features.update(self._file_access_features(day_events))
        
        # USB/Device features
        features.update(self._device_features(day_events))
        
        # Email features
        features.update(self._email_features(day_events))
        
        return features
    
    def _temporal_features(self, day_events):
        """Extract temporal behavior features"""
        features = {}
        
        # Logon events
        logon_events = day_events[day_events['event_type'] == 'LOGON']
        
        if not logon_events.empty:
            # First logon time (hour of day)
            first_logon = logon_events['timestamp'].min()
            features['first_logon_hour'] = first_logon.hour
            features['first_logon_minute'] = first_logon.minute
            
            # Last logoff time
            last_event = logon_events['timestamp'].max()
            features['last_event_hour'] = last_event.hour
            
            # Work duration (hours)
            work_duration = (last_event - first_logon).total_seconds() / 3600
            features['work_duration_hours'] = work_duration
            
            # Day of week (0=Monday, 6=Sunday)
            features['day_of_week'] = first_logon.dayofweek
            
            # Is weekend
            features['is_weekend'] = 1 if first_logon.dayofweek >= 5 else 0
            
            # Logon count
            logon_count = len(logon_events[logon_events['activity'] == 'Logon'])
            logoff_count = len(logon_events[logon_events['activity'] == 'Logoff'])
            features['logon_count'] = logon_count
            features['logoff_count'] = logoff_count
        else:
            features['first_logon_hour'] = -1
            features['first_logon_minute'] = -1
            features['last_event_hour'] = -1
            features['work_duration_hours'] = 0
            features['day_of_week'] = day_events['timestamp'].iloc[0].dayofweek
            features['is_weekend'] = 1 if features['day_of_week'] >= 5 else 0
            features['logon_count'] = 0
            features['logoff_count'] = 0
        
        return features
    
    def _activity_count_features(self, day_events):
        """Count different activity types"""
        features = {}
        
        # Event type counts
        event_counts = day_events['event_type'].value_counts()
        features['logon_event_count'] = event_counts.get('LOGON', 0)
        features['device_event_count'] = event_counts.get('DEVICE', 0)
        features['http_event_count'] = event_counts.get('HTTP', 0)
        features['file_event_count'] = event_counts.get('FILE', 0)
        features['email_event_count'] = event_counts.get('EMAIL', 0)
        features['total_event_count'] = len(day_events)
        
        return features
    
    def _behavioral_features(self, day_events):
        """Extract behavioral patterns"""
        features = {}
        
        # Time between events (minutes)
        if len(day_events) > 1:
            time_diffs = day_events['timestamp'].diff().dt.total_seconds() / 60
            time_diffs = time_diffs.dropna()
            
            if len(time_diffs) > 0:
                features['avg_time_between_events'] = time_diffs.mean()
                features['std_time_between_events'] = time_diffs.std() if len(time_diffs) > 1 else 0
                features['max_time_between_events'] = time_diffs.max()
            else:
                features['avg_time_between_events'] = 0
                features['std_time_between_events'] = 0
                features['max_time_between_events'] = 0
        else:
            features['avg_time_between_events'] = 0
            features['std_time_between_events'] = 0
            features['max_time_between_events'] = 0
        
        # Unique PCs used
        unique_pcs = set()
        for _, event in day_events.iterrows():
            try:
                details = json.loads(event['details'])
                if 'pc' in details and details['pc']:
                    unique_pcs.add(details['pc'])
            except:
                pass
        
        features['unique_pc_count'] = len(unique_pcs)
        
        return features
    
    def _network_features(self, day_events):
        """Extract network/HTTP features"""
        features = {}
        
        http_events = day_events[day_events['event_type'] == 'HTTP']
        
        if not http_events.empty:
            features['http_request_count'] = len(http_events)
            
            # Unique domains accessed
            unique_domains = set()
            for _, event in http_events.iterrows():
                try:
                    details = json.loads(event['details'])
                    if 'url' in details:
                        url = details['url']
                        # Extract domain
                        if '://' in url:
                            domain = url.split('://')[1].split('/')[0]
                            unique_domains.add(domain)
                except:
                    pass
            
            features['unique_domains_count'] = len(unique_domains)
        else:
            features['http_request_count'] = 0
            features['unique_domains_count'] = 0
        
        return features
    
    def _file_access_features(self, day_events):
        """Extract file access features"""
        features = {}
        
        file_events = day_events[day_events['event_type'] == 'FILE']
        
        if not file_events.empty:
            features['file_access_count'] = len(file_events)
            
            # Unique files accessed
            unique_files = set()
            for _, event in file_events.iterrows():
                try:
                    details = json.loads(event['details'])
                    if 'filename' in details:
                        unique_files.add(details['filename'])
                except:
                    pass
            
            features['unique_files_count'] = len(unique_files)
        else:
            features['file_access_count'] = 0
            features['unique_files_count'] = 0
        
        return features
    
    def _device_features(self, day_events):
        """Extract USB/device features"""
        features = {}
        
        device_events = day_events[day_events['event_type'] == 'DEVICE']
        
        if not device_events.empty:
            features['device_event_count'] = len(device_events)
            
            # Connect/disconnect counts
            connect_count = len(device_events[device_events['activity'] == 'Connect'])
            disconnect_count = len(device_events[device_events['activity'] == 'Disconnect'])
            
            features['usb_connect_count'] = connect_count
            features['usb_disconnect_count'] = disconnect_count
        else:
            features['device_event_count'] = 0
            features['usb_connect_count'] = 0
            features['usb_disconnect_count'] = 0
        
        return features
    
    def _email_features(self, day_events):
        """Extract email features"""
        features = {}
        
        email_events = day_events[day_events['event_type'] == 'EMAIL']
        
        if not email_events.empty:
            features['email_sent_count'] = len(email_events)
            
            # Email size statistics
            total_size = 0
            attachment_count = 0
            
            for _, event in email_events.iterrows():
                try:
                    details = json.loads(event['details'])
                    if 'size' in details and details['size']:
                        total_size += int(details['size'])
                    if 'attachments' in details and details['attachments']:
                        attachment_count += len(details['attachments'].split(';'))
                except:
                    pass
            
            features['total_email_size'] = total_size
            features['email_with_attachments'] = attachment_count
        else:
            features['email_sent_count'] = 0
            features['total_email_size'] = 0
            features['email_with_attachments'] = 0
        
        return features
    
    def extract_features_batch(self, events_df):
        """Extract features for all users"""
        all_features = []
        
        unique_users = events_df['user'].unique()
        print(f"Extracting features for {len(unique_users)} users...")
        
        for i, user in enumerate(unique_users):
            if (i + 1) % 100 == 0:
                print(f"Processed {i + 1}/{len(unique_users)} users")
            
            user_features = self.extract_features_per_user(events_df, user)
            if not user_features.empty:
                all_features.append(user_features)
        
        if all_features:
            features_df = pd.concat(all_features, ignore_index=True)
            self.feature_names = [col for col in features_df.columns if col not in ['user', 'date']]
            print(f"Extracted {len(self.feature_names)} features")
            return features_df
        
        return pd.DataFrame()
    
    def get_feature_vector(self, features_df):
        """Get numerical feature vectors for ML"""
        if features_df.empty:
            return np.array([]), []
        
        # Select only numerical features
        feature_cols = [col for col in features_df.columns if col not in ['user', 'date']]
        X = features_df[feature_cols].fillna(0).values
        
        return X, feature_cols
