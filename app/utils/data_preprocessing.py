import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
import hashlib
from pathlib import Path

class DataPreprocessor:
    """Handles preprocessing of CERT r4.2 dataset"""
    
    def __init__(self, data_path):
        self.data_path = Path(data_path)
        self.malicious_users = ['ACM2278', 'CMP2946', 'MBG3183', 'PLJ1771']
        
    def load_cert_data(self):
        """Load all CERT dataset files"""
        data = {}
        
        files = {
            'ldap': 'ldap.csv',
            'logon': 'logon.csv',
            'device': 'device.csv',
            'http': 'http.csv',
            'file': 'file.csv',
            'email': 'email.csv'
        }
        
        for key, filename in files.items():
            file_path = self.data_path / filename
            if file_path.exists():
                try:
                    data[key] = pd.read_csv(file_path)
                    print(f"Loaded {key}: {len(data[key])} records")
                except Exception as e:
                    print(f"Error loading {key}: {str(e)}")
                    data[key] = pd.DataFrame()
            else:
                print(f"File not found: {filename}")
                data[key] = pd.DataFrame()
        
        return data
    
    def parse_timestamp(self, timestamp_str):
        """Parse CERT timestamp format"""
        try:
            # CERT format: MM/DD/YYYY HH:MM:SS
            return pd.to_datetime(timestamp_str, format='%m/%d/%Y %H:%M:%S')
        except:
            return pd.NaT
    
    def process_logon_data(self, logon_df):
        """Process logon events"""
        if logon_df.empty:
            return pd.DataFrame()
        
        df = logon_df.copy()
        df['timestamp'] = df['date'].apply(self.parse_timestamp)
        df['event_type'] = 'LOGON'
        df['activity'] = df['activity']
        
        # Create event details
        df['details'] = df.apply(lambda x: json.dumps({
            'pc': x.get('pc', ''),
            'activity': x.get('activity', '')
        }), axis=1)
        
        df['event_id'] = df.apply(lambda x: self._generate_event_id(
            x['user'], x['timestamp'], 'LOGON'
        ), axis=1)
        
        return df[['event_id', 'user', 'timestamp', 'event_type', 'activity', 'details']]
    
    def process_device_data(self, device_df):
        """Process USB/device events"""
        if device_df.empty:
            return pd.DataFrame()
        
        df = device_df.copy()
        df['timestamp'] = df['date'].apply(self.parse_timestamp)
        df['event_type'] = 'DEVICE'
        df['activity'] = df['activity']
        
        # Create event details
        df['details'] = df.apply(lambda x: json.dumps({
            'pc': x.get('pc', ''),
            'activity': x.get('activity', ''),
            'file_tree': x.get('file_tree', '')
        }), axis=1)
        
        df['event_id'] = df.apply(lambda x: self._generate_event_id(
            x['user'], x['timestamp'], 'DEVICE'
        ), axis=1)
        
        return df[['event_id', 'user', 'timestamp', 'event_type', 'activity', 'details']]
    
    def process_http_data(self, http_df):
        """Process HTTP/web browsing events"""
        if http_df.empty:
            return pd.DataFrame()
        
        df = http_df.copy()
        df['timestamp'] = df['date'].apply(self.parse_timestamp)
        df['event_type'] = 'HTTP'
        df['activity'] = 'WEB_ACCESS'
        
        # Create event details
        df['details'] = df.apply(lambda x: json.dumps({
            'pc': x.get('pc', ''),
            'url': x.get('url', ''),
            'content': x.get('content', '')
        }), axis=1)
        
        df['event_id'] = df.apply(lambda x: self._generate_event_id(
            x['user'], x['timestamp'], 'HTTP'
        ), axis=1)
        
        return df[['event_id', 'user', 'timestamp', 'event_type', 'activity', 'details']]
    
    def process_file_data(self, file_df):
        """Process file access events"""
        if file_df.empty:
            return pd.DataFrame()
        
        df = file_df.copy()
        df['timestamp'] = df['date'].apply(self.parse_timestamp)
        df['event_type'] = 'FILE'
        df['activity'] = 'FILE_ACCESS'
        
        # Create event details
        df['details'] = df.apply(lambda x: json.dumps({
            'pc': x.get('pc', ''),
            'filename': x.get('filename', ''),
            'content': x.get('content', '')
        }), axis=1)
        
        df['event_id'] = df.apply(lambda x: self._generate_event_id(
            x['user'], x['timestamp'], 'FILE'
        ), axis=1)
        
        return df[['event_id', 'user', 'timestamp', 'event_type', 'activity', 'details']]
    
    def process_email_data(self, email_df):
        """Process email events"""
        if email_df.empty:
            return pd.DataFrame()
        
        df = email_df.copy()
        df['timestamp'] = df['date'].apply(self.parse_timestamp)
        df['event_type'] = 'EMAIL'
        df['activity'] = 'EMAIL_SENT'
        
        # Create event details
        df['details'] = df.apply(lambda x: json.dumps({
            'pc': x.get('pc', ''),
            'to': x.get('to', ''),
            'cc': x.get('cc', ''),
            'bcc': x.get('bcc', ''),
            'size': x.get('size', ''),
            'attachments': x.get('attachments', ''),
            'content': x.get('content', '')
        }), axis=1)
        
        df['event_id'] = df.apply(lambda x: self._generate_event_id(
            x['user'], x['timestamp'], 'EMAIL'
        ), axis=1)
        
        return df[['event_id', 'user', 'timestamp', 'event_type', 'activity', 'details']]
    
    def combine_all_events(self, data):
        """Combine all event types into single dataframe"""
        processed_events = []
        
        # Process each event type
        if not data['logon'].empty:
            processed_events.append(self.process_logon_data(data['logon']))
        
        if not data['device'].empty:
            processed_events.append(self.process_device_data(data['device']))
        
        if not data['http'].empty:
            processed_events.append(self.process_http_data(data['http']))
        
        if not data['file'].empty:
            processed_events.append(self.process_file_data(data['file']))
        
        if not data['email'].empty:
            processed_events.append(self.process_email_data(data['email']))
        
        # Combine all events
        if processed_events:
            all_events = pd.concat(processed_events, ignore_index=True)
            all_events = all_events.sort_values('timestamp').reset_index(drop=True)
            all_events['user'] = all_events['user'].str.strip()
            return all_events
        
        return pd.DataFrame()
    
    def filter_baseline_data(self, events_df, weeks=2):
        """Extract first N weeks of data for baseline, excluding malicious users"""
        if events_df.empty:
            return pd.DataFrame()
        
        # Remove malicious users
        baseline_df = events_df[~events_df['user'].isin(self.malicious_users)].copy()
        
        # Get first N weeks
        min_date = baseline_df['timestamp'].min()
        max_baseline_date = min_date + timedelta(weeks=weeks)
        
        baseline_df = baseline_df[baseline_df['timestamp'] <= max_baseline_date]
        
        print(f"Baseline data: {len(baseline_df)} events")
        print(f"Date range: {min_date} to {max_baseline_date}")
        print(f"Unique users: {baseline_df['user'].nunique()}")
        
        return baseline_df
    
    def load_ldap_structure(self, ldap_df):
        """Load organizational structure from LDAP"""
        if ldap_df.empty:
            return {}
        
        org_structure = {}
        
        for _, row in ldap_df.iterrows():
            user_id = row.get('user_id', '').strip()
            org_structure[user_id] = {
                'employee_name': row.get('employee_name', ''),
                'email': row.get('email', ''),
                'domain': row.get('domain', ''),
                'role': row.get('role', ''),
                'business_unit': row.get('business_unit', ''),
                'functional_unit': row.get('functional_unit', ''),
                'department': row.get('department', ''),
                'team': row.get('team', ''),
                'supervisor': row.get('supervisor', '')
            }
        
        return org_structure
    
    def _generate_event_id(self, user, timestamp, event_type):
        """Generate unique event ID"""
        raw = f"{user}{timestamp}{event_type}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]
    
    def save_processed_data(self, df, output_path, filename):
        """Save processed data to CSV"""
        output_file = Path(output_path) / filename
        output_file.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_file, index=False)
        print(f"Saved {len(df)} records to {output_file}")
        return output_file
