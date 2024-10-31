import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Set, Optional
import json
from collections import defaultdict
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('log_correlation.log'),
        logging.StreamHandler()
    ]
)

class LogCorrelationAnalyzer:
    def __init__(self, config_path: str = 'correlation_config.json'):
        """Initialize the log correlation analyzer"""
        self.load_config(config_path)
        self.events = defaultdict(list)
        self.alerts = []
        
    def load_config(self, config_path: str) -> None:
        """Load configuration settings"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            self.time_window = config.get('correlation_window_minutes', 30)
            self.suspicious_patterns = config.get('suspicious_patterns', [])
            self.high_risk_resources = set(config.get('high_risk_resources', []))
            logging.info("Configuration loaded successfully")
        except Exception as e:
            logging.error(f"Error loading configuration: {str(e)}")
            raise

    def process_log_entry(self, log_entry: Dict) -> Optional[Dict]:
        """Process a single log entry and correlate with existing events"""
        try:
            user_id = log_entry.get('user_id')
            timestamp = datetime.fromisoformat(log_entry.get('timestamp'))
            event_type = log_entry.get('event_type')
            resource = log_entry.get('resource')
            
            # Add event to user's timeline
            self.events[user_id].append({
                'timestamp': timestamp,
                'event_type': event_type,
                'resource': resource,
                'details': log_entry
            })
            
            # Clean old events
            self._clean_old_events(user_id, timestamp)
            
            # Check for suspicious patterns
            alert = self._check_patterns(user_id)
            if alert:
                self.alerts.append(alert)
                return alert
                
            return None

        except Exception as e:
            logging.error(f"Error processing log entry: {str(e)}")
            raise

    def _clean_old_events(self, user_id: str, current_time: datetime) -> None:
        """Remove events outside the correlation window"""
        cutoff_time = current_time - timedelta(minutes=self.time_window)
        self.events[user_id] = [
            event for event in self.events[user_id]
            if event['timestamp'] > cutoff_time
        ]

    def _check_patterns(self, user_id: str) -> Optional[Dict]:
        """Check for suspicious patterns in user events"""
        user_events = self.events[user_id]
        
        # Check for rapid access to multiple sensitive resources
        sensitive_resources = self._check_sensitive_resource_access(user_events)
        if sensitive_resources:
            return {
                'alert_type': 'multiple_sensitive_access',
                'severity': 'HIGH',
                'user_id': user_id,
                'timestamp': datetime.now(),
                'details': f"Rapid access to sensitive resources: {sensitive_resources}"
            }

        # Check for failed login followed by successful access
        if self._check_failed_login_pattern(user_events):
            return {
                'alert_type': 'suspicious_login_pattern',
                'severity': 'HIGH',
                'user_id': user_id,
                'timestamp': datetime.now(),
                'details': "Failed login followed by successful access from different location"
            }

        # Check for large data transfers
        large_transfers = self._check_large_data_transfers(user_events)
        if large_transfers:
            return {
                'alert_type': 'large_data_transfer',
                'severity': 'MEDIUM',
                'user_id': user_id,
                'timestamp': datetime.now(),
                'details': f"Large data transfers detected: {large_transfers}"
            }

        return None

    def _check_sensitive_resource_access(self, events: List[Dict]) -> Set[str]:
        """Check for rapid access to multiple sensitive resources"""
        sensitive_resources = set()
        for event in events:
            if event['resource'] in self.high_risk_resources:
                sensitive_resources.add(event['resource'])
        
        return sensitive_resources if len(sensitive_resources) >= 3 else set()

    def _check_failed_login_pattern(self, events: List[Dict]) -> bool:
        """Check for failed login followed by successful access pattern"""
        failed_logins = [
            event for event in events
            if event['event_type'] == 'login_failed'
        ]
        
        successful_accesses = [
            event for event in events
            if event['event_type'] == 'login_success'
        ]
        
        for failed in failed_logins:
            for success in successful_accesses:
                if (success['timestamp'] - failed['timestamp']).total_seconds() < 300:  # 5 minutes
                    if failed['details'].get('ip_address') != success['details'].get('ip_address'):
                        return True
        
        return False

    def _check_large_data_transfers(self, events: List[Dict]) -> List[str]:
        """Check for large data transfer events"""
        large_transfers = []
        for event in events:
            if (event['event_type'] == 'file_transfer' and 
                event['details'].get('size_mb', 0) > 100):  # 100MB threshold
                large_transfers.append(
                    f"{event['resource']} ({event['details']['size_mb']}MB)"
                )
        return large_transfers

    def generate_correlation_report(self) -> Dict:
        """Generate a summary report of correlated events"""
        report = {
            'total_alerts': len(self.alerts),
            'alerts_by_type': defaultdict(int),
            'alerts_by_severity': defaultdict(int),
            'users_with_alerts': set(),
            'timeline': []
        }
        
        for alert in self.alerts:
            report['alerts_by_type'][alert['alert_type']] += 1
            report['alerts_by_severity'][alert['severity']] += 1
            report['users_with_alerts'].add(alert['user_id'])
            report['timeline'].append({
                'timestamp': alert['timestamp'],
                'alert_type': alert['alert_type'],
                'severity': alert['severity'],
                'user_id': alert['user_id']
            })
        
        report['users_with_alerts'] = list(report['users_with_alerts'])
        return report

# Example usage
if __name__ == "__main__":
    analyzer = LogCorrelationAnalyzer()
    
    # Example log entry
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'user_id': 'user123',
        'event_type': 'file_access',
        'resource': '/sensitive/customer_data.db',
        'ip_address': '192.168.1.100',
        'size_mb': 150
    }
    
    # Process log entry
    alert = analyzer.process_log_entry(log_entry)
    if alert:
        logging.warning(f"Alert detected: {json.dumps(alert, default=str)}")