import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import json
import os

class UEBADetector:
    def __init__(self, config_path: str = "config.json"):
        """Initialize the UEBA Detector with configuration settings."""
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ueba_detector.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('UEBADetector')
        
        # Load configuration
        self.config = self._load_config(config_path)
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=float(self.config.get('contamination', 0.1)),
            random_state=42
        )

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.warning("Config file not found. Using default values.")
            return {
                "contamination": 0.1,
                "time_window_hours": 24,
                "features": [
                    "login_count",
                    "file_access_count",
                    "after_hours_access",
                    "sensitive_data_access",
                    "failed_login_attempts"
                ],
                "alert_threshold": -0.7
            }

    def process_user_activities(self, activities_df: pd.DataFrame) -> Tuple[pd.DataFrame, List[Dict]]:
        """
        Process user activities and detect anomalies.
        
        Args:
            activities_df: DataFrame with columns:
                - timestamp
                - user_id
                - activity_type
                - resource_accessed
                - success (boolean)
        
        Returns:
            Tuple containing processed DataFrame and list of alerts
        """
        try:
            # Aggregate features per user within time window
            features_df = self._extract_features(activities_df)
            
            # Detect anomalies
            anomalies = self._detect_anomalies(features_df)
            
            # Generate alerts
            alerts = self._generate_alerts(features_df, anomalies)
            
            return features_df, alerts

        except Exception as e:
            self.logger.error(f"Error processing user activities: {str(e)}")
            raise

    def _extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract relevant features from user activities."""
        features = pd.DataFrame()
        
        # Group by user_id
        grouped = df.groupby('user_id')
        
        features['login_count'] = grouped.apply(
            lambda x: len(x[x['activity_type'] == 'login'])
        )
        
        features['file_access_count'] = grouped.apply(
            lambda x: len(x[x['activity_type'] == 'file_access'])
        )
        
        # After hours access (assumed to be between 8 PM and 6 AM)
        features['after_hours_access'] = grouped.apply(
            lambda x: len(x[
                (pd.to_datetime(x['timestamp']).dt.hour >= 20) |
                (pd.to_datetime(x['timestamp']).dt.hour < 6)
            ])
        )
        
        features['sensitive_data_access'] = grouped.apply(
            lambda x: len(x[
                (x['activity_type'] == 'file_access') &
                (x['resource_accessed'].str.contains('confidential|restricted|sensitive', case=False))
            ])
        )
        
        features['failed_login_attempts'] = grouped.apply(
            lambda x: len(x[
                (x['activity_type'] == 'login') &
                (~x['success'])
            ])
        )
        
        return features

    def _detect_anomalies(self, features_df: pd.DataFrame) -> np.ndarray:
        """Detect anomalies using Isolation Forest."""
        # Scale features
        scaled_features = self.scaler.fit_transform(features_df)
        
        # Fit and predict
        return self.model.fit_predict(scaled_features)

    def _generate_alerts(self, features_df: pd.DataFrame, anomalies: np.ndarray) -> List[Dict]:
        """Generate alerts for detected anomalies."""
        alerts = []
        
        for idx, (user_id, features) in enumerate(features_df.iterrows()):
            if anomalies[idx] == -1:  # Anomaly detected
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "user_id": user_id,
                    "alert_type": "UEBA_ANOMALY",
                    "severity": self._calculate_severity(features),
                    "features": features.to_dict(),
                    "description": self._generate_alert_description(features)
                }
                alerts.append(alert)
                
                # Log alert
                self.logger.warning(f"Anomaly detected for user {user_id}: {alert['description']}")
        
        return alerts

    def _calculate_severity(self, features: pd.Series) -> str:
        """Calculate alert severity based on feature values."""
        severity_score = 0
        
        # Add to severity score based on different factors
        if features['failed_login_attempts'] > 5:
            severity_score += 3
        if features['after_hours_access'] > 10:
            severity_score += 2
        if features['sensitive_data_access'] > 5:
            severity_score += 3
        
        if severity_score >= 6:
            return "HIGH"
        elif severity_score >= 3:
            return "MEDIUM"
        return "LOW"

    def _generate_alert_description(self, features: pd.Series) -> str:
        """Generate human-readable alert description."""
        descriptions = []
        
        if features['failed_login_attempts'] > 5:
            descriptions.append(f"High number of failed login attempts ({features['failed_login_attempts']})")
        if features['after_hours_access'] > 10:
            descriptions.append(f"Unusual after-hours activity ({features['after_hours_access']} accesses)")
        if features['sensitive_data_access'] > 5:
            descriptions.append(f"Multiple sensitive data accesses ({features['sensitive_data_access']} files)")
        
        return ". ".join(descriptions) if descriptions else "Anomalous behavior detected based on user activity pattern"

if __name__ == "__main__":
    # Example usage
    detector = UEBADetector()
    
    # Sample data (in practice, this would come from your logging system)
    sample_data = {
        'timestamp': pd.date_range(start='2024-01-01', periods=100, freq='H'),
        'user_id': np.random.choice(['user1', 'user2', 'user3'], 100),
        'activity_type': np.random.choice(['login', 'file_access'], 100),
        'resource_accessed': np.random.choice(['confidential_doc', 'public_doc', 'restricted_file'], 100),
        'success': np.random.choice([True, False], 100, p=[0.9, 0.1])
    }
    
    activities_df = pd.DataFrame(sample_data)
    
    # Process activities and get alerts
    features_df, alerts = detector.process_user_activities(activities_df)
    
    # Print alerts
    for alert in alerts:
        print(f"\nAlert Generated:")
        print(json.dumps(alert, indent=2))