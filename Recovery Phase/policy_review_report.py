import os
import sys
import json
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import pandas as pd
import yaml
from jinja2 import Template
import matplotlib.pyplot as plt
import seaborn as sns
from dataclasses import dataclass
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('policy_review.log'),
        logging.StreamHandler()
    ]
)

class PolicyReviewReport:
    def __init__(self, config_path: str = 'policy_config.yaml'):
        """Initialize the policy review report generator"""
        self.config = self._load_config(config_path)
        self.violations_data = []
        self.access_data = []
        self.report_data = {}
        
    def _load_config(self, config_path: str) -> dict:
        """Load and validate configuration file"""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            required_keys = ['policies', 'thresholds', 'report_settings']
            for key in required_keys:
                if key not in config:
                    raise ValueError(f"Missing required configuration section: {key}")
                    
            return config
        except Exception as e:
            logging.error(f"Configuration loading failed: {str(e)}")
            raise

    def collect_data(self, start_date: datetime, end_date: datetime) -> None:
        """Collect all necessary data for the report"""
        self._collect_policy_violations(start_date, end_date)
        self._collect_access_changes(start_date, end_date)
        self._collect_system_logs(start_date, end_date)

    def _collect_policy_violations(self, start_date: datetime, end_date: datetime) -> None:
        """Collect policy violation data"""
        try:
            violation_files = [
                'security_violations.json',
                'access_violations.json',
                'data_violations.json'
            ]
            
            for file in violation_files:
                if os.path.exists(file):
                    with open(file, 'r') as f:
                        data = json.load(f)
                        filtered_data = [
                            entry for entry in data
                            if start_date <= datetime.fromisoformat(entry['timestamp']) <= end_date
                        ]
                        self.violations_data.extend(filtered_data)
                        
            logging.info(f"Collected {len(self.violations_data)} violation records")
        except Exception as e:
            logging.error(f"Error collecting violation data: {str(e)}")
            raise

    def _collect_access_changes(self, start_date: datetime, end_date: datetime) -> None:
        """Collect access change data"""
        try:
            with open('access_changes.json', 'r') as f:
                data = json.load(f)
                self.access_data = [
                    entry for entry in data
                    if start_date <= datetime.fromisoformat(entry['timestamp']) <= end_date
                ]
            logging.info(f"Collected {len(self.access_data)} access change records")
        except Exception as e:
            logging.error(f"Error collecting access change data: {str(e)}")
            raise

    def analyze_data(self) -> None:
        """Perform comprehensive data analysis"""
        self.report_data = {
            'summary': self._generate_summary(),
            'violation_analysis': self._analyze_violations(),
            'access_analysis': self._analyze_access_changes(),
            'risk_assessment': self._perform_risk_assessment(),
            'recommendations': self._generate_recommendations()
        }

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate executive summary of findings"""
        return {
            'total_violations': len(self.violations_data),
            'total_access_changes': len(self.access_data),
            'high_severity_incidents': sum(1 for v in self.violations_data if v['severity'] == 'HIGH'),
            'unique_users_affected': len(set(v['user_id'] for v in self.violations_data)),
            'compliance_score': self._calculate_compliance_score()
        }

    def _analyze_violations(self) -> Dict[str, Any]:
        """Analyze policy violations in detail"""
        df = pd.DataFrame(self.violations_data)
        
        analysis = {
            'severity_distribution': df['severity'].value_counts().to_dict(),
            'policy_distribution': df['policy_type'].value_counts().to_dict(),
            'temporal_analysis': self._analyze_temporal_patterns(df),
            'repeat_offenders': self._identify_repeat_offenders(df),
            'violation_categories': self._categorize_violations(df)
        }
        
        # Add trend analysis
        analysis['trends'] = self._analyze_trends(df)
        
        return analysis

    def _analyze_access_changes(self) -> Dict[str, Any]:
        """Analyze access change patterns"""
        df = pd.DataFrame(self.access_data)
        
        return {
            'change_types': df['change_type'].value_counts().to_dict(),
            'approver_analysis': self._analyze_approvers(df),
            'suspicious_patterns': self._identify_suspicious_patterns(df),
            'department_breakdown': self._analyze_by_department(df)
        }

    def _perform_risk_assessment(self) -> Dict[str, Any]:
        """Assess security risks based on collected data"""
        risks = {
            'high_risk_users': self._identify_high_risk_users(),
            'vulnerable_systems': self._identify_vulnerable_systems(),
            'policy_gaps': self._identify_policy_gaps(),
            'risk_metrics': self._calculate_risk_metrics()
        }
        return risks

    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Analyze high-risk areas
        if self.report_data['summary']['high_severity_incidents'] > self.config['thresholds']['high_severity_limit']:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Security Controls',
                'finding': 'Excessive high-severity security incidents',
                'recommendation': 'Implement additional security controls and monitoring',
                'suggested_actions': [
                    'Review and strengthen access controls',
                    'Implement additional monitoring tools',
                    'Conduct security awareness training'
                ]
            })
        
        # Add policy-specific recommendations
        for policy_type, count in self.report_data['violation_analysis']['policy_distribution'].items():
            if count > self.config['thresholds']['policy_violation_limit']:
                recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Policy Compliance',
                    'finding': f'High number of {policy_type} violations',
                    'recommendation': f'Review and update {policy_type} policies',
                    'suggested_actions': [
                        'Review current policy effectiveness',
                        'Update policy documentation',
                        'Conduct targeted training sessions'
                    ]
                })
        
        return recommendations

    def generate_visualizations(self, output_dir: str) -> None:
        """Generate visualization charts for the report"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Violation Severity Distribution
        plt.figure(figsize=(10, 6))
        severity_data = pd.Series(self.report_data['violation_analysis']['severity_distribution'])
        severity_data.plot(kind='bar')
        plt.title('Policy Violations by Severity')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'severity_distribution.png'))
        plt.close()
        
        # Temporal Analysis
        plt.figure(figsize=(12, 6))
        temporal_data = pd.DataFrame(self.report_data['violation_analysis']['temporal_analysis'])
        sns.lineplot(data=temporal_data)
        plt.title('Violation Trends Over Time')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'temporal_trends.png'))
        plt.close()
        
        # Department Risk Analysis
        plt.figure(figsize=(10, 6))
        dept_data = pd.DataFrame(self.report_data['access_analysis']['department_breakdown'])
        sns.heatmap(dept_data, annot=True, cmap='YlOrRd')
        plt.title('Department Risk Analysis')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'department_risk.png'))
        plt.close()

    def generate_report(self, output_path: str) -> None:
        """Generate the final report"""
        try:
            template_path = self.config['report_settings']['template_path']
            with open(template_path, 'r') as f:
                template = Template(f.read())
            
            report_html = template.render(
                report_data=self.report_data,
                generated_at=datetime.now(),
                company_name=self.config['report_settings']['company_name']
            )
            
            with open(output_path, 'w') as f:
                f.write(report_html)
                
            logging.info(f"Report generated successfully: {output_path}")
        except Exception as e:
            logging.error(f"Error generating report: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(description='Generate Policy Review Report')
    parser.add_argument('--config', default='policy_config.yaml', help='Path to configuration file')
    parser.add_argument('--start-date', required=True, help='Start date for report period (YYYY-MM-DD)')
    parser.add_argument('--end-date', required=True, help='End date for report period (YYYY-MM-DD)')
    parser.add_argument('--output', required=True, help='Output path for report')
    
    args = parser.parse_args()
    
    try:
        # Initialize report generator
        report_generator = PolicyReviewReport(args.config)
        
        # Parse dates
        start_date = datetime.strptime(args.start_date, '%Y-%m-%d')
        end_date = datetime.strptime(args.end_date, '%Y-%m-%d')
        
        # Generate report
        report_generator.collect_data(start_date, end_date)
        report_generator.analyze_data()
        report_generator.generate_visualizations('report_visuals')
        report_generator.generate_report(args.output)
        
        logging.info("Report generation completed successfully")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Report generation failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()