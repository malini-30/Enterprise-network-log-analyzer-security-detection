import json
from datetime import datetime
import os

class Reporter:
    def __init__(self, reports_directory):
        self.reports_directory = reports_directory
        
    def save_alerts(self, alerts, critical_alerts, alert_file='alerts.log', critical_file='critical_alerts.log'):
        """Save alerts to log files"""
        # Create logs directory if it doesn't exist
        if not os.path.exists('logs'):
            os.makedirs('logs')
        
        # Save regular alerts
        with open(f'logs/{alert_file}', 'a') as file:
            for alert in alerts:
                file.write(f"{alert['timestamp']} | {alert['ip']} | {alert['activity']} | {alert['rule']}\n")
        
        # Save critical alerts
        with open(f'logs/{critical_file}', 'a') as file:
            for alert in critical_alerts:
                file.write(f"{alert['timestamp']} | {alert['ip']} | {alert['activity']} | {alert['rule']}\n")
    
    def generate_daily_report(self, logs, alerts, critical_alerts, analysis_results):
        """Generate daily security report"""
        if not os.path.exists(self.reports_directory):
            os.makedirs(self.reports_directory)
        
        date_str = datetime.now().strftime("%Y-%m-%d")
        report_file = f"{self.reports_directory}/security_report_{date_str}.txt"
        
        with open(report_file, 'w') as file:
            file.write("=" * 60 + "\n")
            file.write(f"DAILY SECURITY REPORT - {date_str}\n")
            file.write("=" * 60 + "\n\n")
            
            # Summary
            file.write("SUMMARY\n")
            file.write("-" * 40 + "\n")
            file.write(f"Total logs processed: {analysis_results['total_logs']}\n")
            file.write(f"Unique IPs: {analysis_results['unique_ips']}\n")
            file.write(f"Total alerts: {len(alerts) + len(critical_alerts)}\n")
            file.write(f"Critical alerts: {len(critical_alerts)}\n")
            file.write(f"Failed login attempts: {analysis_results['failed_logins']}\n\n")
            
            # Threat Categories
            file.write("THREAT CATEGORIES TRIGGERED\n")
            file.write("-" * 40 + "\n")
            categories = set()
            for alert in alerts + critical_alerts:
                categories.add(alert['rule'])
            
            for category in categories:
                file.write(f"- {category}\n")
            file.write("\n")
            
            # Top Suspicious IPs
            file.write("TOP SUSPICIOUS IPS\n")
            file.write("-" * 40 + "\n")
            for ip, count in analysis_results['top_ips'][:5]:
                file.write(f"{ip}: {count} activities\n")
            file.write("\n")
            
            # Blocked Attempts
            file.write("BLOCKED ATTEMPTS\n")
            file.write("-" * 40 + "\n")
            blocked_count = sum(1 for alert in critical_alerts if 'Unauthorized' in alert['rule'] or 'blacklisted' in alert['activity'])
            file.write(f"Total blocked attempts: {blocked_count}\n\n")
            
            # Time-based Activity (simplified ASCII chart)
            file.write("ACTIVITY TIMELINE\n")
            file.write("-" * 40 + "\n")
            # Group by hour for simple chart
            hours = {}
            for log in logs:
                try:
                    hour = datetime.strptime(log['timestamp'], "%Y-%m-%d %H:%M:%S").hour
                    hours[hour] = hours.get(hour, 0) + 1
                except:
                    continue
            
            for hour in sorted(hours.keys()):
                bar = '#' * min(hours[hour] // 10, 50)  # Scale down for display
                file.write(f"{hour:02d}:00 | {bar} ({hours[hour]} requests)\n")
        
        print(f"Report generated: {report_file}")
        return report_file