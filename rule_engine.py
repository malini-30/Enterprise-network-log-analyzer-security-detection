from datetime import datetime, timedelta
from collections import defaultdict

class RuleEngine:
    def __init__(self, config):
        self.config = config
        self.alerts = []
        self.critical_alerts = []
        self.alerted_ips = set()  # Track IPs we've already alerted on
        
    def analyzing_logs(self, logs):
        """Apply all detection rules to logs"""
        self.alerts = []
        self.critical_alerts = []
        self.alerted_ips = set()  # Reset for each analysis
        
        # Group logs by IP for some analyses
        ip_logs = defaultdict(list)
        for log in logs:
            ip_logs[log['source_ip']].append(log)
        
        # Apply each rule
        for log in logs:
            self.checking_blacklisted_ip(log)
            self.checking_restricted_endpoint(log)
            self.checking_firewall_block(log)
        
        # Check for brute force patterns
        self.checking_brute_force(ip_logs)
        
        # Check for high traffic
        self.checking_high_traffic(ip_logs)
        
        return self.alerts, self.critical_alerts
    
    def checking_blacklisted_ip(self, log):
        """Check if IP is blacklisted - prevent duplicate alerts"""
        ip = log['source_ip']
        
        # Only alert if IP is blacklisted AND we haven't alerted for this IP yet
        if ip in self.config['blacklisted_ips'] and ip not in self.alerted_ips:
            alert = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'ip': ip,
                'activity': f"Access from blacklisted IP",
                'rule': 'Suspicious IP Access',
                'severity': 'HIGH',
                'log_entry': log['raw_log']
            }
            self.critical_alerts.append(alert)
            self.alerted_ips.add(ip)  # Mark this IP as alerted
    
    def checking_restricted_endpoint(self, log):
        """Check for unauthorized endpoint access"""
        for endpoint in self.config['restricted_endpoints']:
            if endpoint in log['endpoint'] and log['status'] >= 400:
                # Create unique key for this type of alert
                alert_key = f"{log['source_ip']}_{endpoint}"
                
                if alert_key not in self.alerted_ips:
                    alert = {
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'ip': log['source_ip'],
                        'activity': f"Unauthorized access to {log['endpoint']}",
                        'rule': 'Unauthorized Access Attempt',
                        'severity': 'HIGH',
                        'log_entry': log['raw_log']
                    }
                    self.critical_alerts.append(alert)
                    self.alerted_ips.add(alert_key)
    
    def checking_firewall_block(self, log):
        """Check for firewall blocks"""
        if 'BLOCKED' in log['raw_log'].upper():
            # Only alert once per unique blocked log
            if log['raw_log'] not in self.alerted_ips:
                alert = {
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'ip': log.get('source_ip', 'UNKNOWN'),
                    'activity': "Firewall blocked request",
                    'rule': 'Firewall Block Alert',
                    'severity': 'MEDIUM',
                    'log_entry': log['raw_log']
                }
                self.alerts.append(alert)
                self.alerted_ips.add(log['raw_log'])
    
    def checking_brute_force(self, ip_logs):
        """Detect brute force login attempts"""
        threshold = self.config['thresholds']['failed_logins']
        time_window = self.config['thresholds']['time_window_minutes']
        
        for ip, logs in ip_logs.items():
            # Skip if we've already alerted for brute force on this IP
            if f"brute_force_{ip}" in self.alerted_ips:
                continue
                
            failed_logins = []
            for log in logs:
                # Check for failed login patterns (status 401, endpoint contains login)
                if log['status'] == 401 and ('login' in log['endpoint'].lower() or 'auth' in log['endpoint'].lower()):
                    failed_logins.append(log)
            
            if len(failed_logins) >= threshold:
                # Check if they occurred within time window
                timestamps = [datetime.strptime(log['timestamp'], "%Y-%m-%d %H:%M:%S") 
                            for log in failed_logins]
                timestamps.sort()
                
                for i in range(len(timestamps) - threshold + 1):
                    time_diff = timestamps[i + threshold - 1] - timestamps[i]
                    if time_diff.total_seconds() <= time_window * 60:
                        alert = {
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'ip': ip,
                            'activity': f"{threshold} failed logins in {time_window} minutes",
                            'rule': 'Brute Force Indicator',
                            'severity': 'HIGH',
                            'log_entry': f"Multiple failed logins from {ip}"
                        }
                        self.critical_alerts.append(alert)
                        self.alerted_ips.add(f"brute_force_{ip}")
                        break
    
    def checking_high_traffic(self, ip_logs):
        """Detect high traffic spikes"""
        threshold = self.config['thresholds']['high_traffic_requests']
        time_window = self.config['thresholds']['high_traffic_window_seconds']
        
        for ip, logs in ip_logs.items():
            # Skip if we've already alerted for high traffic on this IP
            if f"high_traffic_{ip}" in self.alerted_ips:
                continue
                
            if len(logs) >= threshold:
                # Sort logs by timestamp
                sorted_logs = sorted(logs, key=lambda x: x['timestamp'])
                
                for i in range(len(sorted_logs) - threshold + 1):
                    start_time = datetime.strptime(sorted_logs[i]['timestamp'], "%Y-%m-%d %H:%M:%S")
                    end_time = datetime.strptime(sorted_logs[i + threshold - 1]['timestamp'], "%Y-%m-%d %H:%M:%S")
                    
                    if (end_time - start_time).total_seconds() <= time_window:
                        alert = {
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            'ip': ip,
                            'activity': f"{threshold} requests in {time_window} seconds",
                            'rule': 'High Traffic Spike',
                            'severity': 'MEDIUM',
                            'log_entry': f"High traffic from {ip}"
                        }
                        self.alerts.append(alert)
                        self.alerted_ips.add(f"high_traffic_{ip}")
                        break