import re
import json
from datetime import datetime
import os

class LogParser:
    def __init__(self, log_directory):
        self.log_directory = log_directory
        
    def parse_log_file(self, filename):
        """Parse a single log file"""
        logs = []
        filepath = os.path.join(self.log_directory, filename)
        
        try:
            with open(filepath, 'r') as file:
                for line in file:
                    parsed = self.parse_log_entry(line.strip())
                    if parsed:
                        logs.append(parsed)
        except FileNotFoundError:
            print(f"File {filename} not found in {self.log_directory}")
        
        return logs
    
    def parse_log_entry(self, log_entry):
        """Parse individual log entry"""
        patterns = [
            # Common log format: timestamp IP method endpoint status
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\d+\.\d+\.\d+\.\d+) (\w+) (.+) (\d+)',
            # With user ID: timestamp IP user method endpoint status
            r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (\d+\.\d+\.\d+\.\d+) (\w+) (\w+) (.+) (\d+)'
        ]
        
        for pattern in patterns:
            match = re.match(pattern, log_entry)
            if match:
                groups = match.groups()
                if len(groups) == 5:
                    timestamp, source_ip, method, endpoint, status = groups
                    user_id = None
                elif len(groups) == 6:
                    timestamp, source_ip, user_id, method, endpoint, status = groups
                
                return {
                    'timestamp': timestamp,
                    'source_ip': source_ip,
                    'user_id': user_id,
                    'method': method,
                    'endpoint': endpoint,
                    'status': int(status),
                    'raw_log': log_entry
                }
        
        return None
    
    def parse_all_logs(self):
        """Parse all log files in the directory"""
        all_logs = []
        
        if not os.path.exists(self.log_directory):
            print(f"Log directory {self.log_directory} not found")
            return all_logs
        
        for filename in os.listdir(self.log_directory):
            if filename.endswith('.log') or filename.endswith('.txt'):
                logs = self.parse_log_file(filename)
                all_logs.extend(logs)
        
        return all_logs