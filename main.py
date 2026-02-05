import json
import os
from datetime import datetime
from modules.log_parser import LogParser
from modules.rule_engine import RuleEngine
from modules.dashboard import Dashboard
from modules.reporter import Reporter

def loading_config(config_file='config.json'):
    """Load configuration from JSON file"""
    try:
        with open(config_file, 'r') as file:
            config = json.load(file)
        return config
    except FileNotFoundError:
        print(f"Configuration file {config_file} not found!")
        return None
    except json.JSONDecodeError:
        print(f"Error parsing {config_file}!")
        return None

def main():
    print("Enterprise Network Log Analyzer")
    print("=" * 40)
    
    # Load configuration
    config = loading_config()
    if not config:
        print("Failed to load configuration. Exiting.")
        return
    
    # Initialize components
    parser = LogParser(config['log_directory'])
    rule_engine = RuleEngine(config)
    dashboard = Dashboard()
    reporter = Reporter(config['reports_directory'])
    
    # Parse logs
    print("\n[1/5] Parsing log files...")
    logs = parser.parse_all_logs()
    
    if not logs:
        print("No logs found or unable to parse logs.")
        return
    
    print(f"Parsed {len(logs)} log entries.")
    
    # Analyze logs for threats
    print("\n[2/5] Analyzing logs for security threats...")
    alerts, critical_alerts = rule_engine.analyzing_logs(logs)
    
    # Display dashboard
    print("\n[3/5] Generating security dashboard...")
    analysis_results = dashboard.displaying_summary(logs, alerts, critical_alerts)
    
    # Save alerts
    print("\n[4/5] Saving alerts to log files...")
    reporter.save_alerts(alerts, critical_alerts)
    print(f"Saved {len(alerts)} alerts to logs/alerts.log")
    print(f"Saved {len(critical_alerts)} critical alerts to logs/critical_alerts.log")
    
    # Generate report
    print("\n[5/5] Generating daily security report...")
    report_file = reporter.generate_daily_report(logs, alerts, critical_alerts, analysis_results)
    
    print("\n" + "=" * 40)
    print("ANALYSIS COMPLETE")
    print("=" * 40)
    print(f"\nSummary:")
    print(f"- Processed {len(logs)} log entries")
    print(f"- Generated {len(alerts) + len(critical_alerts)} total alerts")
    print(f"- Created daily report: {report_file}")
    
    # Display recent critical alerts
    if critical_alerts:
        print("\nRecent Critical Alerts:")
        for alert in critical_alerts[:5]:
            print(f"  [{alert['timestamp']}] {alert['ip']} - {alert['activity']}")

if __name__ == "__main__":
    main()