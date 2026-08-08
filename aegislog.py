import re
import os
import time
import logging
import subprocess
import pandas as pd
from typing import List, Dict, Optional
from sklearn.ensemble import IsolationForest

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class AegisLogPipeline:
    def __init__(self, log_path: str, mitigation_script: str):
        self.log_path = log_path
        self.mitigation_script = mitigation_script
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.log_pattern = re.compile(
            r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] ".*?" (?P<status>\d{3}) (?P<size>\d+|-)'
        )
        self.blocked_ips = set()

    def parse_logs(self) -> pd.DataFrame:
        parsed_data: List[Dict[str, any]] = []
        
        if not os.path.exists(self.log_path):
            logging.warning(f"Log file {self.log_path} not found. Waiting for data...")
            return pd.DataFrame()

        with open(self.log_path, 'r') as file:
            for line in file:
                match = self.log_pattern.search(line)
                if match:
                    status = int(match.group('status'))
                    parsed_data.append({
                        'ip': match.group('ip'),
                        'is_error': 1 if status >= 400 else 0
                    })
        
        return pd.DataFrame(parsed_data)

    def extract_features(self, df: pd.DataFrame) -> Optional[pd.DataFrame]:
        if df.empty:
            return None

        features = df.groupby('ip').agg(
            request_count=('ip', 'count'),
            error_rate=('is_error', 'mean')
        ).reset_index()

        return features

    def detect_anomalies(self, features_df: pd.DataFrame):
        if len(features_df) < 5:
            return

        X = features_df[['request_count', 'error_rate']]
        
        features_df['anomaly_score'] = self.model.fit_predict(X)
        
        malicious_ips = features_df[
            (features_df['anomaly_score'] == -1) & 
            (~features_df['ip'].isin(self.blocked_ips))
        ]

        for _, row in malicious_ips.iterrows():
            ip = row['ip']
            logging.warning(f"Critical anomaly detected. Source: {ip} | Requests: {row['request_count']} | Error Rate: {row['error_rate']:.2f}")
            self.mitigate_threat(ip)

    def mitigate_threat(self, ip: str):
        logging.info(f"Initializing bash_firewall.sh subroutine for IP {ip}...")
        try:
            result = subprocess.run(
                ['bash', self.mitigation_script, ip], 
                capture_output=True, text=True, check=True
            )
            logging.info(result.stdout.strip())
            self.blocked_ips.add(ip)
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to apply mitigation rule for {ip}. Error: {e.stderr.strip()}")

    def run_daemon(self, interval: int = 10):
        logging.info("AegisLog service initialized. Monitoring access.log...")
        try:
            while True:
                df = self.parse_logs()
                features = self.extract_features(df)
                if features is not None:
                    self.detect_anomalies(features)
                time.sleep(interval)
        except KeyboardInterrupt:
            logging.info("AegisLog service terminated safely.")

if __name__ == "__main__":
    pipeline = AegisLogPipeline(
        log_path="access.log", 
        mitigation_script="bash_firewall.sh"
    )
    pipeline.run_daemon(interval=5)