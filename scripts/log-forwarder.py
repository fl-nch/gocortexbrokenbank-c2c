#!/usr/bin/env python3
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# GoCortex Broken Bank - Tomcat Log Forwarder
# Version: 1.5.0
#
# This script tails Tomcat access logs and forwards them to a configured
# HTTP endpoint for SIEM ingestion. The logs are shipped in their native
# Apache Combined format for compatibility with Tomcat-aware parsers.
#
# Usage:
#   python scripts/log-forwarder.py [--log-path /path/to/tomcat/logs]
#
# Environment variables:
#   LOG_ENDPOINT_TOMCAT_ACCESS - HTTP endpoint URL for log shipping
#   LOG_AUTH_TOMCAT_ACCESS - Authentication token for the endpoint

import os
import sys
import time
import glob
import argparse
import logging
import requests
from datetime import datetime

import yaml

# Suppress SSL warnings for intentionally insecure configuration
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class TomcatLogForwarder:
    """Forwards Tomcat access logs to HTTP endpoint."""
    
    def __init__(self, log_path=None, config_path="config/logging.yaml"):
        self.config = self._load_config(config_path)
        self.log_path = log_path or self._detect_log_path()
        self.last_position = {}
        self.running = False
        
    def _load_config(self, config_path):
        """Load logging configuration from YAML."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                return self._resolve_env_vars(config)
        except FileNotFoundError:
            logging.warning(f"Config not found at {config_path}, using environment variables")
            return {}
        except Exception as e:
            logging.error(f"Error loading config: {e}")
            return {}
    
    def _resolve_env_vars(self, obj):
        """Recursively resolve environment variable placeholders."""
        if isinstance(obj, dict):
            return {k: self._resolve_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._resolve_env_vars(item) for item in obj]
        elif isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
            env_var = obj[2:-1]
            return os.environ.get(env_var, "")
        return obj
    
    def _detect_log_path(self):
        """Detect Tomcat log directory."""
        common_paths = [
            "/opt/tomcat/logs",
            "/var/log/tomcat",
            "/usr/share/tomcat/logs",
            "./logs",
            "../exploit-app/logs"
        ]
        
        for path in common_paths:
            if os.path.isdir(path):
                return path
        
        return "/opt/tomcat/logs"
    
    def _get_endpoint_config(self):
        """Get tomcat_access endpoint configuration."""
        endpoint = self.config.get("endpoints", {}).get("tomcat_access", {})
        defaults = self.config.get("defaults", {})
        
        url = endpoint.get("url") or os.environ.get("LOG_ENDPOINT_TOMCAT_ACCESS", "")
        
        if not url:
            base_url = defaults.get("base_url", "")
            path = endpoint.get("path") or defaults.get("path", "")
            if base_url and path:
                url = base_url.rstrip("/") + "/" + path.lstrip("/")
                logging.info(f"Using default URL: {url}")
        
        auth_config = endpoint.get("auth", {})
        auth_type = auth_config.get("type", "header")
        
        if auth_type == "header":
            header_name = auth_config.get("header_name", "Authorization")
            header_value = auth_config.get("header_value") or os.environ.get("LOG_AUTH_TOMCAT_ACCESS", "")
        else:
            header_name = "Authorization"
            header_value = os.environ.get("LOG_AUTH_TOMCAT_ACCESS", "")
        
        return {
            "url": url,
            "header_name": header_name,
            "header_value": header_value
        }
    
    def _get_latest_log_file(self):
        """Get the most recent Tomcat access log file."""
        pattern = os.path.join(self.log_path, "localhost_access_log.*.txt")
        files = glob.glob(pattern)
        
        if not files:
            # Try alternate patterns
            alt_patterns = [
                os.path.join(self.log_path, "access_log.*.txt"),
                os.path.join(self.log_path, "catalina.*.log")
            ]
            for alt in alt_patterns:
                files = glob.glob(alt)
                if files:
                    break
        
        if not files:
            return None
        
        return max(files, key=os.path.getmtime)
    
    def _ship_log_line(self, line, endpoint_config):
        """Ship a single log line to the endpoint."""
        url = endpoint_config["url"]
        if not url:
            return False
        
        headers = {
            "Content-Type": "text/plain"
        }
        
        if endpoint_config["header_value"]:
            headers[endpoint_config["header_name"]] = endpoint_config["header_value"]
        
        try:
            response = requests.post(
                url,
                data=line.encode('utf-8'),
                headers=headers,
                timeout=10,
                verify=False
            )
            
            if response.status_code in [200, 201, 202, 204]:
                return True
            else:
                logging.warning(f"Failed to ship log: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            logging.error(f"Error shipping log: {e}")
            return False
    
    def _tail_file(self, filepath, endpoint_config):
        """Tail a log file and ship new lines."""
        if filepath not in self.last_position:
            # Start from end of file
            try:
                self.last_position[filepath] = os.path.getsize(filepath)
            except OSError:
                self.last_position[filepath] = 0
        
        try:
            current_size = os.path.getsize(filepath)
        except OSError:
            return
        
        if current_size < self.last_position[filepath]:
            # File was truncated or rotated
            self.last_position[filepath] = 0
        
        if current_size > self.last_position[filepath]:
            with open(filepath, 'r') as f:
                f.seek(self.last_position[filepath])
                
                for line in f:
                    line = line.strip()
                    if line:
                        # Only advance position after successful shipping
                        if self._ship_log_line(line, endpoint_config):
                            self.last_position[filepath] = f.tell()
                        else:
                            # Stop processing on failure to avoid data loss
                            logging.warning("Shipping failed, will retry from current position")
                            break
    
    def _cleanup_stale_positions(self):
        """Remove position entries for files that no longer exist or are older than 7 days."""
        stale_keys = []
        now = time.time()
        max_age_seconds = 7 * 24 * 60 * 60  # 7 days
        
        for filepath in list(self.last_position.keys()):
            try:
                if not os.path.exists(filepath):
                    stale_keys.append(filepath)
                else:
                    file_mtime = os.path.getmtime(filepath)
                    if now - file_mtime > max_age_seconds:
                        stale_keys.append(filepath)
            except OSError:
                stale_keys.append(filepath)
        
        for key in stale_keys:
            del self.last_position[key]
            logging.debug(f"Removed stale position entry: {key}")
        
        if stale_keys:
            logging.info(f"Cleaned up {len(stale_keys)} stale position entries")
    
    def run(self):
        """Main forwarder loop."""
        endpoint_config = self._get_endpoint_config()
        
        if not endpoint_config["url"]:
            logging.error("No endpoint URL configured. Set LOG_ENDPOINT_TOMCAT_ACCESS or configure in logging.yaml")
            return
        
        logging.info(f"Starting Tomcat log forwarder")
        logging.info(f"Log path: {self.log_path}")
        logging.info(f"Endpoint: {endpoint_config['url']}")
        
        self.running = True
        loop_counter = 0
        cleanup_interval = 3600  # Run cleanup every hour (3600 iterations at 1 sec each)
        
        while self.running:
            try:
                log_file = self._get_latest_log_file()
                
                if log_file:
                    self._tail_file(log_file, endpoint_config)
                else:
                    logging.debug(f"No log files found in {self.log_path}")
                
                # Periodic cleanup of stale position entries
                loop_counter += 1
                if loop_counter >= cleanup_interval:
                    self._cleanup_stale_positions()
                    loop_counter = 0
                
                time.sleep(1)
                
            except KeyboardInterrupt:
                logging.info("Shutting down...")
                break
            except Exception as e:
                logging.error(f"Error in forwarder loop: {e}")
                time.sleep(5)
        
        self.running = False
        logging.info("Tomcat log forwarder stopped")
    
    def stop(self):
        """Stop the forwarder."""
        self.running = False


def main():
    parser = argparse.ArgumentParser(description="Tomcat Log Forwarder for SIEM")
    parser.add_argument(
        "--log-path",
        help="Path to Tomcat logs directory",
        default=None
    )
    parser.add_argument(
        "--config",
        help="Path to logging.yaml config file",
        default="config/logging.yaml"
    )
    
    args = parser.parse_args()
    
    forwarder = TomcatLogForwarder(
        log_path=args.log_path,
        config_path=args.config
    )
    
    forwarder.run()


if __name__ == "__main__":
    main()
