# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# GoCortex Broken Bank - Background Authentication Traffic Generator
# Version: 1.5.0
#
# This module generates simulated authentication traffic for SIEM testing.
# It produces realistic-looking login events with seeded anomalies for demo purposes.

import os
import random
import threading
import time
import logging
from datetime import datetime, timezone

import yaml
from faker import Faker

from log_shipping import get_log_shipper
import observability.metrics as metrics

# Initialise Faker for username generation
fake = Faker(['en_AU', 'en_GB', 'en_US'])


class AuthTrafficGenerator:
    """Generates simulated authentication traffic with seeded anomalies."""
    
    def __init__(self, logging_config_path="config/logging.yaml", 
                 anomaly_config_path="config/anomaly_seeds.yaml"):
        self.logging_config = self._load_config(logging_config_path)
        self.anomaly_config = self._load_config(anomaly_config_path)
        self.running = False
        self.thread = None
        self.last_anomaly_time = {}
        
        # Cache user pool for repeat logins
        self.user_pool = self._generate_user_pool(100)
        
    def _load_config(self, config_path):
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logging.warning(f"Config not found at {config_path}")
            return {}
        except Exception as e:
            logging.error(f"Error loading config {config_path}: {e}")
            return {}
    
    def _generate_user_pool(self, size):
        """Generate a pool of usernames for realistic repeat logins."""
        users = []
        for _ in range(size):
            users.append({
                "username": fake.user_name(),
                "weight": random.randint(1, 10)
            })
        return users
    
    def _get_weighted_username(self):
        """Get a username with weighted selection for repeat logins."""
        total_weight = sum(u["weight"] for u in self.user_pool)
        r = random.uniform(0, total_weight)
        current = 0
        for user in self.user_pool:
            current += user["weight"]
            if r <= current:
                return user["username"]
        return self.user_pool[0]["username"]
    
    def _generate_random_ip(self):
        """Generate a random non-RFC1918 IP address."""
        while True:
            octets = [random.randint(1, 254) for _ in range(4)]
            
            # Exclude RFC1918 private ranges
            if octets[0] == 10:
                continue
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                continue
            if octets[0] == 192 and octets[1] == 168:
                continue
            # Exclude loopback
            if octets[0] == 127:
                continue
            # Exclude multicast
            if octets[0] >= 224:
                continue
            
            return ".".join(str(o) for o in octets)
    
    def _generate_random_ipv6(self):
        """Generate a random IPv6 address."""
        segments = [format(random.randint(0, 65535), 'x') for _ in range(8)]
        return ":".join(segments)
    
    def _get_random_user_agent(self):
        """Get a random legitimate user agent string."""
        user_agents = [
            # Chrome Desktop
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Firefox Desktop
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            # Safari Desktop
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            # Chrome Mobile
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1",
            # Safari Mobile
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            # Edge Desktop
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
            # Samsung Browser
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36"
        ]
        return random.choice(user_agents)
    
    def _get_random_country(self):
        """Get a random country based on configured weights."""
        countries = self.anomaly_config.get("normal_traffic", {}).get("countries", [
            {"code": "AU", "weight": 70},
            {"code": "KR", "weight": 20},
            {"code": "US", "weight": 5},
            {"code": "GB", "weight": 5}
        ])
        
        total_weight = sum(c["weight"] for c in countries)
        r = random.uniform(0, total_weight)
        current = 0
        for country in countries:
            current += country["weight"]
            if r <= current:
                return country["code"]
        return "AU"
    
    def _get_device_type(self, user_agent):
        """Detect device type from user agent."""
        ua_lower = user_agent.lower()
        if any(m in ua_lower for m in ["mobile", "android", "iphone", "ipod"]):
            return "mobile"
        elif any(t in ua_lower for t in ["ipad", "tablet"]):
            return "tablet"
        return "desktop"
    
    def _should_inject_anomaly(self, anomaly_type):
        """Check if it's time to inject a specific anomaly type."""
        now = time.time()
        last_time = self.last_anomaly_time.get(anomaly_type, 0)
        
        # Get frequency for this anomaly type
        if anomaly_type == "ip":
            frequency_minutes = self.anomaly_config.get("anomaly_config", {}).get("frequency_minutes", 10)
        elif anomaly_type in ["brute_force", "credential_stuffing", "impossible_travel", "account_takeover"]:
            scenarios = self.anomaly_config.get("scenarios", {})
            frequency_minutes = scenarios.get(anomaly_type, {}).get("frequency_minutes", 30)
        else:
            frequency_minutes = 10
        
        if now - last_time >= frequency_minutes * 60:
            self.last_anomaly_time[anomaly_type] = now
            if metrics.auth_anomaly_injections is not None:
                metrics.auth_anomaly_injections.add(
                    1, {"type": anomaly_type}
                )
            return True
        return False
    
    def _get_suspicious_ip(self):
        """Get a suspicious IP from the seeded list."""
        ips = self.anomaly_config.get("suspicious_ips", [])
        if not ips:
            return None
        
        # Weighted selection
        total_weight = sum(ip.get("weight", 1) for ip in ips)
        r = random.uniform(0, total_weight)
        current = 0
        for ip_entry in ips:
            current += ip_entry.get("weight", 1)
            if r <= current:
                return ip_entry["ip"]
        return ips[0]["ip"]
    
    def _get_suspicious_user_agent(self):
        """Get a suspicious user agent from the seeded list."""
        agents = self.anomaly_config.get("suspicious_user_agents", [])
        if not agents:
            return None
        
        # Weighted selection
        total_weight = sum(a.get("weight", 1) for a in agents)
        r = random.uniform(0, total_weight)
        current = 0
        for agent_entry in agents:
            current += agent_entry.get("weight", 1)
            if r <= current:
                return agent_entry["agent"]
        return agents[0]["agent"]
    
    def _generate_auth_event(self):
        """Generate a single authentication event."""
        # Determine if this should be an anomaly
        inject_suspicious_ip = self._should_inject_anomaly("ip")
        inject_suspicious_ua = self._should_inject_anomaly("user_agent")
        
        # Generate base event
        username = self._get_weighted_username()
        
        if inject_suspicious_ip:
            source_ip = self._get_suspicious_ip() or self._generate_random_ip()
        else:
            # 5% chance of IPv6
            if random.random() < 0.05:
                source_ip = self._generate_random_ipv6()
            else:
                source_ip = self._generate_random_ip()
        
        if inject_suspicious_ua:
            user_agent = self._get_suspicious_user_agent() or self._get_random_user_agent()
        else:
            user_agent = self._get_random_user_agent()
        
        # Determine success/failure with time-based variation
        base_success_rate = self.anomaly_config.get("normal_traffic", {}).get("success_rate_percent", 92)
        
        # Apply time-based variation (+/- 5% based on hour of day)
        current_hour = datetime.now().hour
        # Lower success rates during early morning (potential automated attacks)
        # and higher during business hours
        if 2 <= current_hour <= 5:
            hour_modifier = -5
        elif 9 <= current_hour <= 17:
            hour_modifier = 3
        else:
            hour_modifier = 0
        
        adjusted_rate = max(60, min(98, base_success_rate + hour_modifier))
        success_rate = adjusted_rate / 100
        status = "success" if random.random() < success_rate else "failure"

        if metrics.auth_events is not None:
            is_anomaly = "true" if (inject_suspicious_ip or inject_suspicious_ua) else "false"
            metrics.auth_events.add(1, {"status": status, "anomaly": is_anomaly})

        country = self._get_random_country()
        device_type = self._get_device_type(user_agent)
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "vendor": "GoCortex",
            "product": "BrokenBank",
            "event_type": "authentication",
            "username": username,
            "status": status,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "country": country,
            "device_type": device_type,
            "simulated": True
        }
    
    def _run_generator(self):
        """Main generator loop."""
        shipper = get_log_shipper()
        
        # Get rate from config
        endpoint_config = self.logging_config.get("endpoints", {}).get("netbank_auth", {})
        generator_config = endpoint_config.get("generator", {})
        rate_per_minute = generator_config.get("rate_per_minute", 4)
        
        # Validate rate to prevent division by zero
        if rate_per_minute <= 0:
            logging.warning(f"Invalid rate_per_minute ({rate_per_minute}), using default of 4")
            rate_per_minute = 4
        
        interval = 60.0 / rate_per_minute
        
        logging.info(f"Auth traffic generator started: {rate_per_minute} events/minute")
        
        while self.running:
            try:
                event = self._generate_auth_event()
                shipper.ship_log_async("netbank_auth", event)
                logging.debug(f"Generated auth event: {event['username']} - {event['status']}")
            except Exception as e:
                logging.error(f"Error generating auth event: {e}")
            
            time.sleep(interval)
        
        logging.info("Auth traffic generator stopped")
    
    def start(self):
        """Start the background traffic generator."""
        if self.running:
            logging.warning("Auth traffic generator already running")
            return
        
        # Check if generator is enabled
        endpoint_config = self.logging_config.get("endpoints", {}).get("netbank_auth", {})
        generator_config = endpoint_config.get("generator", {})
        
        if not generator_config.get("enabled", False):
            logging.info("Auth traffic generator disabled in config")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_generator, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop the background traffic generator."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
            self.thread = None


# Global generator instance
_generator = None


def get_auth_generator():
    """Get or create the global auth traffic generator."""
    global _generator
    if _generator is None:
        _generator = AuthTrafficGenerator()
    return _generator


def start_auth_generator():
    """Start the background auth traffic generator."""
    generator = get_auth_generator()
    generator.start()


def stop_auth_generator():
    """Stop the background auth traffic generator."""
    generator = get_auth_generator()
    generator.stop()
