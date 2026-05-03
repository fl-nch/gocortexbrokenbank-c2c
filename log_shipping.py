# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# GoCortex Broken Bank - Log Shipping Module
# Version: 1.5.0
#
# This module provides HTTP POST-based log shipping to external SIEM platforms.
# Supports multiple log types: tomcat_access, netbank_application, netbank_auth

import os
import json
import logging
import threading
import time
from datetime import datetime, timezone
from functools import wraps
from queue import Queue, Full

import yaml
import requests
import observability.metrics as metrics

# Suppress SSL warnings for intentionally insecure configuration
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class LogShipper:
    """HTTP POST-based log shipper for SIEM integration."""
    
    # Maximum queue size to prevent unbounded memory growth
    MAX_QUEUE_SIZE = 1000
    
    def __init__(self, config_path="config/logging.yaml"):
        self.config = self._load_config(config_path)
        self.enabled = self.config.get("log_shipping", {}).get("enabled", False)
        self.endpoints = self.config.get("endpoints", {})
        self.retry_config = self.config.get("log_shipping", {}).get("retry", {})
        self.defaults = self.config.get("defaults", {})
        
        # Bounded queue for async log shipping
        self._queue = Queue(maxsize=self.MAX_QUEUE_SIZE)
        self._worker_thread = None
        self._running = False
        
        # Start worker thread if shipping is enabled
        if self.enabled:
            self._start_worker()
        
    def _load_config(self, config_path):
        """Load logging configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                return self._resolve_env_vars(config)
        except FileNotFoundError:
            logging.warning(f"Logging config not found at {config_path}, using defaults")
            return {"log_shipping": {"enabled": False}}
        except Exception as e:
            logging.error(f"Error loading logging config: {e}")
            return {"log_shipping": {"enabled": False}}
    
    def _resolve_env_vars(self, obj):
        """Recursively resolve environment variable placeholders in config."""
        if isinstance(obj, dict):
            return {k: self._resolve_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._resolve_env_vars(item) for item in obj]
        elif isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
            env_var = obj[2:-1]
            return os.environ.get(env_var, "")
        return obj
    
    def _get_auth_headers(self, endpoint_config):
        """Build authentication headers based on endpoint configuration."""
        log_format = endpoint_config.get("format", "json")
        if log_format == "json":
            headers = {"Content-Type": "application/json"}
        else:
            headers = {"Content-Type": "text/plain"}
        
        auth_config = endpoint_config.get("auth", {})
        auth_type = auth_config.get("type", "none")
        
        if auth_type == "header":
            header_name = auth_config.get("header_name", "Authorization")
            header_value = auth_config.get("header_value", "")
            if header_value:
                headers[header_name] = header_value
                
        elif auth_type == "bearer":
            token = auth_config.get("token", "")
            if token:
                headers["Authorization"] = f"Bearer {token}"
                
        elif auth_type == "basic":
            import base64
            username = auth_config.get("username", "")
            password = auth_config.get("password", "")
            if username and password:
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {credentials}"
        
        return headers
    
    def ship_log(self, log_type, log_data):
        """Ship a log entry to the configured endpoint."""
        if not self.enabled:
            return False
            
        endpoint_config = self.endpoints.get(log_type, {})
        if not endpoint_config.get("enabled", False):
            return False
            
        url = endpoint_config.get("url", "")
        if not url:
            # Fall back to defaults if available
            base_url = self.defaults.get("base_url", "")
            path = self.defaults.get("path", "")
            if base_url and path:
                url = base_url.rstrip("/") + "/" + path.lstrip("/")
                logging.debug(f"Using default URL for {log_type}: {url}")
            else:
                logging.debug(f"No URL configured for log type: {log_type}")
                return False
        
        headers = self._get_auth_headers(endpoint_config)
        
        max_attempts = self.retry_config.get("max_attempts", 3)
        backoff = self.retry_config.get("backoff_seconds", 5)
        
        log_format = endpoint_config.get("format", "json")
        
        for attempt in range(max_attempts):
            try:
                if log_format == "json":
                    body = json.dumps(log_data)
                else:
                    body = log_data if isinstance(log_data, str) else str(log_data)
                
                response = requests.post(
                    url,
                    data=body,
                    headers=headers,
                    timeout=10,
                    verify=False
                )
                
                if response.status_code in [200, 201, 202, 204]:
                    logging.debug(f"Log shipped successfully to {log_type}: {response.status_code}")
                    if metrics.log_ship_total is not None:
                        metrics.log_ship_total.add(1, {"log_type": log_type, "result": "success"})
                    return True
                else:
                    logging.warning(f"Log shipping failed for {log_type}: {response.status_code} - {response.text[:200]}")
                    
            except requests.exceptions.RequestException as e:
                logging.warning(f"Log shipping error for {log_type} (attempt {attempt + 1}): {e}")
                
            if attempt < max_attempts - 1:
                time.sleep(backoff)

        if metrics.log_ship_total is not None:
            metrics.log_ship_total.add(1, {"log_type": log_type, "result": "error"})
        return False
    
    def _start_worker(self):
        """Start the background worker thread for processing log queue."""
        if self._worker_thread is not None and self._worker_thread.is_alive():
            return
        
        self._running = True
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()
        logging.info("Log shipping worker thread started")
    
    def _worker_loop(self):
        """Background worker loop that processes logs from the queue."""
        while self._running:
            try:
                # Block with timeout to allow checking _running flag
                log_type, log_data = self._queue.get(timeout=1.0)
                if metrics.log_ship_queue_depth is not None:
                    metrics.log_ship_queue_depth.add(-1, {"log_type": log_type})
                self.ship_log(log_type, log_data)
                self._queue.task_done()
            except Exception:
                # Queue.get timeout or empty queue
                pass
    
    def ship_log_async(self, log_type, log_data):
        """Ship a log entry asynchronously via bounded queue (non-blocking)."""
        if not self.enabled:
            return
        
        try:
            self._queue.put_nowait((log_type, log_data))
            if metrics.log_ship_queue_depth is not None:
                metrics.log_ship_queue_depth.add(1, {"log_type": log_type})
        except Full:
            logging.warning("Log shipping queue full, dropping log entry")


# Global log shipper instance
_log_shipper = None


def get_log_shipper():
    """Get or create the global log shipper instance."""
    global _log_shipper
    if _log_shipper is None:
        _log_shipper = LogShipper()
    return _log_shipper


def log_bbwaf_event(endpoint, vulnerability, payload, request_obj):
    """
    Log a BBWAF (Broken Bank WAF) security event.
    
    This simulates a WAF/security appliance detecting and logging
    exploitation attempts against vulnerable endpoints.
    """
    shipper = get_log_shipper()
    
    log_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "vendor": "GoCortex",
        "product": "BBWAF",
        "event_type": "security_detection",
        "endpoint": endpoint,
        "vulnerability": vulnerability,
        "payload": str(payload)[:1000] if payload else "",
        "source_ip": request_obj.remote_addr or "unknown",
        "user_agent": request_obj.headers.get("User-Agent", "unknown"),
        "request_method": request_obj.method,
        "request_path": request_obj.path,
        "query_string": request_obj.query_string.decode("utf-8", errors="ignore")[:500]
    }
    
    shipper.ship_log_async("netbank_application", log_data)


def log_auth_event(username, status, request_obj, simulated=False):
    """
    Log an authentication event to the netbank_auth stream.
    
    Args:
        username: The username attempting authentication
        status: "success" or "failure"
        request_obj: Flask request object
        simulated: True if this is generated background traffic
    """
    shipper = get_log_shipper()
    
    user_agent = request_obj.headers.get("User-Agent", "unknown") if request_obj else "unknown"
    source_ip = request_obj.remote_addr if request_obj else "unknown"
    
    log_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "vendor": "GoCortex",
        "product": "BrokenBank",
        "event_type": "authentication",
        "username": username,
        "status": status,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "country": _detect_country(source_ip),
        "device_type": _detect_device_type(user_agent),
        "simulated": simulated
    }
    
    shipper.ship_log_async("netbank_auth", log_data)


def log_concierge_event(event_type, request_obj, *, session_id, turn_id,
                        model_name, prompt_text=None, response_text=None,
                        response_path=None, context_document_count=0,
                        context_document_labels=None, document_label=None,
                        source_url=None, body_preview=None, body_length=None):
    """
    Log a Mars Banking Initiative Concierge event to the netbank_concierge stream.

    event_type is one of:
      - "prompt"          : inbound user prompt to /concierge/chat
      - "response"        : Concierge model output for /concierge/chat
      - "context_loaded"  : indirect-injection sink fired (URL or text upload)

    The two chat events share a turn_id so a prompt-injection ruleset in XSIAM
    can correlate the user's payload with the model's leaked output. The
    context_loaded event captures attacker-controlled document text as it
    enters the Concierge context window.
    """
    shipper = get_log_shipper()

    user_agent = request_obj.headers.get("User-Agent", "unknown") if request_obj else "unknown"
    source_ip = request_obj.remote_addr if request_obj else "unknown"
    request_method = request_obj.method if request_obj else "unknown"
    request_path = request_obj.path if request_obj else "unknown"

    log_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "vendor": "GoCortex",
        "product": "Concierge",
        "event_type": event_type,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "request_method": request_method,
        "request_path": request_path,
        "session_id": session_id,
        "turn_id": turn_id,
        "model_name": model_name,
        "context_document_count": context_document_count,
        "context_document_labels": list(context_document_labels or []),
    }

    if prompt_text is not None:
        log_data["prompt_text"] = str(prompt_text)
    if response_text is not None:
        log_data["response_text"] = str(response_text)
    if response_path is not None:
        log_data["response_path"] = response_path
    if document_label is not None:
        log_data["document_label"] = document_label
    if source_url is not None:
        log_data["source_url"] = source_url
    if body_length is not None:
        log_data["body_length"] = body_length
    if body_preview is not None:
        # Cap document preview at the same ~1000 char ceiling BBWAF uses for
        # payloads so a single oversized indirect-injection upload cannot
        # blow out the SIEM record.
        log_data["body_preview"] = str(body_preview)[:1000]

    shipper.ship_log_async("netbank_concierge", log_data)


def _detect_country(ip_address):
    """Simple country detection based on IP patterns (mock implementation)."""
    if not ip_address or ip_address in ["unknown", "127.0.0.1", "::1"]:
        return "AU"
    return "AU"


def _detect_device_type(user_agent):
    """Detect device type from user agent string."""
    if not user_agent:
        return "unknown"
    
    ua_lower = user_agent.lower()
    
    if any(mobile in ua_lower for mobile in ["mobile", "android", "iphone", "ipod"]):
        return "mobile"
    elif any(tablet in ua_lower for tablet in ["ipad", "tablet"]):
        return "tablet"
    else:
        return "desktop"


# Vulnerability type mapping for BBWAF logging
VULNERABILITY_MAPPING = {
    "/search": "SQL_INJECTION",
    "/comment": "CROSS_SITE_SCRIPTING",
    "/ldap": "LDAP_INJECTION",
    "/deserialize": "INSECURE_DESERIALIZATION",
    "/fetch": "SERVER_SIDE_REQUEST_FORGERY",
    "/xml": "XML_EXTERNAL_ENTITY",
    "/redirect": "HTTP_HEADER_INJECTION",
    "/mongo": "NOSQL_INJECTION",
    "/token": "JWT_VERIFICATION_BYPASS",
    "/json": "CODE_INJECTION",
    "/template": "TEMPLATE_INJECTION",
    "/file": "PATH_TRAVERSAL",
    "/wildcard": "PATH_TRAVERSAL",
    "/download": "PATH_TRAVERSAL",
    "/admin": "BROKEN_ACCESS_CONTROL",
    "/hash": "WEAK_CRYPTOGRAPHY",
    "/encrypt": "WEAK_CRYPTOGRAPHY",
    "/ssl_test": "WEAK_TLS_CONFIGURATION",
    "/keyexchange": "UNAUTHENTICATED_KEY_EXCHANGE",
    "/transfer": "CSRF_DISABLED",
    "/credentials": "CLEARTEXT_CREDENTIALS",
    "/debug": "INFORMATION_DISCLOSURE",
    "/log": "LOG_INJECTION",
    "/exception": "IMPROPER_ERROR_HANDLING",
    "/random": "WEAK_RANDOM_GENERATION",
    "/none": "NULL_POINTER_ACCESS",
    "/email": "CLEARTEXT_TRANSMISSION",
    "/ml_model": "INSECURE_MODEL_DOWNLOAD",
    "/pytorch": "INSECURE_MODEL_LOADING",
    "/redis": "UNENCRYPTED_CONNECTION",
    "/html": "IMPROPER_OUTPUT_NEUTRALISATION",
    "/resource": "RESOURCE_EXHAUSTION",
    "/dh_exchange": "WEAK_KEY_EXCHANGE",
    "/config": "CODE_INJECTION",
    "/custom_scheme": "AUTHORISATION_BYPASS",
    "/ldap_anon": "ANONYMOUS_BINDING",
    "/ipmi": "INSECURE_CONFIGURATION",
    "/permissions": "INSECURE_FILE_PERMISSIONS",
    "/tensorflow": "INSECURE_MODEL_SECURITY",
    "/exhaust": "RESOURCE_EXHAUSTION",
    "/database": "HARDCODED_CREDENTIALS"
}


def bbwaf_logging_middleware(app):
    """
    Flask middleware to log exploitation attempts on vulnerable endpoints.
    
    This captures requests to known vulnerable endpoints and logs them
    with BBWAF branding for SIEM ingestion.
    """
    @app.before_request
    def log_vulnerable_endpoint_access():
        from flask import request
        
        path = request.path
        
        if path in VULNERABILITY_MAPPING:
            vulnerability = VULNERABILITY_MAPPING[path]
            
            if request.method == "GET":
                payload = request.query_string.decode("utf-8", errors="ignore")
            elif request.method == "POST":
                payload = request.get_data(as_text=True)[:1000]
            else:
                payload = ""
            
            log_bbwaf_event(path, vulnerability, payload, request)
    
    return app
