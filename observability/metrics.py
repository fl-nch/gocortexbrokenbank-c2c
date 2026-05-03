# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# GoCortex Broken Bank - OTel Poll-Based Metrics
# Version: 1.5.0
#
# Exposes a Prometheus scrape endpoint on port 9464 (OTel default).
# No tracing. No push exporters. Collector polls this endpoint.

import logging

import prometheus_client
from opentelemetry.exporter.prometheus import PrometheusMetricReader
from opentelemetry.sdk.metrics import MeterProvider

_initialized = False

# Instrument handles - imported by instrumented modules
auth_events = None
auth_anomaly_injections = None
http_requests = None
http_request_duration = None
log_ship_total = None
log_ship_queue_depth = None


def init_metrics(port=9464):
    """
    Initialise the OTel MeterProvider and start the Prometheus HTTP server.

    Safe to call multiple times - subsequent calls are no-ops. Must be called
    once at application startup before any instrumented code runs.
    """
    global _initialized
    global auth_events, auth_anomaly_injections
    global http_requests, http_request_duration
    global log_ship_total, log_ship_queue_depth

    if _initialized:
        return

    reader = PrometheusMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    meter = provider.get_meter("brokenbank", "1.5.0")

    # Auth traffic generator counters
    auth_events = meter.create_counter(
        name="brokenbank_auth_events_total",
        description="Authentication events by outcome and anomaly flag",
        unit="1",
    )

    auth_anomaly_injections = meter.create_counter(
        name="brokenbank_auth_anomaly_injections_total",
        description="Seeded anomaly injections by type",
        unit="1",
    )

    # Flask HTTP layer
    http_requests = meter.create_counter(
        name="brokenbank_http_requests_total",
        description="HTTP requests by method, endpoint, and status code",
        unit="1",
    )

    http_request_duration = meter.create_histogram(
        name="brokenbank_http_request_duration_seconds",
        description="HTTP request duration in seconds",
        unit="s",
    )

    # Log shipping pipeline
    log_ship_total = meter.create_counter(
        name="brokenbank_log_ship_total",
        description="Log shipping attempts by log type and result",
        unit="1",
    )

    log_ship_queue_depth = meter.create_up_down_counter(
        name="brokenbank_log_ship_queue_depth",
        description="Current log shipping queue depth across all log types",
        unit="1",
    )

    # Start the Prometheus scrape endpoint on the dedicated port.
    # Using SO_REUSEADDR so the port is reclaimed immediately on gunicorn
    # --reload worker restarts without a bind error.
    try:
        prometheus_client.start_http_server(port)
        logging.info("OTel metrics scrape endpoint listening on port %d", port)
    except OSError as exc:
        logging.warning(
            "Could not start metrics server on port %d: %s", port, exc
        )

    _initialized = True
