#!/bin/bash
# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# GoCortex Broken Bank Deployment Script
# Intentionally vulnerable banking application for CI/CD security testing

# Extract version from pyproject.toml
VERSION=$(grep '^version = ' pyproject.toml | sed 's/version = "\(.*\)"/\1/')

echo "Starting GoCortex Broken Bank v${VERSION} deployment..."

# Check if Docker is installed (using whereis for non-standard locations)
if ! command -v docker &> /dev/null && [ -z "$(whereis docker | cut -d: -f2)" ]; then
    echo "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is available (using whereis for non-standard locations)
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null && [ -z "$(whereis docker-compose | cut -d: -f2)" ]; then
    echo "Docker Compose is not available. Please install Docker Compose."
    exit 1
fi

# Stop any existing containers
echo "Stopping existing containers..."
docker-compose down 2>/dev/null || docker compose down 2>/dev/null || true

# Build and start the application
echo "Building and starting GoCortex Broken Bank..."
if command -v docker-compose &> /dev/null; then
    docker-compose up --build -d
else
    docker compose up --build -d
fi

# Wait for applications to start
echo "Waiting for applications to start..."
sleep 15

# Check if both servers are running
FLASK_STATUS=0
TOMCAT_STATUS=0

if curl -f http://localhost:8888 >/dev/null 2>&1; then
    FLASK_STATUS=1
    echo "Flask/Gunicorn server running successfully on port 8888"
else
    echo "WARNING: Flask/Gunicorn server failed to start on port 8888"
fi

if curl -f http://localhost:9999 >/dev/null 2>&1; then
    TOMCAT_STATUS=1
    echo "Tomcat server running successfully on port 9999"
else
    echo "WARNING: Tomcat server failed to start on port 9999"
fi

REACT_STATUS=0

if curl -f http://localhost:7777 >/dev/null 2>&1; then
    REACT_STATUS=1
    echo "React/Next.js server running successfully on port 7777"
else
    echo "WARNING: React/Next.js server failed to start on port 7777"
fi

if [ $FLASK_STATUS -eq 1 ] && [ $TOMCAT_STATUS -eq 1 ] && [ $REACT_STATUS -eq 1 ]; then
    echo ""
    echo "GoCortex Broken Bank tri-server deployment successful!"
    echo "Container Status:"
    docker ps --filter "name=gocortex-broken-bank"
elif [ $FLASK_STATUS -eq 1 ] || [ $TOMCAT_STATUS -eq 1 ] || [ $REACT_STATUS -eq 1 ]; then
    echo ""
    echo "Partial deployment - one server failed. Checking logs..."
    docker-compose logs || docker compose logs
    echo ""
    echo "You can continue with the running server, or troubleshoot the failed one."
else
    echo ""
    echo "Both servers failed to start. Checking logs..."
    docker-compose logs || docker compose logs
    exit 1
fi

echo ""
echo "Deployment Complete!"
echo "Application: GoCortex Broken Bank v${VERSION}"
echo "Purpose: CI/CD Security Testing & Educational Use"
echo ""
echo "Access URLs:"
echo "  Flask/Gunicorn (SAST Testing): http://localhost:8888"
echo "  Tomcat/Java (Exploit Endpoints): http://localhost:9999/exploit-app/"
echo "  SpaceATM Terminal (React/Next.js): http://localhost:7777"
echo "  OTel Metrics Scrape (Prometheus): http://localhost:9464/metrics"
echo "  Security Disclaimer: http://localhost:8888/disclaimer"
echo ""
echo "Container Management:"
echo "  Stop: docker-compose down"
echo "  Logs: docker-compose logs -f"
echo "  Shell: docker exec -it gocortex-broken-bank bash"
echo ""
echo "Security Testing Features:"
echo "  • 55+ vulnerable endpoints across tri-server architecture"
echo "  • 75+ hardcoded secrets for detection testing"
echo "  • Flask server (port 8888): SAST vulnerabilities, secrets, license compliance"
echo "  • Tomcat server (port 9999): RCE exploits, Spring4Shell CVE-2022-22965"
echo "  • React/Next.js server (port 7777): CVE-2025-55182 React2Shell RCE, CVE-2025-66478"
echo "  • Insecure Docker configuration for container scanning"
echo "  • Comprehensive OWASP Top 10 vulnerability coverage"