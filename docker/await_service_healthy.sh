#!/bin/bash
#
# This script provides a simple way to wait for a docker service to be healthy
# It is intended to be called from the Makefile to facilitate easier docker command orchestration
#

SERVICE=$1
TIMEOUT=$2
INTERVAL=2

if [ -z "$SERVICE" ]; then
    echo "Usage: $0 <service> [timeout_seconds]"
    exit 1
fi

# Set timeout with a default of 60 seconds if not provided
if [ -z "$TIMEOUT" ]; then
    TIMEOUT=60
fi

echo "Waiting for service '$SERVICE' to be healthy (timeout: ${TIMEOUT}s)..."

start_time=$(date +%s)
while true; do
    current_time=$(date +%s)
    elapsed_time=$((current_time - start_time))

    if [ $elapsed_time -ge $TIMEOUT ]; then
        echo "Timeout reached. Service '$SERVICE' did not become healthy within $TIMEOUT seconds."
        echo "Current status:"
        docker inspect -f '{{.State.Health.Status}}' $(docker compose ps -q "$SERVICE")
        exit 1
    fi

    # Get the health status using docker inspect
    HEALTH_STATUS=$(docker inspect -f '{{.State.Health.Status}}' $(docker compose ps -q "$SERVICE") 2>/dev/null)

    if [ "$HEALTH_STATUS" == "healthy" ]; then
        echo "Service '$SERVICE' is healthy."
        exit 0
    elif [ "$HEALTH_STATUS" == "unhealthy" ]; then
        echo "Service '$SERVICE' is unhealthy. Exiting."
        exit 1
    elif [ "$HEALTH_STATUS" == "starting" ]; then
        echo "Service '$SERVICE' is starting, waiting..."
    elif [ "$HEALTH_STATUS" == "" ]; then
        # Handle cases where service name might be wrong or no healthcheck configured
        echo "Could not get health status for '$SERVICE'. Check if name is correct and healthcheck is configured."
        exit 1
    fi

    sleep $INTERVAL
done