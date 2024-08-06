#!/bin/bash
#
# This script is intended to be run from within the Docker "tests" container
# The docker compose file brings forward the env vars: DB
#
set -e
set -o pipefail

timestamp=`date +%Y-%m-%d_%H-%M-%S`

echo "Setting up test DB (ssas_test)..."
DB_HOST_URL=${DB}?sslmode=disable
TEST_DB_URL=${DB}/ssas_test?sslmode=disable
echo "DB_HOST_URL is $DB_HOST_URL"
echo "TEST_DB_URL is $TEST_DB_URL"
usql $DB_HOST_URL -c 'drop database if exists ssas_test;'
usql $DB_HOST_URL -c 'create database ssas_test;'

echo "Running SSAS migration tests"

cd db/migrations
DATABASE_URL=$TEST_DB_URL DEBUG=true go test -tags=migrations -v

echo "Cleaning up test DB (ssas_test)..."
usql $DB_HOST_URL -c 'drop database ssas_test;'