lint:
	docker compose -f docker-compose.test.yml run --rm tests golangci-lint --timeout 10m0s -v run --new-from-merge-base=main
	docker compose -f docker-compose.test.yml run --rm tests gosec ./...

# The following vars are available to tests needing SSAS admin credentials; currently they are used in smoke-test-ssas, postman-ssas, and unit-test-ssas
# Note that these variables should only be used for smoke tests, must be set before the api starts, and cannot be changed after the api starts
SSAS_ADMIN_CLIENT_ID ?= 31e029ef-0e97-47f8-873c-0e8b7e7f99bf
SSAS_ADMIN_CLIENT_SECRET := $(shell docker compose run --rm ssas sh -c 'ssas --reset-secret --client-id=$(SSAS_ADMIN_CLIENT_ID)'|tail -n1)

smoke-test:
	docker compose -f docker-compose.test.yml run --rm postman_test test/postman_test/SSAS_Smoke_Test.postman_collection.json -e test/postman_test/local.postman_environment.json --global-var "token=$(token)" --global-var adminClientId=$(SSAS_ADMIN_CLIENT_ID) --global-var adminClientSecret=$(SSAS_ADMIN_CLIENT_SECRET) --global-var ssas_client_assertion_aud=$(SASS_CLIENT_ASSERTION_AUD)

postman:
	docker compose -f docker-compose.test.yml run --rm postman_test test/postman_test/SSAS.postman_collection.json -e test/postman_test/local.postman_environment.json --global-var adminClientId=$(SSAS_ADMIN_CLIENT_ID) --global-var adminClientSecret=$(SSAS_ADMIN_CLIENT_SECRET) --global-var ssas_client_assertion_aud=$(SASS_CLIENT_ASSERTION_AUD)

migrations-test:
	docker compose -f docker-compose.test.yml run --rm tests bash ops/migrations_test.sh

start-db:
	docker compose up -d db

unit-test: start-db
	docker compose -f docker-compose.test.yml run --rm tests bash unit_test.sh

test:
	$(MAKE) lint
	$(MAKE) unit-test
	$(MAKE) postman
	$(MAKE) smoke-test
	$(MAKE) migrations-test

setup-tests:
	# Clean up any existing data to ensure we spin up container in a known state.
	docker compose -f docker-compose.test.yml rm -fsv tests
	docker compose -f docker-compose.test.yml build tests

# make test-path TEST_PATH="bcdaworker/worker/*.go"
test-path: setup-tests
	@docker compose -f docker-compose.test.yml run --rm tests go test -v $(TEST_PATH)

reset-db:
	# Rebuild the databases to ensure that we're starting in a fresh state
	docker compose rm -fsv db

	docker compose up -d db
	./docker/await_service_healthy.sh db

	# Initialize schemas
	docker compose -f docker-compose.migrate.yml run --rm migrate -database "postgres://postgres:toor@db:5432/bcda?sslmode=disable" -path /go/src/github.com/CMSgov/bcda-ssas-app/db/migrations up

load-fixtures:
	$(MAKE) reset-db
	docker compose -f docker-compose.yml run --rm ssas sh -c 'ssas --add-fixture-data'

docker-build:
	docker compose build --force-rm
	docker compose -f docker-compose.test.yml build --force-rm

docker-bootstrap:
	$(MAKE) docker-build
	docker compose up -d
	./docker/await_service_healthy.sh ssas
	$(MAKE) load-fixtures

dbdocs: start-db load-fixtures
	docker run --rm -v $PWD:/work -w /work --network bcda-ssas-app_default ghcr.io/k1low/tbls doc --rm-dist "postgres://postgres:toor@db:5432/bcda?sslmode=disable" dbdocs/bcda

.PHONY: docker-build docker-bootstrap reset-db load-fixtures test release smoke-test postman unit-test lint migrations-test start-db dbdocs

# Build and publish images to ECR
build-ssas:
	$(eval ACCOUNT_ID =$(shell aws sts get-caller-identity --output text --query Account))
	$(eval CURRENT_COMMIT=$(shell git log -n 1 --pretty=format:'%h'))
	$(eval DOCKER_REGISTRY_URL=${ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com/bcda-ssas)
	docker build -t ${DOCKER_REGISTRY_URL}:latest -t '${DOCKER_REGISTRY_URL}:${CURRENT_COMMIT}' -f docker/Dockerfile.ssas .

publish-ssas:
	$(eval ACCOUNT_ID =$(shell aws sts get-caller-identity --output text --query Account))
	$(eval DOCKER_REGISTRY_URL=${ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com/bcda-ssas)
	aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin '${DOCKER_REGISTRY_URL}'
	docker image push ${DOCKER_REGISTRY_URL} -a
