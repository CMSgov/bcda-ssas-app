package:
	# This target should be executed by passing in an argument representing the version of the artifacts we are packaging
	# For example: make package version=r1
	docker-compose run --rm documentation swagger generate spec -i ../../swaggerui/tags.yml -o ../../swaggerui/swagger.json -m
	docker build -t packaging -f Dockerfiles/Dockerfile.package .
	docker run --rm \
	-e BCDA_GPG_RPM_PASSPHRASE='${BCDA_GPG_RPM_PASSPHRASE}' \
	-e GPG_RPM_USER='${GPG_RPM_USER}' \
	-e GPG_RPM_EMAIL='${GPG_RPM_EMAIL}' \
	-e GPG_PUB_KEY_FILE='${GPG_PUB_KEY_FILE}' \
	-e GPG_SEC_KEY_FILE='${GPG_SEC_KEY_FILE}' \
	-v ${PWD}:/go/src/github.com/CMSgov/bcda-ssas-app packaging $(version)

lint:
	docker-compose -f docker-compose.test.yml run --rm tests golangci-lint -e SA1029 -v run ./...
	docker-compose -f docker-compose.test.yml run --rm tests gosec ./...

# The following vars are available to tests needing SSAS admin credentials; currently they are used in smoke-test-ssas, postman-ssas, and unit-test-ssas
# Note that these variables should only be used for smoke tests, must be set before the api starts, and cannot be changed after the api starts
SSAS_ADMIN_CLIENT_ID ?= 31e029ef-0e97-47f8-873c-0e8b7e7f99bf
SSAS_ADMIN_CLIENT_SECRET := $(shell docker-compose run --rm ssas sh -c 'ssas --reset-secret --client-id=$(SSAS_ADMIN_CLIENT_ID)'|tail -n1)

smoke-test:
	docker-compose -f docker-compose.test.yml run --rm postman_test test/postman_test/SSAS_Smoke_Test.postman_collection.json -e test/postman_test/local.postman_environment.json --global-var "token=$(token)" --global-var adminClientId=$(SSAS_ADMIN_CLIENT_ID) --global-var adminClientSecret=$(SSAS_ADMIN_CLIENT_SECRET) --global-var ssas_client_assertion_aud=$(SASS_CLIENT_ASSERTION_AUD)

postman:
	docker-compose -f docker-compose.test.yml run --rm postman_test test/postman_test/SSAS.postman_collection.json -e test/postman_test/local.postman_environment.json --global-var adminClientId=$(SSAS_ADMIN_CLIENT_ID) --global-var adminClientSecret=$(SSAS_ADMIN_CLIENT_SECRET) --global-var ssas_client_assertion_aud=$(SASS_CLIENT_ASSERTION_AUD)

migrations-test:
	docker-compose -f docker-compose.test.yml run --rm tests bash ops/migrations_test.sh

unit-test:
	docker-compose up -d db
	docker-compose -f docker-compose.test.yml run --rm tests bash unit_test.sh

test:
	$(MAKE) lint
	$(MAKE) unit-test
	$(MAKE) postman
	$(MAKE) smoke-test
	$(MAKE) migrations-test

load-fixtures:
	docker-compose -f docker-compose.migrate.yml run --rm migrate  -database "postgres://postgres:toor@db:5432/bcda?sslmode=disable" -path /go/src/github.com/CMSgov/bcda-ssas-app/db/migrations up
	docker-compose -f docker-compose.yml run ssas sh -c 'ssas --add-fixture-data'

docker-build:
	docker-compose build --force-rm
	docker-compose -f docker-compose.test.yml build --force-rm

docker-bootstrap:
	$(MAKE) docker-build
	docker-compose up -d
	sleep 40
	$(MAKE) load-fixtures

.PHONY: docker-build docker-bootstrap load-fixtures test package release smoke-test postman unit-test lint migrations-test
