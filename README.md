# System-to-System Authentication Service (SSAS)

The SSAS can be run as a standalone web service or embedded as a library.

# Code Organization

The outline below shows the physical directory structure of the code, with package names highlighted. The service package contains a standalone http service that presents the authorization library via two http servers, one for admin tasks and one for authorization tasks.

Imports always go up the directory tree from leaves; that is, parents do not import from their children. Children may import from their siblings. In short, the `ssas` and `cfg` packages must not import from packages in the service directory.

- **ssas**
  - **cfg**
    - _configuration management; cfg should not import from ssas packages_
  - **service**
    - **admin**
      - _contains the REST API for managing the service implementation_
    - **main**
      - _cli for running servers and some admin tasks_
    - **public**
      - _contains the rest API for authorization services_

# Configuration

Values below are either indicated by Required, SSAS, BCDA, or a combination.

- Required values must be present in the docker compose.\*.yml files.
- Some values are primarily for the use of the BCDA API, and are only used by SSAS for testing purposes.
- Some values are only used by the BCDA API; they are listed for reference.

Very long keys have been split across two rows for formatting purposes.

Some variables below have a note indicating their name should be changed. These changes serve to make the names consistent with established naming patterns and/or to clarify their purpose. They should be made after we complete the initial deployments to AWS envs so that we don't have to change all of our existing deployment checklists in a short timeframe.

| Key                                                                  | Required | SSAS | BCDA | Purpose                                                                                                                                                                                                                                                                                    |
| -------------------------------------------------------------------- | :------: | :--: | :--: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| BCDA_AUTH_PROVIDER                                                   |   Yes    |      |  X   | Tells BCDA API which auth provider to use                                                                                                                                                                                                                                                  |
| BCDA_CA_FILE                                                         |   Yes    |      |  X   | Tells BCDA API the certificate file with which to validate its TLS connection to SSAS. When setting vars for AWS envs, you must include a var for the key material                                                                                                                         |
| BCDA_SSAS_CLIENT_ID                                                  |   Yes    |      |  X   | Tells BCDA API the client_id to use with the SSAS REST API.                                                                                                                                                                                                                                |
| BCDA_SSAS_SECRET                                                     |   Yes    |      |  X   | Tells BCDA API the secret to use with the SSAS REST API.                                                                                                                                                                                                                                   |
| SSAS_USE_TLS                                                         |   Yes    |      |  X   | Should be renamed to BCDA_SSAS_USE_TLS                                                                                                                                                                                                                                                     |
| SSAS_URL                                                             |   Yes    |      |  X   | The url of the SSAS admin server. Should be renamed to BCDA_SSAS_URL                                                                                                                                                                                                                       |
| SSAS_PUBLIC_URL                                                      |   Yes    |      |  X   | The url of the SSAS public server (auth endpoints). Should be renamed to BCDA_SSAS_URL_PUBLIC                                                                                                                                                                                              |
| DATABASE_URL                                                         |   Yes    |  X   |      | Provides the database url                                                                                                                                                                                                                                                                  |
| DEBUG                                                                | Depends  |  X   |      | Flag to indicate that the system is running in a development environments. Generally not used outside of docker.                                                                                                                                                                           |
| HTTP_ONLY                                                            | Depends  |  X   |      | Flag to operation of the system. By default, the servers will use https. When HTTP_ONLY is present **and** set to true, they will use http. Generally not used outside of docker.                                                                                                          |
| SSAS_DEFAULT_SYSTEM_SCOPE                                            |   Yes    |  X   |      | Used to set the scope on systems that do not specify their scope. Must be set or runtime failures will occur.                                                                                                                                                                              |
| SSAS_HASH_ITERATIONS                                                 |   Yes    |  X   |      | Controls how many iterations our secure hashing mechanism performs. Service will panic if this key does not have a value.                                                                                                                                                                  |
| SSAS_HASH_KEY_LENGTH                                                 |   Yes    |  X   |      | Controls the key length used by our secure hashing mechanism. Service will panic if this key does not have a value.                                                                                                                                                                        |
| SSAS_HASH_SALT_SIZE                                                  |   Yes    |  X   |      | Controls salt size used by our secure hashing mechanism performs. Service will panic if this key does not have a value.                                                                                                                                                                    |
| SSAS*MFA_CHALLENGE* <br/> REQUEST_MILLISECONDS                       |    No    |  X   |      | Minimum execution time for RequestFactorChallenge(). If not present, defaults to 1500. In production, this should always be set longer than the longest expected execution time. (Actual execution time is logged.)                                                                        |
| SSAS*MFA_TOKEN* <br/> TIMEOUT_MINUTES                                |    No    |  X   |      | Token lifetime for self-registration (MFA tokens and Registration tokens). Defaults to 60 (minutes).                                                                                                                                                                                       |
| SSAS_READ_TIMEOUT                                                    |    No    |  X   |      | Sets the read timeout on server requests                                                                                                                                                                                                                                                   |
| SSAS_WRITE_TIMEOUT                                                   |    No    |  X   |      | Sets the write timeout on server responses                                                                                                                                                                                                                                                 |
| SSAS_IDLE_TIMEOUT                                                    |    No    |  X   |      | Sets how long the server will keep idle connections open                                                                                                                                                                                                                                   |
| SSAS_LOG                                                             |    No    |  X   |      | Directs all ssas logging to a named file                                                                                                                                                                                                                                                   |
| SSAS_ADMIN_PORT <br/> SSAS_PUBLIC_PORT <br/> SSAS_HTTP_TO_HTTPS_PORT |    No    |  X   |  X   | These values are not yet used by code. Intended to allow changing port assignments. If used, will affect BCDA SSAS URL vars.                                                                                                                                                               |
| SSAS_ADMIN_SIGNING_KEY <br/>or<br/> SSAS_ADMIN_SIGNING_KEY_PATH      |   Yes    |  X   |      | Provides the plaintext/path of the admin server signing key. When setting vars for AWS envs, you must include a var for the key material. Set either the key or the path but not both.                                                                                                     |
| SSAS_PUBLIC_SIGNING_KEY <br/>or <br/>SSAS_PUBLIC_SIGNING_KEY_PATH    |   Yes    |  X   |      | Provides the plaintext/path of the public server signing key. When setting vars for AWS envs, you must include a var for the key material. Set either the key or the path but not both.                                                                                                    |
| SSAS*TOKEN_BLACKLIST_CACHE* <br/> CLEANUP_MINUTES                    |    No    |  X   |      | Tunes the frequency that expired entries are cleared from the token blacklist cache. Defaults to 15 minutes.                                                                                                                                                                               |
| SSAS*TOKEN_BLACKLIST_CACHE* <br/> TIMEOUT_MINUTES                    |    No    |  X   |      | Sets the lifetime of token blacklist cache entries. Defaults to 24 hours.                                                                                                                                                                                                                  |
| SSAS*TOKEN_BLACKLIST_CACHE* <br/> REFRESH_MINUTES                    |    No    |  X   |      | Configures the number of minutes between times the token blacklist cache is refreshed from the database.                                                                                                                                                                                   |
| BCDA_TLS_CERT                                                        | Depends  |  X   |      | The cert used when the SSAS service is running in secure mode. When setting vars for AWS envs, you must include a var for the cert material. This var should be renamed to SSAS_TLS_CERT.                                                                                                  |
| BCDA_TLS_KEY                                                         | Depends  |  X   |      | The private key used when the SSAS service is running in secure mode. When setting vars for AWS envs, you must include a var for the key material. This var should be renamed to SSAS_TLS_KEY.                                                                                             |
| SSAS_CLIENT_ASSERTION_AUD                                            |   Yes    |  X   |      | The audience (aud) claim value required when authenticating using client assertion tokens (v2/token).                                                                                                                                                                                      |
| SSAS_CRED_TIMEOUT_DAYS                                               |    No    |  X   |      | Setting for timeout of SSAS Credentials. Utilized in CLI command —list-exp-creds to show credentials that shows credentials about to timeout or expire. Defaults to 60 days.                                                                                                               |
| SSAS_CRED_EXPIRATION_DAYS                                            |    No    |  X   |      | Setting for expiration of SSAS Credentials. Utilized in (1) setting ExpiresAt value during inital token creation, (2) app logic checks to see if a presented token is expired, and (3) in CLI command —list-exp-creds to show credentials about to timeout or expire. Defaults to 90 days. |
| SSAS_CRED_WARNING_DAYS                                               |    No    |  X   |      | Setting for warning of SSAS Credentials. Utilized in CLI command —list-exp-creds to show credentials about to timeout or expire. Defaults to 7 days.                                                                                                                                       |

# Development Setup

## Install and Use Pre-commit

Anyone committing to this repo must use the pre-commit hook to lower the likelihood that secrets will be exposed.

### Step 1: Install pre-commit

You can install pre-commit using the MacOS package manager Homebrew:

```sh
brew install pre-commit
```

Other installation options can be found in the [pre-commit documentation](https://pre-commit.com/#install).

### Step 2: Install the hooks

You will need to manually install `goimports` for the following commands to function:

```
go install golang.org/x/tools/cmd/goimports@latest
```

Run the following command to install the hook:

```sh
pre-commit install
```

This will download and install the pre-commit hooks specified in `.pre-commit-config.yaml`, which includes gitleaks for secret scanning and go-imports to ensure that any added, copied, or modified go files are formatted properly.

## Go Modules

The project uses [Go Modules](https://golang.org/ref/mod) allowing you to clone the repo outside of the `$GOPATH`. This also means that running `go get` inside the repo will add the dependency to the project, not globally.

# Build

Build all the code and containers with `make docker-bootstrap`. Alternatively, `docker compose up ssas` will build and run the SSAS by itself. Note that SSAS needs the db container to be running as well.

## Bootstrapping CLI

SSAS currently has a simple CLI intended to make bootstrapping tasks and manual testing easier to accomplish. The CLI will only run one command at a time; commands do not chain.

The sequence of commands needed to bootstrap the SSAS into a new environment is as follows:

1. migrate, which will build or update the tables
1. add-fixture-data, which adds the admin group and seeds minimal data for smoke Testing
1. new-admin-system, which adds an admin system and returns its client_id
1. reset-secret, which replaces the secret associated with a client_id and returns that new secret
1. start, which starts the servers and the token blacklist cache

You will need the admin client_id and secret to use the service's admin endpoints.

Note that to initialize our docker container, we use migrate-and-start, which combines the first three of the steps above with some conditional logic to make sure we're running in a development environment. This command should most likely not be used elsewhere.

# Test

The SSAS can be tested by running `make unit-test`. You can also use the repo-wide command `make test`, which will run tests against the entire repo, including the SSAS code. Some tests are designed to be only run as needed, and are excluded from `make` by a build tag. To include
one of these test suites, follow the instructions at the top of the test file.

### **Running Single / Single-file Unit Tests**

This step assumes that the user has installed VSCode, the Go language extension available [here](https://marketplace.visualstudio.com/items?itemName=golang.Go), and has successfully imported test data to their local database.

To run tests from within VSCode:
In a FILENAME_test.go file, there will be a green arrow to the left of the method name, and clicking this arrow will run a single test locally. Tests should not be dependent upon other tests, but if a known-good test is failing, the user can run all tests in a given file by going to View -> Command Palette -> Go: Test Package, which will run all tests in a given file. Alternatively, in some instances, the init() method can be commented out to enable testing of single functions.

# Integration Testing

To run postman tests locally:

Build and startup the required containers. Building with docker compose up first will significantly improve the performance of the following steps.

```
docker compose up
docker compose stop
docker compose up -d db
docker compose up ssas
```

If this is the first time you've started the containers, set up your database tables and seed them with sample group and systems:

```
make load-fixtures
```

point your browser at one of the following ports, or use the postman test collection in tests.

- public server: 3103
- admin server: 3104
- forwarding server: 3105

# Goland IDE

To run a test suite inside of Goland IDE, edit its configuration from the `Run` menu and add values for all necessary
environmental variables. It is also possible to run individual tests, but that may require configurations for each test.

# Docker Fun

To get postgres dump of schema (replace PASSHERE with password)

```
docker run --rm --network bcda-ssas-app_default -e PGPASSWORD=PASSHERE -it postgres pg_dump -s -h bcda-ssas-app_db_1 -d bcda -U postgres > schema.sql
```

To reset a secret by client id (can be found in Makefile):

```
docker compose run --rm ssas sh -c 'ssas --reset-secret --client-id=[client_id]'
```

To list all active IPs from the connected database:

```
docker compose run --rm ssas sh -c 'ssas --list-ips'
```

# Swagger Documentation

The admin server has Swagger documentation. To access:

1. Make sure it's been built (the container will stop after a few seconds when the documentation is ready)

   `docker compose up documentation`

1. Make sure the `ssas` container is running

   `docker compose up ssas`

1. Access Swagger in your browser:
   http://localhost:3104/swagger
