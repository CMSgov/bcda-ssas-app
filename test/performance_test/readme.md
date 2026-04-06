# Overview

The directory hosts performance stress testing suite for `bcda-ssas-app` using the native Go `vegeta` library. This standalone go program will accept flags to configure the environment, duration, and frequency.

**Key Flags**:
- `--host`: The API Host (e.g., `localhost:3004` or `ssas.dev.bcda.gov`).
- `--clientID` & `--clientSecret`: The basic credentials to hit SSAS.
- `--freq`: Requests per second (default 10).
- `--duration`: Total test duration in seconds (default 60).
- `--endpoint`: Which endpoint to strike (`token` or `introspect`).
- `--insecure`: Bypasses TLS certificate validation. **Critical for non-prod environments (like dev)** where certificates may be self-signed or non-compliant.

**Execution Logic**:
1. **If testing `/token`**:
   - The script creates a Vegeta targeter sending `POST /token` with the provided Basic Auth credentials in parallel.
2. **If testing `/introspect`**:
   - The script makes exactly *one* raw `http.Client` request to `/token` to fetch a valid `access_token`.
   - Then, it hammers the `POST /introspect` endpoint passing `{ "token": "<access_token>" }` as the JSON payload while maintaining Basic Auth headers.
3. Generates the response plots in `bcda-ssas-app/test_results/performance.html`.

## Usage Examples

Make sure you are in `bcda-ssas-app/test/performance_test`. Then, you can run normal `go run` commands.
Note: you can run `make credentials` from the root directory to generate a client ID and secret.
**Important**: When testing against non-prod environments (like dev) over HTTPS, ensure you include the `-insecure` flag to bypass TLS certificate validation errors.

### Scenario 1: Hitting `/token`
This stress-tests generating token grants via the `POST /token` payload aggressively:

```bash
go run performance.go \
    -host="localhost:3104" \
    -clientID="<YOUR_DEV_CLIENT_ID>" \
    -clientSecret="<YOUR_DEV_CLIENT_SECRET>" \
    -endpoint="token" \
    -duration=60 \
    -freq=15
```

### Scenario 2: Hitting `/introspect`
This fetches one single access token from `/token`, encodes it in JSON, and aggressively spams the `POST /introspect` validation layer:

```bash
go run performance.go \
    -host="non-prod-instance-to-test.elb.amazonaws.com" \
    -clientID="<YOUR_DEV_CLIENT_ID>" \
    -clientSecret="<YOUR_DEV_CLIENT_SECRET>" \
    -endpoint="introspect" \
    -duration=60 \
    -freq=15 \
    -insecure
```

After either suite runs, a performance test artifact (`[endpoint]_api_plot.html`) will automatically appear in `bcda-ssas-app/test_results/performance/`.