# Overview

The directory hosts performance stress testing suite for `bcda-ssas-app` using the native Go `vegeta` library. This standalone go program will accept flags to configure the environment, duration, and frequency.

**Key Flags**:
- `--host`: The API Host (e.g., `localhost:3004` or `ssas.dev.bcda.gov`).
- `--clientID` & `--clientSecret`: The basic credentials to hit SSAS.
- `--freq`: Requests per second (default 10).
- `--duration`: Total test duration in seconds (default 60).
- `--endpoint`: Which endpoint to strike (`token` or `introspect`).

**Execution Logic**:
1. **If testing `/token`**:
   - The script creates a Vegeta targeter sending `POST /token` with the provided Basic Auth credentials in parallel.
2. **If testing `/introspect`**:
   - The script makes exactly *one* raw `http.Client` request to `/token` to fetch a valid `access_token`.
   - Then, it hammers the `POST /introspect` endpoint passing `{ "token": "<access_token>" }` as the JSON payload while maintaining Basic Auth headers.
3. Generates the response plots in `bcda-ssas-app/test_results/performance.html`.

