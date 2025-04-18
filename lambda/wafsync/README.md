The WAF Sync lambda keeps our AWS WAF synced to our IP addresses DB table.  It should be running roughly every 15m and fetching/updating each env's WAF IP set.  See https://github.com/CMSgov/cdap/tree/main/terraform/services/api-waf-sync for related terraform infrastructure support.

You can run the unit test suite from the base dir (bcda-ssas-app) using the following command:
- `make test-path TEST_PATH="lambda/wafsync/*.go"`.  (You might have to `make load-fixtures` first).  It also has an integration test run via github actions (see .github/workflows/waf-sync-lambda-integration-test.yml).

The lambda is deployed (or promoted in the case of prod) using github actions (see .github/workflows/waf-sync-lambda-{env}-deploy.yml files).

Note: This code is adapted from the DPC project. For reference, see the original implementation here: https://github.com/CMSgov/dpc-app/blob/main/lambda/api-waf-sync
