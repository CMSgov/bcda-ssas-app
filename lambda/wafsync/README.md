Get short-term AWS credentials through CloudTamer:
You can run from the base dir (bcda-ssas-app) using the following command:
- `make test-path TEST_PATH="lambda/wafsync/*.go"`.  (You might have to `make load-fixtures` first).
- If not available in your quick access dashboard, you can find these credentials in CloudTamer by:
  1. Selecting your project
  2. Navigating to Cloud Management > Cloud Access Roles
  3. Choosing the relevant application role
  4. Selecting the IAM role
  5. Clicking on "Short-Term Access Keys"
> **⚠️ Caution:** The test updates the live IP address set `bcda-test-api-customers`. If it fails midway (unlikely), it's possible that the IP set has been altered and not reset to the original set, so watch for that.

Note: This code is adapted from the DPC project. For reference, see the original implementation here: https://github.com/CMSgov/dpc-app/blob/main/lambda/api-waf-sync
