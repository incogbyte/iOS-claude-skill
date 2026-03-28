#!/usr/bin/env bash
# deep-secret-scan.sh — Deep scan for cloud credentials, API keys, and secrets in extracted iOS app
set -euo pipefail

usage() {
  cat <<EOF
Usage: deep-secret-scan.sh <analysis-dir> [OPTIONS]

Deep scan extracted iOS app output for cloud provider credentials, API keys,
and other secrets. Produces structured output suitable for LLM analysis.

Arguments:
  <analysis-dir>    Path to the analysis output directory (from extract-ipa.sh)

Options:
  --firebase        Search only for Firebase/Google credentials
  --aws             Search only for AWS credentials
  --azure           Search only for Azure credentials
  --gcp             Search only for GCP credentials
  --payments        Search only for payment provider keys (Stripe, etc.)
  --messaging       Search only for messaging/push keys (Twilio, OneSignal, etc.)
  --analytics       Search only for analytics keys (Mixpanel, Amplitude, Sentry, etc.)
  --jwt             Search only for JWT tokens
  --all             Search all patterns (default)
  --report FILE     Export results as structured Markdown report
  --json            Output results in JSON format for programmatic use
  --severity LEVEL  Minimum severity to report: critical, high, medium, low, info (default: low)
  -h, --help        Show this help message

Output:
  Structured findings with service, credential type, severity, and location.
  Designed for LLM analysis to classify and assess risk of each finding.
EOF
  exit 0
}

ANALYSIS_DIR=""
SEARCH_FIREBASE=false
SEARCH_AWS=false
SEARCH_AZURE=false
SEARCH_GCP=false
SEARCH_PAYMENTS=false
SEARCH_MESSAGING=false
SEARCH_ANALYTICS=false
SEARCH_JWT=false
SEARCH_ALL=true
REPORT_FILE=""
JSON_OUTPUT=false
MIN_SEVERITY="low"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --firebase)    SEARCH_FIREBASE=true;    SEARCH_ALL=false; shift ;;
    --aws)         SEARCH_AWS=true;         SEARCH_ALL=false; shift ;;
    --azure)       SEARCH_AZURE=true;       SEARCH_ALL=false; shift ;;
    --gcp)         SEARCH_GCP=true;         SEARCH_ALL=false; shift ;;
    --payments)    SEARCH_PAYMENTS=true;    SEARCH_ALL=false; shift ;;
    --messaging)   SEARCH_MESSAGING=true;   SEARCH_ALL=false; shift ;;
    --analytics)   SEARCH_ANALYTICS=true;   SEARCH_ALL=false; shift ;;
    --jwt)         SEARCH_JWT=true;         SEARCH_ALL=false; shift ;;
    --all)         SEARCH_ALL=true; shift ;;
    --report)      REPORT_FILE="$2"; shift 2 ;;
    --json)        JSON_OUTPUT=true; shift ;;
    --severity)    MIN_SEVERITY="$2"; shift 2 ;;
    -h|--help)     usage ;;
    -*)            echo "Error: Unknown option $1" >&2; usage ;;
    *)             ANALYSIS_DIR="$1"; shift ;;
  esac
done

if [[ -z "$ANALYSIS_DIR" ]]; then
  echo "Error: No analysis directory specified." >&2
  usage
fi

if [[ ! -d "$ANALYSIS_DIR" ]]; then
  echo "Error: Directory not found: $ANALYSIS_DIR" >&2
  exit 1
fi

GREP_OPTS="-rn --include=*.h --include=*.m --include=*.swift --include=*.txt --include=*.plist --include=*.json --include=*.c"

# Counters
TOTAL_FINDINGS=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0

REPORT_CONTENT=""
JSON_FINDINGS="[]"

# --- Severity filter ---
severity_passes() {
  local sev="$1"
  case "$MIN_SEVERITY" in
    info)     return 0 ;;
    low)
      case "$sev" in info) return 1 ;; *) return 0 ;; esac ;;
    medium)
      case "$sev" in info|low) return 1 ;; *) return 0 ;; esac ;;
    high)
      case "$sev" in info|low|medium) return 1 ;; *) return 0 ;; esac ;;
    critical)
      case "$sev" in critical) return 0 ;; *) return 1 ;; esac ;;
  esac
}

# --- Output helpers ---
finding() {
  local service="$1" cred_type="$2" severity="$3" pattern_name="$4"

  if ! severity_passes "$severity"; then
    return
  fi

  local results=""
  shift 4
  local case_flag=""
  if [[ "$1" == "-i" ]]; then
    case_flag="-i"
    shift
  fi
  local pattern="$1"

  # shellcheck disable=SC2086
  results=$(grep $GREP_OPTS $case_flag -E "$pattern" "$ANALYSIS_DIR" 2>/dev/null || true)

  if [[ -z "$results" ]]; then
    return
  fi

  local count
  count=$(echo "$results" | grep -c '' || true)
  TOTAL_FINDINGS=$((TOTAL_FINDINGS + count))

  case "$severity" in
    critical) CRITICAL_COUNT=$((CRITICAL_COUNT + count)) ;;
    high)     HIGH_COUNT=$((HIGH_COUNT + count)) ;;
    medium)   MEDIUM_COUNT=$((MEDIUM_COUNT + count)) ;;
    low)      LOW_COUNT=$((LOW_COUNT + count)) ;;
    info)     INFO_COUNT=$((INFO_COUNT + count)) ;;
  esac

  local sev_icon=""
  case "$severity" in
    critical) sev_icon="CRITICAL" ;;
    high)     sev_icon="HIGH" ;;
    medium)   sev_icon="MEDIUM" ;;
    low)      sev_icon="LOW" ;;
    info)     sev_icon="INFO" ;;
  esac

  echo
  echo "[$sev_icon] $service — $cred_type ($pattern_name)"
  echo "  Matches: $count"
  echo "$results" | head -20
  if [[ "$count" -gt 20 ]]; then
    echo "  ... and $((count - 20)) more matches"
  fi

  if [[ -n "$REPORT_FILE" ]]; then
    REPORT_CONTENT+=$'\n'"### [$sev_icon] $service — $cred_type"$'\n\n'
    REPORT_CONTENT+="- **Pattern**: \`$pattern_name\`"$'\n'
    REPORT_CONTENT+="- **Matches**: $count"$'\n\n'
    REPORT_CONTENT+='```'$'\n'"$(echo "$results" | head -30)"$'\n''```'$'\n\n'
  fi
}

echo "=== Deep Secret Scan: $ANALYSIS_DIR ==="
echo "Minimum severity: $MIN_SEVERITY"
echo

# =====================================================================
# Firebase / Google
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_FIREBASE" == true ]]; then
  echo "--- Scanning for Firebase / Google credentials ---"

  finding "Firebase" "API Key" "medium" "firebase-api-key" \
    'GOOGLE_APP_ID\|GCM_SENDER_ID\|FIREBASE_URL\|API_KEY.*AIza\|REVERSED_CLIENT_ID\|PLIST_VERSION'

  finding "Firebase" "Database URL" "high" "firebase-db-url" \
    'firebaseio\.com\|firebaseapp\.com'

  finding "Firebase" "Storage Bucket" "high" "firebase-storage" \
    'STORAGE_BUCKET\|firebasestorage\.googleapis\.com\|\.appspot\.com'

  finding "Firebase" "Cloud Messaging" "low" "firebase-fcm" \
    'GCM_SENDER_ID\|fcm\.googleapis\.com\|FIRMessaging'

  finding "Firebase" "GoogleService-Info" "medium" "firebase-plist" \
    -i 'GoogleService-Info\|GOOGLE_APP_ID\|BUNDLE_ID.*com\.'

  finding "Firebase" "SDK Usage" "info" "firebase-sdk" \
    'FIRApp\|FirebaseApp\|FIRAuth\|FIRDatabase\|FIRFirestore\|FIRStorage\|FIRCrashlytics\|FIRRemoteConfig\|FIRAnalytics'

  finding "Firebase" "Dynamic Links" "low" "firebase-dynamic-links" \
    'page\.link\|app\.goo\.gl\|FIRDynamicLink'
fi

# =====================================================================
# Google Cloud Platform
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_GCP" == true ]]; then
  echo "--- Scanning for GCP credentials ---"

  finding "GCP" "API Key" "high" "gcp-api-key" \
    'AIza[0-9A-Za-z_-]\{35\}'

  finding "GCP" "Service Account" "critical" "gcp-service-account" \
    -i '"type".*service_account\|client_email.*gserviceaccount\.com\|private_key_id'

  finding "GCP" "OAuth Client ID" "medium" "gcp-oauth-client" \
    '[0-9]\{12\}-[a-z0-9]\{32\}\.apps\.googleusercontent\.com'

  finding "GCP" "API Endpoints" "info" "gcp-endpoints" \
    'googleapis\.com\|storage\.cloud\.google\.com'

  finding "Google" "Maps API" "medium" "google-maps" \
    -i 'maps\.googleapis\.com\|places\.googleapis\.com\|GMSServices\|GMSMapView\|GoogleMaps\|GooglePlaces'

  finding "Google" "Sign-In" "medium" "google-signin" \
    'GIDSignIn\|GIDConfiguration\|clientID.*googleusercontent'
fi

# =====================================================================
# AWS
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_AWS" == true ]]; then
  echo "--- Scanning for AWS credentials ---"

  finding "AWS" "Access Key ID" "critical" "aws-access-key" \
    'AKIA[0-9A-Z]\{16\}'

  finding "AWS" "Secret Access Key" "critical" "aws-secret-key" \
    -i 'aws[_-]?secret[_-]?access[_-]?key\|aws[_-]?secret[_-]?key'

  finding "AWS" "Session Token" "high" "aws-session-token" \
    -i 'aws[_-]?session[_-]?token\|x-amz-security-token'

  finding "AWS" "Cognito Pool" "medium" "aws-cognito" \
    -i 'cognito[_-]?identity[_-]?pool\|user[_-]?pool[_-]?id\|CognitoIdentityUserPoolId\|CognitoIdentityPoolId'

  finding "AWS" "Cognito Identity" "medium" "aws-cognito-identity" \
    'us-east-1:[a-f0-9-]\{36\}\|us-west-2:[a-f0-9-]\{36\}\|eu-west-1:[a-f0-9-]\{36\}\|eu-central-1:[a-f0-9-]\{36\}\|ap-southeast-1:[a-f0-9-]\{36\}'

  finding "AWS" "SDK Usage" "info" "aws-sdk" \
    'AWSMobileClient\|AWSCognitoIdentityProvider\|AWSS3\|AWSDynamoDB\|AWSLambda\|AWSAppSync\|AWSIoT'

  finding "AWS" "S3 Bucket" "medium" "aws-s3-bucket" \
    's3://[a-z0-9][a-z0-9.-]*\|[a-z0-9.-]*\.s3\.amazonaws\.com\|s3\.[a-z0-9-]*\.amazonaws\.com'

  finding "AWS" "Endpoints" "info" "aws-endpoints" \
    '\.amazonaws\.com\|execute-api\..*\.amazonaws\|lambda\..*\.amazonaws'

  finding "AWS" "Amplify Config" "medium" "aws-amplify" \
    -i 'amplifyconfiguration\|awsconfiguration\|aws-exports'
fi

# =====================================================================
# Azure
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_AZURE" == true ]]; then
  echo "--- Scanning for Azure credentials ---"

  finding "Azure" "Connection String" "critical" "azure-connection-string" \
    'DefaultEndpointsProtocol=https;AccountName=\|AccountKey='

  finding "Azure" "SAS Token" "high" "azure-sas-token" \
    'SharedAccessSignature=\|sv=[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}.*sig='

  finding "Azure" "MSAL/ADAL" "medium" "azure-msal" \
    'MSALPublicClientApplication\|MSALConfiguration\|MSALAuthority\|ADALContext\|ADAL'

  finding "Azure" "Tenant/Client ID" "medium" "azure-tenant" \
    -i 'tenant[_-]?id.*[a-f0-9]\{8\}-[a-f0-9]\{4\}\|client[_-]?id.*[a-f0-9]\{8\}-[a-f0-9]\{4\}'

  finding "Azure" "Endpoints" "info" "azure-endpoints" \
    '\.azurewebsites\.net\|\.blob\.core\.windows\.net\|\.table\.core\.windows\.net\|\.vault\.azure\.net\|\.database\.windows\.net\|\.servicebus\.windows\.net'

  finding "Azure" "Notification Hubs" "medium" "azure-notification-hubs" \
    -i 'SBNotificationHub\|notificationhubname\|DefaultFullSharedAccessSignature'

  finding "Azure" "Key Vault" "info" "azure-keyvault" \
    -i 'keyvault\|\.vault\.azure\.net'

  finding "Azure" "App Configuration" "high" "azure-appconfig" \
    'Endpoint=https://.*\.azconfig\.io'
fi

# =====================================================================
# Payment Providers
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_PAYMENTS" == true ]]; then
  echo "--- Scanning for payment provider credentials ---"

  finding "Stripe" "Secret Key" "critical" "stripe-secret" \
    'sk_live_[0-9a-zA-Z]\{24,\}'

  finding "Stripe" "Test Secret Key" "medium" "stripe-test-secret" \
    'sk_test_[0-9a-zA-Z]\{24,\}'

  finding "Stripe" "Publishable Key" "low" "stripe-publishable" \
    'pk_live_[0-9a-zA-Z]\{24,\}\|pk_test_[0-9a-zA-Z]\{24,\}'

  finding "Stripe" "Restricted Key" "high" "stripe-restricted" \
    'rk_live_[0-9a-zA-Z]\{24,\}\|rk_test_[0-9a-zA-Z]\{24,\}'

  finding "PayPal" "SDK" "info" "paypal-sdk" \
    -i 'paypal\|braintree\|BTPayPalDriver\|BTDropInController'

  finding "RevenueCat" "API Key" "medium" "revenuecat-key" \
    -i 'revenuecat\|Purchases\.configure\|appl_[a-zA-Z0-9]'
fi

# =====================================================================
# Messaging / Push
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_MESSAGING" == true ]]; then
  echo "--- Scanning for messaging/push credentials ---"

  finding "Twilio" "Account SID" "high" "twilio-sid" \
    'AC[0-9a-f]\{32\}'

  finding "Twilio" "API Key" "high" "twilio-api-key" \
    'SK[0-9a-f]\{32\}'

  finding "SendGrid" "API Key" "critical" "sendgrid-key" \
    'SG\.[a-zA-Z0-9_-]\{22\}\.[a-zA-Z0-9_-]\{43\}'

  finding "Slack" "Bot Token" "critical" "slack-bot-token" \
    'xoxb-[0-9]\{11\}-[0-9]\{11\}-[a-zA-Z0-9]\{24\}'

  finding "Slack" "Webhook" "high" "slack-webhook" \
    'hooks\.slack\.com/services/'

  finding "OneSignal" "App ID" "medium" "onesignal-appid" \
    -i 'onesignal\|OneSignal\|setAppId'

  finding "Pusher" "Credentials" "medium" "pusher-creds" \
    -i 'pusher\|PusherSwift\|Pusher('

  finding "PubNub" "Keys" "medium" "pubnub-keys" \
    -i 'pubnub\|PubNub\|subscribeKey\|publishKey'
fi

# =====================================================================
# Analytics
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_ANALYTICS" == true ]]; then
  echo "--- Scanning for analytics credentials ---"

  finding "Sentry" "DSN" "medium" "sentry-dsn" \
    'sentry\.io\|SentrySDK\|https://[a-f0-9]*@.*\.ingest\.sentry\.io'

  finding "Mixpanel" "Token" "medium" "mixpanel-token" \
    -i 'mixpanel\|Mixpanel\.initialize\|Mixpanel\.mainInstance'

  finding "Amplitude" "API Key" "medium" "amplitude-key" \
    -i 'amplitude\|Amplitude\.instance\|amplitude[_-]?api[_-]?key'

  finding "Segment" "Write Key" "medium" "segment-writekey" \
    -i 'segment\|Analytics\.setup\|writeKey'

  finding "Algolia" "API Key" "medium" "algolia-key" \
    -i 'algolia\|ALGOLIA_API_KEY\|algolianet\.com'

  finding "Datadog" "Client Token" "medium" "datadog-token" \
    -i 'datadog\|Datadog\.initialize\|clientToken\|dd-api-key'

  finding "Crashlytics" "Usage" "info" "crashlytics" \
    'Crashlytics\|FIRCrashlytics\|fabric\.io'

  finding "AppsFly" "Dev Key" "medium" "appsflyer-key" \
    -i 'appsflyer\|AppsFlyerLib\|appsFlyerDevKey'
fi

# =====================================================================
# JWT Tokens
# =====================================================================
if [[ "$SEARCH_ALL" == true || "$SEARCH_JWT" == true ]]; then
  echo "--- Scanning for JWT tokens ---"

  finding "JWT" "Token" "high" "jwt-token" \
    'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
fi

# =====================================================================
# Generic high-confidence patterns (always run)
# =====================================================================
echo "--- Scanning for generic secret patterns ---"

finding "Generic" "Private Key Block" "critical" "private-key-block" \
  'BEGIN.*PRIVATE KEY\|BEGIN RSA PRIVATE'

finding "Generic" "Hardcoded Password" "high" "hardcoded-password" \
  -i 'password\s*[:=]\s*"[^"]\{4,\}"\|passwd\s*[:=]\s*"[^"]\{4,\}'

finding "Generic" "Encryption Key" "high" "encryption-key" \
  -i 'encryption[_-]?key\s*[:=]\s*"\|aes[_-]?key\s*[:=]\s*"\|secret[_-]?key\s*[:=]\s*"'

finding "Generic" "Hardcoded IV" "high" "hardcoded-iv" \
  -i 'iv[_-]?vector\s*[:=]\s*"\|initialization[_-]?vector\s*[:=]\s*"'

finding "Generic" "Base64 Encoded Key" "medium" "base64-key" \
  -i 'private[_-]?key.*[A-Za-z0-9+/=]\{40,\}'

# =====================================================================
# Summary
# =====================================================================
echo
echo "============================================"
echo "=== Deep Secret Scan Complete ==="
echo "============================================"
echo
echo "Total findings: $TOTAL_FINDINGS"
echo "  Critical: $CRITICAL_COUNT"
echo "  High:     $HIGH_COUNT"
echo "  Medium:   $MEDIUM_COUNT"
echo "  Low:      $LOW_COUNT"
echo "  Info:     $INFO_COUNT"
echo
echo "LLM_ANALYSIS_SUMMARY:TOTAL=$TOTAL_FINDINGS,CRITICAL=$CRITICAL_COUNT,HIGH=$HIGH_COUNT,MEDIUM=$MEDIUM_COUNT,LOW=$LOW_COUNT,INFO=$INFO_COUNT"

# --- Generate report ---
if [[ -n "$REPORT_FILE" ]]; then
  {
    echo "# Deep Secret Scan Report"
    echo
    echo "**Analysis directory**: \`$ANALYSIS_DIR\`"
    echo "**Generated**: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "**Minimum severity**: $MIN_SEVERITY"
    echo
    echo "## Summary"
    echo
    echo "| Severity | Count |"
    echo "|----------|-------|"
    echo "| Critical | $CRITICAL_COUNT |"
    echo "| High | $HIGH_COUNT |"
    echo "| Medium | $MEDIUM_COUNT |"
    echo "| Low | $LOW_COUNT |"
    echo "| Info | $INFO_COUNT |"
    echo "| **Total** | **$TOTAL_FINDINGS** |"
    echo
    echo "## Findings"
    echo
    echo "$REPORT_CONTENT"
    echo
    echo "---"
    echo
    echo "## LLM Analysis Instructions"
    echo
    echo "For each finding above, analyze:"
    echo "1. **Is this a real credential or a false positive?** (e.g., example values, documentation)"
    echo "2. **Is this credential client-safe?** (e.g., Firebase API keys, Stripe publishable keys)"
    echo "3. **What is the blast radius?** (what can an attacker do with this credential)"
    echo "4. **What is the remediation?** (rotate, restrict, move to server-side)"
    echo "5. **Can this be validated?** (suggest safe validation commands)"
    echo
    echo "---"
    echo "_Report generated by ios-reverse-engineering-skill deep-secret-scan_"
  } > "$REPORT_FILE"
  echo "Report saved to: $REPORT_FILE"
fi

# Exit code based on severity
if [[ "$CRITICAL_COUNT" -gt 0 ]]; then
  exit 2
elif [[ "$HIGH_COUNT" -gt 0 ]]; then
  exit 1
else
  exit 0
fi
