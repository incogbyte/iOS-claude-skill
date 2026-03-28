# Cloud Secrets & Credential Patterns

Comprehensive patterns for detecting cloud provider credentials, API keys, and service configurations leaked in iOS application binaries. These patterns are used by the LLM analysis phase to classify, validate, and assess the risk of exposed secrets.

## Firebase

Firebase is extremely common in iOS apps. Look for configuration embedded via `GoogleService-Info.plist`.

### Patterns

```bash
# Firebase config (GoogleService-Info.plist values)
grep -rni 'GOOGLE_APP_ID\|GCM_SENDER_ID\|FIREBASE_URL\|DATABASE_URL.*firebaseio\.com\|STORAGE_BUCKET\|PROJECT_ID\|BUNDLE_ID\|API_KEY\|CLIENT_ID.*apps\.googleusercontent\.com' output/

# Firebase SDK classes
grep -rn 'FIRApp\|FirebaseApp\|FIRAuth\|FIRDatabase\|FIRFirestore\|FIRStorage\|FIRMessaging\|FIRAnalytics\|FIRCrashlytics\|FIRRemoteConfig' output/

# Firebase URLs
grep -rn 'firebaseio\.com\|firebaseapp\.com\|firebase\.google\.com\|fcm\.googleapis\.com\|firebasestorage\.googleapis\.com' output/

# Firebase Dynamic Links
grep -rn 'page\.link\|app\.goo\.gl\|FIRDynamicLink' output/

# Realtime Database / Firestore rules (sometimes hardcoded)
grep -rni 'databaseURL\|firestoreSettings\|persistenceEnabled\|cacheSizeBytes' output/
```

### What to look for

| Field | Risk | Notes |
|-------|------|-------|
| `API_KEY` | Medium | Restricted by API key restrictions, but can be abused if unrestricted |
| `DATABASE_URL` | High | Direct database access if security rules are misconfigured |
| `STORAGE_BUCKET` | High | May allow unauthenticated file read/write |
| `GCM_SENDER_ID` | Low | Can be used to send push notifications if abused |
| `PROJECT_ID` | Low-Medium | Identifies the project, useful for enumeration |
| `CLIENT_ID` | Medium | OAuth client ID, can be used for authentication flows |

### LLM Analysis Prompts

When analyzing Firebase credentials, the LLM should:
1. Check if `API_KEY` has domain/app restrictions (cannot be determined from binary alone — flag for manual testing)
2. Verify if `DATABASE_URL` is accessible without authentication (`curl <url>/.json`)
3. Check if `STORAGE_BUCKET` allows public listing
4. Identify if Firebase Auth is configured (presence of `FIRAuth` classes)
5. Flag any hardcoded Firebase Admin SDK credentials (service account keys)

## Google Cloud Platform (GCP)

### Patterns

```bash
# GCP API keys
grep -rni 'AIza[0-9A-Za-z_-]\{35\}' output/

# GCP Service Account
grep -rni 'service_account\|client_email.*gserviceaccount\.com\|private_key_id\|"type":\s*"service_account"' output/

# GCP OAuth Client IDs
grep -rn '[0-9]\{12\}-[a-z0-9]\{32\}\.apps\.googleusercontent\.com' output/

# GCP project references
grep -rni 'googleapis\.com\|storage\.cloud\.google\.com\|compute\.googleapis\.com\|bigquery\.googleapis\.com' output/

# Google Maps
grep -rni 'maps\.googleapis\.com\|places\.googleapis\.com\|GMSServices\|GMSMapView\|GoogleMaps\|GooglePlaces' output/

# Google Sign-In
grep -rn 'GIDSignIn\|GIDConfiguration\|GIDGoogleUser\|clientID.*googleusercontent' output/
```

### Key formats

| Credential | Pattern | Risk |
|-----------|---------|------|
| API Key | `AIza[0-9A-Za-z_-]{35}` | Medium-High (depends on restrictions) |
| OAuth Client ID | `{12-digits}-{32-chars}.apps.googleusercontent.com` | Medium |
| Service Account JSON | `"type": "service_account"` with `private_key` | **Critical** |
| Project Number | `[0-9]{12}` (in context of GCP) | Low |

## Amazon Web Services (AWS)

### Patterns

```bash
# AWS Access Key ID
grep -rn 'AKIA[0-9A-Z]\{16\}' output/

# AWS Secret Access Key (40 char base64)
grep -rni 'aws[_-]?secret[_-]?access[_-]?key\|aws[_-]?secret\|secret[_-]?key.*[A-Za-z0-9/+=]\{40\}' output/

# AWS session/temp credentials
grep -rni 'aws[_-]?session[_-]?token\|x-amz-security-token' output/

# AWS SDK and service references
grep -rn 'AWSMobileClient\|AWSCognitoIdentityProvider\|AWSCognito\|AWSS3\|AWSDynamoDB\|AWSLambda\|AWSAppSync\|AWSIoT' output/

# AWS Cognito
grep -rni 'cognito[_-]?identity[_-]?pool\|user[_-]?pool[_-]?id\|CognitoIdentityUserPoolId\|CognitoIdentityPoolId\|us-east-1:[a-f0-9-]\{36\}' output/

# AWS endpoints/regions
grep -rni '\.amazonaws\.com\|\.aws\.amazon\.com\|s3\..*\.amazonaws\|execute-api\..*\.amazonaws\|lambda\..*\.amazonaws' output/

# AWS Amplify
grep -rni 'amplifyconfiguration\|awsconfiguration\|aws-exports' output/

# S3 bucket names
grep -rn 's3://[a-z0-9][a-z0-9.-]*\|[a-z0-9][a-z0-9.-]*\.s3\.amazonaws\.com\|s3\.[a-z0-9-]*\.amazonaws\.com/[a-z0-9]' output/
```

### Key formats

| Credential | Pattern | Risk |
|-----------|---------|------|
| Access Key ID | `AKIA[0-9A-Z]{16}` | **Critical** |
| Secret Access Key | 40-char base64 string | **Critical** |
| Cognito Identity Pool ID | `{region}:{uuid}` | Medium |
| Cognito User Pool ID | `{region}_{alphanumeric}` | Medium |
| S3 Bucket Name | URL or `s3://` reference | Medium (enumeration) |

## Microsoft Azure

### Patterns

```bash
# Azure connection strings
grep -rni 'DefaultEndpointsProtocol=https;AccountName=\|SharedAccessSignature=\|AccountKey=' output/

# Azure AD / MSAL
grep -rn 'MSALPublicClientApplication\|MSALConfiguration\|MSALAuthority\|MSALAccount\|ADALContext\|ADAL' output/

# Azure tenant/client IDs
grep -rni 'tenant[_-]?id\|client[_-]?id.*[a-f0-9]\{8\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{12\}' output/

# Azure endpoints
grep -rni '\.azure\.com\|\.azurewebsites\.net\|\.blob\.core\.windows\.net\|\.table\.core\.windows\.net\|\.queue\.core\.windows\.net\|\.vault\.azure\.net\|\.database\.windows\.net\|\.servicebus\.windows\.net' output/

# Azure Notification Hubs
grep -rni 'SBNotificationHub\|notificationhubname\|DefaultFullSharedAccessSignature\|\.servicebus\.windows\.net' output/

# Azure App Configuration
grep -rni 'Endpoint=https://.*\.azconfig\.io' output/

# Azure Key Vault
grep -rni 'keyvault\|\.vault\.azure\.net' output/
```

### Key formats

| Credential | Pattern | Risk |
|-----------|---------|------|
| Storage Account Key | Base64, 88 chars | **Critical** |
| SAS Token | `sv=...&sig=...` | High |
| Connection String | `DefaultEndpointsProtocol=...` | **Critical** |
| Client Secret | GUID-like string in auth context | **Critical** |
| Tenant ID | UUID format | Low |

## Other Common Services

### Stripe

```bash
grep -rni 'sk_live_[0-9a-zA-Z]\{24,\}\|pk_live_[0-9a-zA-Z]\{24,\}\|sk_test_[0-9a-zA-Z]\{24,\}\|pk_test_[0-9a-zA-Z]\{24,\}\|rk_live_\|rk_test_' output/
```

| Key | Pattern | Risk |
|-----|---------|------|
| Secret Key | `sk_live_*` | **Critical** (full API access) |
| Publishable Key | `pk_live_*` | Low (intended for client) |
| Test Secret | `sk_test_*` | Medium |
| Restricted Key | `rk_live_*` | High |

### Twilio

```bash
grep -rni 'AC[0-9a-f]\{32\}\|SK[0-9a-f]\{32\}\|twilio\|\.twilio\.com' output/
```

### SendGrid

```bash
grep -rni 'SG\.[a-zA-Z0-9_-]\{22\}\.[a-zA-Z0-9_-]\{43\}\|sendgrid\|\.sendgrid\.com' output/
```

### Slack

```bash
grep -rni 'xoxb-[0-9]\{11\}-[0-9]\{11\}-[a-zA-Z0-9]\{24\}\|xoxp-\|xoxa-\|hooks\.slack\.com/services/' output/
```

### OneSignal

```bash
grep -rni 'onesignal\|OneSignal\|setAppId\|[a-f0-9]\{8\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{4\}-[a-f0-9]\{12\}.*onesignal' output/
```

### Mixpanel / Amplitude / Segment

```bash
grep -rni 'mixpanel\|Mixpanel\.initialize\|amplitude\|Amplitude\.instance\|segment\|Analytics\.setup\|writeKey' output/
```

### Sentry

```bash
grep -rni 'sentry\.io\|SentrySDK\|dsn.*sentry\|https://[a-f0-9]\{32\}@[a-z0-9]*\.ingest\.sentry\.io' output/
```

### Algolia

```bash
grep -rni 'algolia\|ALGOLIA_API_KEY\|applicationID.*algolia\|algolianet\.com' output/
```

### Pusher / PubNub

```bash
grep -rni 'pusher\|PusherSwift\|Pusher(\|pubnub\|PubNub\|subscribeKey\|publishKey' output/
```

## Regex Summary for Binary Scanning

These high-confidence regexes can be run directly against `strings-raw.txt`:

```bash
# All high-confidence patterns in one scan
grep -E \
  'AIza[0-9A-Za-z_-]{35}|'\
  'AKIA[0-9A-Z]{16}|'\
  'sk_live_[0-9a-zA-Z]{24,}|'\
  'sk_test_[0-9a-zA-Z]{24,}|'\
  'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}|'\
  'xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}|'\
  'AC[0-9a-f]{32}|'\
  'DefaultEndpointsProtocol=https|'\
  'AccountKey=[A-Za-z0-9+/=]{86,}|'\
  'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' \
  output/strings-raw.txt
```

## JWT Token Detection

```bash
# JWT tokens (base64.base64.base64)
grep -rn 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*' output/
```

JWTs found in the binary may contain:
- Hardcoded test/dev tokens
- Default/example tokens with real claims
- Token structure revealing API expectations

## LLM Analysis Guidelines

When the LLM analyzes extracted secrets, it should:

### Classification
1. **Identify the service** — match the key format to known providers
2. **Assess the risk level** — Critical / High / Medium / Low / Info
3. **Determine if client-safe** — some keys (e.g., `pk_live_*`, Firebase `API_KEY`) are intended for client use
4. **Check for test vs production** — test keys (`sk_test_*`, staging URLs) are lower risk

### Validation suggestions
For each found credential, suggest validation steps:
- Firebase API Key → test with Firebase REST API
- AWS Access Key → `aws sts get-caller-identity`
- GCP API Key → test with Maps/Geocoding API
- Azure Connection String → test blob storage access
- Stripe Secret Key → `curl https://api.stripe.com/v1/charges -u sk_live_xxx:`

### Report format
```markdown
### 🔑 [SERVICE] — [RISK LEVEL]

- **Type**: [credential type]
- **Value**: `[redacted first/last 4 chars]`
- **Location**: [file:line]
- **Client-safe**: Yes/No
- **Impact**: [what an attacker could do]
- **Recommendation**: [specific remediation]
```
