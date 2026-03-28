#!/usr/bin/env bash
# find-api-calls.sh — Search extracted iOS app output for API calls and HTTP endpoints
set -euo pipefail

usage() {
  cat <<EOF
Usage: find-api-calls.sh <analysis-dir> [OPTIONS]

Search extracted iOS app analysis output for HTTP API calls and endpoints.
Searches class-dump headers, strings output, and any source files found.

Arguments:
  <analysis-dir>    Path to the analysis output directory (from extract-ipa.sh)

Options:
  --urlsession        Search only for URLSession/NSURLSession patterns
  --alamofire         Search only for Alamofire/AFNetworking/Moya patterns
  --urls              Search only for hardcoded URLs
  --auth              Search only for auth-related patterns
  --swift-concurrency Search only for async/await and Combine patterns
  --graphql           Search only for GraphQL patterns
  --websocket         Search only for WebSocket patterns
  --security          Search only for security patterns (ATS, cert pinning, jailbreak)
  --cloud-secrets     Search only for cloud provider credentials (Firebase, AWS, GCP, Azure)
  --all               Search all patterns (default)
  --report FILE       Export results as Markdown report to FILE
  --context N         Show N lines of context around matches (default: 0)
  --dedup             Deduplicate results by endpoint/URL
  -h, --help          Show this help message

Output:
  Results are printed as file:line:match for easy navigation.
  With --report, a structured Markdown report is also generated.
EOF
  exit 0
}

ANALYSIS_DIR=""
SEARCH_URLSESSION=false
SEARCH_ALAMOFIRE=false
SEARCH_URLS=false
SEARCH_AUTH=false
SEARCH_SWIFT_CONCURRENCY=false
SEARCH_GRAPHQL=false
SEARCH_WEBSOCKET=false
SEARCH_SECURITY=false
SEARCH_CLOUD_SECRETS=false
SEARCH_ALL=true
REPORT_FILE=""
CONTEXT_LINES=0
DEDUP=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --urlsession)        SEARCH_URLSESSION=true;        SEARCH_ALL=false; shift ;;
    --alamofire)         SEARCH_ALAMOFIRE=true;          SEARCH_ALL=false; shift ;;
    --urls)              SEARCH_URLS=true;               SEARCH_ALL=false; shift ;;
    --auth)              SEARCH_AUTH=true;                SEARCH_ALL=false; shift ;;
    --swift-concurrency) SEARCH_SWIFT_CONCURRENCY=true;  SEARCH_ALL=false; shift ;;
    --graphql)           SEARCH_GRAPHQL=true;            SEARCH_ALL=false; shift ;;
    --websocket)         SEARCH_WEBSOCKET=true;          SEARCH_ALL=false; shift ;;
    --security)          SEARCH_SECURITY=true;           SEARCH_ALL=false; shift ;;
    --cloud-secrets)     SEARCH_CLOUD_SECRETS=true;      SEARCH_ALL=false; shift ;;
    --all)               SEARCH_ALL=true; shift ;;
    --report)            REPORT_FILE="$2"; shift 2 ;;
    --context)           CONTEXT_LINES="$2"; shift 2 ;;
    --dedup)             DEDUP=true; shift ;;
    -h|--help)           usage ;;
    -*)                  echo "Error: Unknown option $1" >&2; usage ;;
    *)                   ANALYSIS_DIR="$1"; shift ;;
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

GREP_OPTS="-rn --include=*.h --include=*.m --include=*.swift --include=*.txt --include=*.plist --include=*.json"
CONTEXT_FLAG=""
if [[ "$CONTEXT_LINES" -gt 0 ]]; then
  CONTEXT_FLAG="-C $CONTEXT_LINES"
fi

# Report buffer
REPORT_CONTENT=""
SECTION_COUNTS=()

section() {
  echo
  echo "==== $1 ===="
  echo
  if [[ -n "$REPORT_FILE" ]]; then
    REPORT_CONTENT+=$'\n'"## $1"$'\n\n'
  fi
}

run_grep() {
  local case_flag=""
  if [[ "$1" == "-i" ]]; then
    case_flag="-i"
    shift
  fi
  local pattern="$1"
  local results=""
  # shellcheck disable=SC2086
  results=$(grep $GREP_OPTS $CONTEXT_FLAG $case_flag -E "$pattern" "$ANALYSIS_DIR" 2>/dev/null || true)

  if [[ -n "$results" ]]; then
    if [[ "$DEDUP" == true ]]; then
      results=$(echo "$results" | sort -t: -k3 -u)
    fi
    echo "$results"
    local count
    count=$(echo "$results" | grep -c '' || true)
    SECTION_COUNTS+=("$count")
    if [[ -n "$REPORT_FILE" ]]; then
      REPORT_CONTENT+='```'$'\n'"$results"$'\n''```'$'\n\n'
    fi
  else
    SECTION_COUNTS+=("0")
    if [[ -n "$REPORT_FILE" ]]; then
      REPORT_CONTENT+="_No matches found._"$'\n\n'
    fi
  fi
}

# --- URLSession / NSURLSession ---
if [[ "$SEARCH_ALL" == true || "$SEARCH_URLSESSION" == true ]]; then
  section "URLSession / NSURLSession"
  run_grep '(URLSession|NSURLSession|URLRequest|NSMutableURLRequest|dataTask|uploadTask|downloadTask|URLSessionDelegate|URLSessionConfiguration)'
  section "URLSession HTTP Methods"
  run_grep '(httpMethod|HTTPMethod|"GET"|"POST"|"PUT"|"DELETE"|"PATCH"|setValue.*forHTTPHeaderField|addValue.*forHTTPHeaderField|allHTTPHeaderFields|httpBody)'
  section "URLComponents & URL Construction"
  run_grep '(URLComponents|NSURLComponents|queryItems|URLQueryItem|appendingPathComponent|absoluteString|url.*scheme|url.*host|url.*path)'
fi

# --- Alamofire / AFNetworking / Moya ---
if [[ "$SEARCH_ALL" == true || "$SEARCH_ALAMOFIRE" == true ]]; then
  section "Alamofire"
  run_grep '(AF\.|Session\.(default|request)|\.request\(|\.upload\(|\.download\(|\.responseDecodable|\.responseJSON|\.responseData|\.response\(|HTTPMethod\.|ParameterEncoding|JSONEncoding|URLEncoding|\.validate\(|\.authenticate\(|RequestInterceptor|RequestAdapter|RequestRetrier)'
  section "AFNetworking"
  run_grep '(AFHTTPSessionManager|AFURLSessionManager|AFHTTPRequestSerializer|AFJSONResponseSerializer|AFNetworkReachabilityManager|AFSecurityPolicy)'
  section "Moya"
  run_grep '(MoyaProvider|TargetType|\.request\(|\.rx\.request|\.task|\.method|\.path|\.baseURL|\.headers|\.sampleData|MoyaError|Endpoint)'
fi

# --- Swift Concurrency / Combine ---
if [[ "$SEARCH_ALL" == true || "$SEARCH_SWIFT_CONCURRENCY" == true ]]; then
  section "Swift async/await"
  run_grep '(async\s+(throws\s+)?->|await\s|Task\s*\{|Task\.detached|TaskGroup|withChecking|withThrowingTaskGroup|AsyncSequence|AsyncStream|\.value\b)'
  section "Combine Framework"
  run_grep '(Publisher|AnyPublisher|PassthroughSubject|CurrentValueSubject|\.sink\s*\{|\.receive\(on:|Subscribers|\.eraseToAnyPublisher|\.flatMap|\.map\s*\{|\.tryMap|\.decode\(|URLSession.*dataTaskPublisher|\.assign\(to:)'
  section "Async URLSession"
  run_grep '(URLSession\.shared\.data\(|\.data\(for:|\.bytes\(from:|\.upload\(for:|\.download\(from:)'
fi

# --- Hardcoded URLs ---
if [[ "$SEARCH_ALL" == true || "$SEARCH_URLS" == true ]]; then
  section "Hardcoded URLs (http:// and https://)"
  run_grep '"https?://[^"]+'
  section "URL Constants"
  run_grep -i '(baseURL|base_url|apiURL|api_url|serverURL|server_url|ENDPOINT|API_BASE|HOST_NAME|kAPI|kBase)'
  section "WKWebView / UIWebView"
  run_grep '(WKWebView|UIWebView|loadRequest|loadHTMLString|evaluateJavaScript|WKNavigationDelegate|WKScriptMessageHandler|WKUserContentController)'
fi

# --- Auth patterns ---
if [[ "$SEARCH_ALL" == true || "$SEARCH_AUTH" == true ]]; then
  section "Authentication & API Keys"
  run_grep -i '(api[_-]?key|auth[_-]?token|bearer|authorization|x-api-key|client[_-]?secret|access[_-]?token|refresh[_-]?token|id[_-]?token|oauth)'
  section "Keychain Access"
  run_grep '(SecItemAdd|SecItemCopyMatching|SecItemUpdate|SecItemDelete|kSecClass|kSecAttrAccount|kSecValueData|kSecAttrAccessible|KeychainWrapper|KeychainAccess|SAMKeychain)'
  section "Biometric Authentication"
  run_grep '(LAContext|evaluatePolicy|canEvaluatePolicy|biometryType|deviceOwnerAuthentication|touchIDAuthenticationAllowableReuseDuration)'
fi

# --- GraphQL ---
if [[ "$SEARCH_ALL" == true || "$SEARCH_GRAPHQL" == true ]]; then
  section "GraphQL / Apollo"
  run_grep '(ApolloClient|GraphQLQuery|GraphQLMutation|GraphQLSubscription|\.fetch\(query:|\.perform\(mutation:|\.subscribe\(subscription:|graphql|GraphQL)'
  section "GraphQL Operations"
  run_grep -i '(graphql[_-]?url|graphql[_-]?endpoint|operationName|query.*\{.*\}|mutation.*\{.*\})'
fi

# --- WebSocket ---
if [[ "$SEARCH_ALL" == true || "$SEARCH_WEBSOCKET" == true ]]; then
  section "WebSocket"
  run_grep '(URLSessionWebSocketTask|webSocketTask|NWConnection|NWProtocolWebSocket|WebSocket|Starscream|SocketIO|SRWebSocket|wss?://[^"]*")'
  section "Socket.IO / Starscream"
  run_grep '(SocketManager|SocketIOClient|\.connect\(\)|\.emit\(|\.on\(|WebSocket\(url:|\.write\(string:|\.write\(data:)'
fi

# --- Security Patterns ---
if [[ "$SEARCH_ALL" == true || "$SEARCH_SECURITY" == true ]]; then
  section "App Transport Security (ATS)"
  run_grep -i '(NSAppTransportSecurity|NSAllowsArbitraryLoads|NSExceptionDomains|NSExceptionAllowsInsecureHTTPLoads|NSAllowsArbitraryLoadsInWebContent|NSAllowsLocalNetworking)'
  section "Certificate Pinning"
  run_grep '(URLAuthenticationChallenge|ServerTrust|SecTrust|SecCertificate|pinnedCertificates|evaluateServerTrust|TrustKit|SSLPinningMode|AFSecurityPolicy|certificatePinner|AlamofireExtended|ServerTrustManager|ServerTrustEvaluating|PinnedCertificatesTrustEvaluator|PublicKeysTrustEvaluator)'
  section "Disabled Security (Dangerous)"
  run_grep '(\.performDefaultHandling|\.cancelAuthenticationChallenge|continueWithoutCredential|NSURLAuthenticationMethodServerTrust.*completionHandler|disableEvaluation|AllowAll|trustAll|insecure|kSecTrustResultUnspecified.*proceed)'
  section "Jailbreak Detection"
  run_grep '(Cydia|/Applications/Cydia\.app|cydia://|/bin/bash|/usr/sbin/sshd|/etc/apt|/private/var/lib|canOpenURL.*cydia|fork\(\)|MobileSubstrate|SubstrateLoader|isJailbroken|jailbreak|substrate)'
  section "Debug & Development Flags"
  run_grep -i '(#if\s+DEBUG|isDebug|debugMode|staging|dev[_-]?mode|enableLogging|LOG_LEVEL|VERBOSE|NSLog|print\(|os_log|Logger\.|\.debug\()'
  section "Exposed Secrets & Credentials"
  run_grep -i '(password\s*[:=]\s*"|secret\s*[:=]\s*"|private[_-]?key|encryption[_-]?key|aes[_-]?key|iv[_-]?vector|salt\s*=|firebase[_-]?key|aws[_-]?key|google[_-]?api|maps[_-]?key|stripe[_-]?key|sendgrid|twilio|paypal)'
  section "Crypto & Encryption Usage"
  run_grep '(CCCrypt|CC_MD5|CC_SHA|CommonCrypto|SecKey|kCCAlgorithmAES|kCCEncrypt|kCCDecrypt|CryptoKit|AES\.GCM|SHA256|P256|Curve25519|HMAC|SymmetricKey|SecureEnclave)'
  section "Keychain Security Level"
  run_grep '(kSecAttrAccessibleAlways|kSecAttrAccessibleAfterFirstUnlock|kSecAttrAccessibleWhenUnlocked|kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly|SecAccessControl)'
  section "Privacy Concerns"
  run_grep '(UIPasteboard|generalPasteboard|clipboardData|IDFA|ASIdentifierManager|advertisingIdentifier|ATTrackingManager|requestTrackingAuthorization|CLLocationManager|PHPhotoLibrary|AVCaptureDevice|CNContactStore)'
fi

# --- Cloud Provider Secrets ---
if [[ "$SEARCH_ALL" == true || "$SEARCH_CLOUD_SECRETS" == true ]]; then
  section "Firebase Configuration"
  run_grep -i '(GOOGLE_APP_ID|GCM_SENDER_ID|FIREBASE_URL|STORAGE_BUCKET|firebaseio\.com|firebaseapp\.com|firebasestorage\.googleapis\.com|GoogleService-Info|REVERSED_CLIENT_ID)'
  section "GCP API Keys & Service Accounts"
  run_grep '(AIza[0-9A-Za-z_-]{35}|gserviceaccount\.com|"type".*service_account|googleapis\.com|maps\.googleapis\.com|GMSServices)'
  section "AWS Credentials"
  run_grep '(AKIA[0-9A-Z]{16}|aws[_-]?(secret|access|session)|\.amazonaws\.com|cognito|AWSMobileClient|AWSS3|AWSAppSync|amplifyconfiguration|awsconfiguration)'
  section "Azure Credentials"
  run_grep -i '(DefaultEndpointsProtocol=|AccountKey=|SharedAccessSignature=|\.azurewebsites\.net|\.blob\.core\.windows\.net|\.vault\.azure\.net|\.database\.windows\.net|MSAL|MSALPublicClientApplication|\.azconfig\.io)'
  section "Payment Provider Keys"
  run_grep '(sk_live_[0-9a-zA-Z]{24,}|sk_test_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})'
  section "Messaging Service Keys"
  run_grep '(AC[0-9a-f]{32}|SK[0-9a-f]{32}|SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}|xoxb-[0-9]{11}|hooks\.slack\.com/services/)'
  section "JWT Tokens"
  run_grep 'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
fi

# --- Summary ---
echo
echo "=== Search complete ==="

total_matches=0
for c in "${SECTION_COUNTS[@]}"; do
  total_matches=$((total_matches + c))
done
echo "Total matches: $total_matches"

# --- Generate report ---
if [[ -n "$REPORT_FILE" ]]; then
  {
    echo "# iOS API & Security Analysis Report"
    echo
    echo "**Analysis directory**: \`$ANALYSIS_DIR\`"
    echo "**Generated**: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "**Total matches**: $total_matches"
    echo
    echo "$REPORT_CONTENT"
    echo "---"
    echo
    echo "_Report generated by ios-reverse-engineering-skill_"
  } > "$REPORT_FILE"
  echo "Report saved to: $REPORT_FILE"
fi
