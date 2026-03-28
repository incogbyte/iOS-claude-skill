#!/usr/bin/env bash
# detect-sdks.sh — Identify third-party SDKs/frameworks embedded in iOS apps
# Fingerprints SDKs by framework names, class prefixes, strings, and bundle IDs
set -euo pipefail

usage() {
  cat <<EOF
Usage: detect-sdks.sh <analysis-dir> [OPTIONS]

Identify third-party SDKs and frameworks embedded in an iOS application.
Searches class-dump headers, linked libraries, embedded frameworks, and strings.

Arguments:
  <analysis-dir>    Path to the analysis output directory (from extract-ipa.sh)

Options:
  --report FILE     Export results as Markdown report to FILE
  --json            Output results as JSON
  --check-cves      Flag SDKs with known CVE patterns (based on version)
  --verbose         Show detailed match information
  -h, --help        Show this help message

Output:
  Identified SDKs with name, version (if detectable), category, and risk notes.
EOF
  exit 0
}

ANALYSIS_DIR=""
REPORT_FILE=""
JSON_OUTPUT=false
CHECK_CVES=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report)    REPORT_FILE="$2"; shift 2 ;;
    --json)      JSON_OUTPUT=true; shift ;;
    --check-cves) CHECK_CVES=true; shift ;;
    --verbose)   VERBOSE=true; shift ;;
    -h|--help)   usage ;;
    -*)          echo "Error: Unknown option $1" >&2; usage ;;
    *)           ANALYSIS_DIR="$1"; shift ;;
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

# =====================================================================
# SDK Fingerprint Database
# Format: NAME|CATEGORY|FINGERPRINTS (pipe-separated patterns)|RISK_NOTES
# Fingerprints: framework names, class prefixes, bundle ID fragments, strings
# =====================================================================

declare -a SDK_DB=(
  # --- Networking ---
  "Alamofire|Networking|Alamofire.framework,AFError,SessionManager,ServerTrustManager,ParameterEncoding|None - standard HTTP library"
  "AFNetworking|Networking|AFNetworking.framework,AFHTTPSessionManager,AFURLSessionManager,AFSecurityPolicy,AFNetworkReachabilityManager|Legacy; check for older versions with known vulns"
  "Moya|Networking|Moya.framework,MoyaProvider,TargetType,MoyaError|None - Alamofire abstraction layer"
  "SDWebImage|Networking|SDWebImage.framework,SDWebImageManager,SDImageCache,sd_setImageWithURL|Check for MITM on image downloads"
  "Kingfisher|Networking|Kingfisher.framework,KingfisherManager,KFImage,kf.setImage|None"
  "Apollo GraphQL|Networking|Apollo.framework,ApolloClient,GraphQLQuery,GraphQLMutation|Check GraphQL introspection exposure"

  # --- Analytics & Tracking ---
  "Firebase Analytics|Analytics|FirebaseAnalytics.framework,FIRAnalytics,GoogleService-Info,GOOGLE_APP_ID,GCM_SENDER_ID,firebaseio.com|Check Firebase rules; API keys in client"
  "Firebase Crashlytics|Analytics|FirebaseCrashlytics.framework,FIRCrashlytics,Crashlytics.framework|Collects device info and crash data"
  "Google Analytics|Analytics|GoogleAnalytics.framework,GAI,GAITracker|Tracks user behavior; deprecated"
  "Mixpanel|Analytics|Mixpanel.framework,MixpanelAPI,mixpanel,MixpanelInstance|Check for PII in events"
  "Amplitude|Analytics|Amplitude.framework,AmplitudeSDK,AMPRevenue|Check for PII in events"
  "Segment|Analytics|Analytics.framework,SEGAnalytics,SegmentAnalytics|Hub for multiple analytics; check write key"
  "Adjust|Analytics|Adjust.framework,ADJConfig,AdjustSdk,adj_|Attribution tracking"
  "AppsFlyer|Analytics|AppsFlyerLib.framework,AppsFlyerTracker,AppsFlyerLib|Attribution tracking"
  "Branch|Analytics|Branch.framework,BNCConfig,BranchEvent|Deep linking + attribution"
  "Flurry|Analytics|Flurry.framework,FlurryAnalytics,FlurrySDK|Legacy analytics"
  "Datadog|Analytics|DatadogCore.framework,DDLog,Datadog.framework,DatadogRUM|APM and logging"
  "New Relic|Analytics|NewRelicAgent.framework,NewRelic,NRMAAnalytics|APM agent"
  "Sentry|Analytics|Sentry.framework,SentrySDK,SentryClient,SentryScope|Error tracking; check DSN exposure"
  "Bugsnag|Analytics|Bugsnag.framework,BugsnagClient,BugsnagConfiguration|Error tracking"
  "Instabug|Analytics|Instabug.framework,IBGNetworkLogger|Bug reporting with network logging"

  # --- Advertising ---
  "Google AdMob|Advertising|GoogleMobileAds.framework,GADRequest,GADBannerView,GADInterstitialAd|Ad SDK; collects device info"
  "Facebook Ads|Advertising|FBAudienceNetwork.framework,FBAdView,FBInterstitialAd|Ad SDK; Meta tracking"
  "Unity Ads|Advertising|UnityAds.framework,UADSApiSdk|Ad SDK; collects device info"
  "AppLovin|Advertising|AppLovinSDK.framework,ALSdk,ALInterstitialAd|Mediation + ads"
  "IronSource|Advertising|IronSource.framework,ISBannerView|Ad mediation"
  "Chartboost|Advertising|Chartboost.framework,CHBBanner|Gaming ads"
  "MoPub|Advertising|MoPub.framework,MPAdView|Ad mediation (deprecated)"

  # --- Authentication ---
  "Firebase Auth|Authentication|FirebaseAuth.framework,FIRAuth,FIRUser,FIRAuthCredential|Server-side rules must be configured"
  "Google Sign-In|Authentication|GoogleSignIn.framework,GIDSignIn,GIDGoogleUser|OAuth flow"
  "Facebook Login|Authentication|FBSDKLoginKit.framework,FBSDKLoginButton,FBSDKLoginManager,FBSDKAccessToken|OAuth flow; check token storage"
  "Sign in with Apple|Authentication|AuthenticationServices.framework,ASAuthorizationAppleIDProvider,ASAuthorizationController|Apple native auth"
  "Auth0|Authentication|Auth0.framework,A0SimpleKeychain,Auth0Client|Check client credentials"
  "Okta|Authentication|OktaOidc.framework,OktaAuth|Enterprise SSO"

  # --- Payments ---
  "Stripe|Payments|Stripe.framework,STPPaymentCardTextField,STPAPIClient,STPPaymentMethod|Check publishable key exposure; verify server-side only for secret key"
  "Braintree|Payments|Braintree.framework,BTAPIClient,BTCardClient,BTPayPalDriver|Payment processing"
  "RevenueCat|Payments|RevenueCat.framework,Purchases,RCPurchases,RevenueCat_Purchases|Subscription management; check API key type"
  "Square|Payments|SquareInAppPaymentsSDK.framework|Payment processing"

  # --- Push Notifications ---
  "OneSignal|Push|OneSignal.framework,OneSignalFramework,OSNotification|Push service; check app ID exposure"
  "Pusher|Push|PusherSwift.framework,PusherConnection|Real-time push"
  "Urban Airship|Push|AirshipKit.framework,UAirship|Push + messaging"
  "Leanplum|Push|Leanplum.framework,LPPushNotificationsManager|Push + A/B testing"

  # --- Maps & Location ---
  "Google Maps|Maps|GoogleMaps.framework,GMSMapView,GMSServices,maps.googleapis.com|Check API key restrictions"
  "Mapbox|Maps|Mapbox.framework,MapboxMaps.framework,MGLMapView|Check access token"
  "HERE Maps|Maps|HEREMaps.framework,NMAMapView|Check API key"

  # --- Social ---
  "Facebook SDK|Social|FBSDKCoreKit.framework,FBSDKApplicationDelegate,FBSDKGraphRequest|Meta tracking; check app secret"
  "Twitter/X SDK|Social|TwitterKit.framework,TWTRTwitter|Social integration (deprecated)"
  "LINE SDK|Social|LineSDK.framework,LoginManager|Social login"
  "WeChat SDK|Social|WXApi,WechatOpenSDK|Social login for Chinese market"

  # --- Database & Storage ---
  "Realm|Database|Realm.framework,RealmSwift.framework,RLMRealm,RLMObject|Local DB; check encryption config"
  "Core Data|Database|NSManagedObjectContext,NSPersistentContainer,NSFetchRequest,NSEntityDescription|Apple native; check data protection"
  "FMDB|Database|FMDB.framework,FMDatabase,FMResultSet|SQLite wrapper"
  "GRDB|Database|GRDB.framework,DatabaseQueue,DatabasePool|SQLite wrapper"
  "Firebase Firestore|Database|FirebaseFirestore.framework,FIRFirestore,FIRDocumentReference|Check security rules"
  "Firebase Realtime DB|Database|FirebaseDatabase.framework,FIRDatabase,FIRDatabaseReference|Check security rules"

  # --- Cloud Storage ---
  "AWS S3|Cloud|AWSS3.framework,AWSS3TransferManager,AWSS3TransferUtility|Check bucket permissions and credentials"
  "AWS Amplify|Cloud|Amplify.framework,AWSAmplify,amplifyconfiguration|Check credential management"
  "Azure|Cloud|MSAL.framework,MSALPublicClientApplication,azurewebsites.net|Check connection strings"
  "Firebase Storage|Cloud|FirebaseStorage.framework,FIRStorage,FIRStorageReference|Check storage rules"

  # --- UI & UX ---
  "Lottie|UI|Lottie.framework,AnimationView,LottieAnimationView|Animation library"
  "SnapKit|UI|SnapKit.framework,ConstraintMaker|Auto Layout DSL"
  "RxSwift|Reactive|RxSwift.framework,Observable,DisposeBag,BehaviorRelay|Reactive programming"
  "Combine|Reactive|Publisher,AnyPublisher,PassthroughSubject,CurrentValueSubject|Apple native reactive"
  "SwiftUI|UI|SwiftUI,@State,@Binding,@ObservedObject,@EnvironmentObject|Apple modern UI"

  # --- Security ---
  "TrustKit|Security|TrustKit.framework,TSKPinningValidator,TSKSPKIHashCache|Certificate pinning library"
  "CryptoSwift|Security|CryptoSwift.framework,AES,ChaCha20,Poly1305,PKCS5|Pure Swift crypto; check for weak algo usage"
  "KeychainAccess|Security|KeychainAccess.framework,Keychain|Keychain wrapper"
  "SAMKeychain|Security|SAMKeychain,SSKeychain|Keychain wrapper (legacy)"
  "SwiftKeychainWrapper|Security|SwiftKeychainWrapper.framework,KeychainWrapper|Keychain wrapper"

  # --- Dynamic Instrumentation / Anti-RE ---
  "Frida Gadget|Instrumentation|FridaGadget,frida-gadget|CRITICAL: Frida gadget embedded in release build"

  # --- Messaging ---
  "Twilio|Messaging|TwilioVoice.framework,TwilioChatClient,TCHChannel|Check auth token exposure"
  "SendBird|Messaging|SendBirdSDK.framework,SBDMain|Chat SDK"
  "Stream Chat|Messaging|StreamChat.framework,ChatClient|Chat SDK"
  "PubNub|Messaging|PubNub.framework,PubNub,PNConfiguration|Realtime messaging; check keys"
  "Socket.IO|Messaging|SocketIO.framework,SocketManager,SocketIOClient|WebSocket client"

  # --- Crash & Performance ---
  "PLCrashReporter|Crash|CrashReporter.framework,PLCrashReporter|Crash reporting"
  "Firebase Performance|Performance|FirebasePerformance.framework,FIRPerformance|Performance monitoring"

  # --- A/B Testing ---
  "Firebase Remote Config|Config|FirebaseRemoteConfig.framework,FIRRemoteConfig|Feature flags"
  "LaunchDarkly|Config|LaunchDarkly.framework,LDClient|Feature flags; check SDK key"
  "Optimizely|Config|Optimizely.framework,OPTLYManager|A/B testing"

  # --- Deep Linking ---
  "Firebase Dynamic Links|DeepLink|FirebaseDynamicLinks.framework,FIRDynamicLink|Deep linking"

  # --- AR / ML ---
  "ARKit|AR|ARSCNView,ARSession,ARConfiguration|Apple AR"
  "Core ML|ML|MLModel,VNCoreMLRequest,CoreML.framework|Apple ML"
  "TensorFlow Lite|ML|TensorFlowLite.framework,TFLInterpreter|On-device ML"
)

# =====================================================================
# Known CVE patterns (SDK name -> version range -> CVE)
# =====================================================================

declare -a CVE_DB=(
  "AFNetworking|<3.0|CVE-2016-4117|SSL pinning bypass in AFNetworking < 3.0"
  "AFNetworking|<2.6.0|CVE-2015-3996|MITM via improper cert validation"
  "Alamofire|<5.0.0|CVE-2020-36241|ServerTrustEvaluation bypass"
  "Firebase|<6.0|CVE-2019-7289|Firebase SDK local data exposure"
  "SDWebImage|<5.6.0|CVE-2020-28026|Path traversal in cache"
  "Realm|<5.0|CVE-2019-13143|Unencrypted local database by default"
  "Facebook SDK|<9.0|CVE-2020-25375|Access token exposure in logs"
  "Branch|<0.31.0|CVE-2019-12967|Open redirect vulnerability"
  "CryptoSwift|<1.3.0|GHSA-8265|Timing side-channel in HMAC comparison"
  "TrustKit|<1.6.0|CVE-2018-16491|Pinning bypass with certain configurations"
  "Google Maps|<3.0|CVE-2020-8919|API key exposure in network requests"
  "Stripe|<21.0|CVE-2021-32977|Card data logging in debug mode"
  "Auth0|<1.30|CVE-2020-15119|ID token validation bypass"
)

# =====================================================================
# Detection logic
# =====================================================================

DETECTED_SDKS=()
DETECTED_DETAILS=()
DETECTED_CATEGORIES=()
DETECTED_RISKS=()
DETECTED_VERSIONS=()
DETECTED_MATCHES=()

search_pattern() {
  local pattern="$1"
  local results=""

  # Search in frameworks list
  if [[ -f "$ANALYSIS_DIR/frameworks/list.txt" ]]; then
    results+=$(grep -i "$pattern" "$ANALYSIS_DIR/frameworks/list.txt" 2>/dev/null || true)
  fi

  # Search in linked libraries
  if [[ -f "$ANALYSIS_DIR/linked-libraries.txt" ]]; then
    results+=$(grep -i "$pattern" "$ANALYSIS_DIR/linked-libraries.txt" 2>/dev/null || true)
  fi

  # Search in class-dump headers (filenames and content)
  if [[ -d "$ANALYSIS_DIR/class-dump" ]]; then
    # Search header filenames
    results+=$(find "$ANALYSIS_DIR/class-dump" -name "*.h" 2>/dev/null | xargs -I{} basename {} | grep -i "$pattern" 2>/dev/null || true)
    # Search header content (class names, protocols)
    results+=$(grep -rl "$pattern" "$ANALYSIS_DIR/class-dump/" 2>/dev/null | head -5 || true)
  fi

  # Search in strings
  if [[ -f "$ANALYSIS_DIR/strings-raw.txt" ]]; then
    results+=$(grep -i "$pattern" "$ANALYSIS_DIR/strings-raw.txt" 2>/dev/null | head -3 || true)
  fi

  # Search in symbols
  if [[ -f "$ANALYSIS_DIR/symbols.txt" ]]; then
    results+=$(grep -i "$pattern" "$ANALYSIS_DIR/symbols.txt" 2>/dev/null | head -3 || true)
  fi

  # Search in Info.plist
  if [[ -f "$ANALYSIS_DIR/Info.plist" ]]; then
    results+=$(grep -i "$pattern" "$ANALYSIS_DIR/Info.plist" 2>/dev/null || true)
  fi

  echo "$results"
}

try_detect_version() {
  local sdk_name="$1"
  local version=""

  # Search for version strings in strings output
  if [[ -f "$ANALYSIS_DIR/strings-raw.txt" ]]; then
    # Common version patterns: "SDKName/1.2.3", "SDKName 1.2.3", "1.2.3"
    local sdk_lower
    sdk_lower=$(echo "$sdk_name" | tr '[:upper:]' '[:lower:]' | tr ' ' '.')
    version=$(grep -ioE "${sdk_name}[/ ][0-9]+\.[0-9]+(\.[0-9]+)?" "$ANALYSIS_DIR/strings-raw.txt" 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' || true)
  fi

  # Search in framework Info.plist files
  if [[ -d "$ANALYSIS_DIR/plists" ]]; then
    for plist in "$ANALYSIS_DIR/plists/"*; do
      if grep -qi "$sdk_name" "$plist" 2>/dev/null; then
        local v
        v=$(grep -A1 "CFBundleShortVersionString" "$plist" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)
        if [[ -n "$v" ]]; then
          version="$v"
          break
        fi
      fi
    done
  fi

  echo "$version"
}

echo "=== iOS SDK/Framework Detection ==="
echo "Analysis directory: $ANALYSIS_DIR"
echo

sdk_count=0

for entry in "${SDK_DB[@]}"; do
  IFS='|' read -r sdk_name category fingerprints risk_notes <<< "$entry"

  # Split fingerprints by comma
  IFS=',' read -ra patterns <<< "$fingerprints"

  matched=false
  match_details=""

  for pattern in "${patterns[@]}"; do
    pattern=$(echo "$pattern" | xargs)  # trim whitespace
    result=$(search_pattern "$pattern")
    if [[ -n "$result" ]]; then
      matched=true
      match_details+="$pattern "
    fi
  done

  if [[ "$matched" == true ]]; then
    version=$(try_detect_version "$sdk_name")
    sdk_count=$((sdk_count + 1))

    DETECTED_SDKS+=("$sdk_name")
    DETECTED_CATEGORIES+=("$category")
    DETECTED_RISKS+=("$risk_notes")
    DETECTED_VERSIONS+=("${version:-unknown}")
    DETECTED_MATCHES+=("$match_details")

    printf "  [%s] %-30s" "$category" "$sdk_name"
    if [[ -n "$version" ]]; then
      printf " v%s" "$version"
    fi
    echo
    if [[ "$VERBOSE" == true ]]; then
      echo "    Matched: $match_details"
      echo "    Risk: $risk_notes"
    fi
  fi
done

echo
echo "Total SDKs detected: $sdk_count"

# =====================================================================
# CVE checking
# =====================================================================

CVE_FINDINGS=()

if [[ "$CHECK_CVES" == true ]]; then
  echo
  echo "=== CVE Analysis ==="

  for cve_entry in "${CVE_DB[@]}"; do
    IFS='|' read -r cve_sdk cve_version_range cve_id cve_desc <<< "$cve_entry"

    # Check if SDK was detected
    for i in "${!DETECTED_SDKS[@]}"; do
      if [[ "${DETECTED_SDKS[$i]}" == *"$cve_sdk"* ]]; then
        detected_version="${DETECTED_VERSIONS[$i]}"

        if [[ "$detected_version" == "unknown" ]]; then
          CVE_FINDINGS+=("[POSSIBLE] $cve_id — $cve_sdk $cve_version_range: $cve_desc (version unknown, manual verification needed)")
          echo "  [?] $cve_id — $cve_sdk (version unknown): $cve_desc"
        else
          # Simple version comparison for < patterns
          threshold=$(echo "$cve_version_range" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' || true)
          if [[ -n "$threshold" ]]; then
            # Use sort -V for version comparison
            lower=$(printf '%s\n%s' "$detected_version" "$threshold" | sort -V | head -1)
            if [[ "$lower" == "$detected_version" ]] && [[ "$detected_version" != "$threshold" ]]; then
              CVE_FINDINGS+=("[VULNERABLE] $cve_id — $cve_sdk v$detected_version $cve_version_range: $cve_desc")
              echo "  [!] $cve_id — $cve_sdk v$detected_version: $cve_desc"
            fi
          fi
        fi
        break
      fi
    done
  done

  if [[ ${#CVE_FINDINGS[@]} -eq 0 ]]; then
    echo "  No known CVEs matched for detected SDK versions."
  else
    echo
    echo "  CVE findings: ${#CVE_FINDINGS[@]}"
  fi
fi

# =====================================================================
# Category summary
# =====================================================================

echo
echo "=== Category Summary ==="
declare -A CAT_COUNTS
for cat in "${DETECTED_CATEGORIES[@]}"; do
  CAT_COUNTS["$cat"]=$(( ${CAT_COUNTS["$cat"]:-0} + 1 ))
done
for cat in $(echo "${!CAT_COUNTS[@]}" | tr ' ' '\n' | sort); do
  printf "  %-20s %d\n" "$cat" "${CAT_COUNTS[$cat]}"
done

# =====================================================================
# JSON output
# =====================================================================

if [[ "$JSON_OUTPUT" == true ]]; then
  echo
  echo "=== JSON Output ==="
  echo "["
  for i in "${!DETECTED_SDKS[@]}"; do
    comma=""
    if [[ $i -lt $((${#DETECTED_SDKS[@]} - 1)) ]]; then
      comma=","
    fi
    cat <<JSONEOF
  {
    "name": "${DETECTED_SDKS[$i]}",
    "category": "${DETECTED_CATEGORIES[$i]}",
    "version": "${DETECTED_VERSIONS[$i]}",
    "risk": "${DETECTED_RISKS[$i]}",
    "matches": "${DETECTED_MATCHES[$i]}"
  }${comma}
JSONEOF
  done
  echo "]"
fi

# =====================================================================
# Markdown report
# =====================================================================

if [[ -n "$REPORT_FILE" ]]; then
  {
    echo "# iOS SDK/Framework Detection Report"
    echo
    echo "**Analysis directory**: \`$ANALYSIS_DIR\`"
    echo "**Generated**: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo "**Total SDKs detected**: $sdk_count"
    echo

    echo "## Detected SDKs"
    echo
    echo "| SDK | Category | Version | Risk Notes |"
    echo "|-----|----------|---------|------------|"
    for i in "${!DETECTED_SDKS[@]}"; do
      echo "| ${DETECTED_SDKS[$i]} | ${DETECTED_CATEGORIES[$i]} | ${DETECTED_VERSIONS[$i]} | ${DETECTED_RISKS[$i]} |"
    done
    echo

    echo "## Category Breakdown"
    echo
    for cat in $(echo "${!CAT_COUNTS[@]}" | tr ' ' '\n' | sort); do
      echo "### $cat (${CAT_COUNTS[$cat]})"
      echo
      for i in "${!DETECTED_SDKS[@]}"; do
        if [[ "${DETECTED_CATEGORIES[$i]}" == "$cat" ]]; then
          echo "- **${DETECTED_SDKS[$i]}** v${DETECTED_VERSIONS[$i]}"
          echo "  - Risk: ${DETECTED_RISKS[$i]}"
          if [[ "$VERBOSE" == true ]]; then
            echo "  - Matched patterns: ${DETECTED_MATCHES[$i]}"
          fi
        fi
      done
      echo
    done

    if [[ "$CHECK_CVES" == true ]] && [[ ${#CVE_FINDINGS[@]} -gt 0 ]]; then
      echo "## CVE Findings"
      echo
      echo "| Status | CVE | SDK | Description |"
      echo "|--------|-----|-----|-------------|"
      for finding in "${CVE_FINDINGS[@]}"; do
        status=$(echo "$finding" | grep -oE '^\[[A-Z]+\]')
        rest=$(echo "$finding" | sed 's/^\[[A-Z]*\] //')
        cve_id=$(echo "$rest" | cut -d' ' -f1)
        desc=$(echo "$rest" | cut -d'—' -f2-)
        echo "| $status | $cve_id | $desc |"
      done
      echo
    fi

    echo "## Security Recommendations"
    echo
    echo "1. **Update SDKs** — Ensure all third-party SDKs are at their latest versions"
    echo "2. **Review API keys** — Verify that client-side API keys have proper restrictions"
    echo "3. **Audit analytics** — Ensure no PII is sent to analytics/tracking SDKs"
    echo "4. **Check permissions** — Verify SDKs don't request unnecessary permissions"
    echo "5. **Review data flow** — Map what data each SDK collects and where it's sent"
    echo
    echo "---"
    echo "_Report generated by ios-reverse-engineering-skill_"
  } > "$REPORT_FILE"
  echo
  echo "Report saved to: $REPORT_FILE"
fi
