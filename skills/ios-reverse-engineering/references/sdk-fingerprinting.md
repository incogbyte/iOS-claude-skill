# SDK & Framework Fingerprinting Guide

Identify third-party SDKs and frameworks embedded in iOS applications. This guide covers detection techniques, known SDK signatures, version extraction, and CVE assessment.

## Detection Techniques

### 1. Embedded Frameworks

The primary source for SDK detection. Located in `<app>/Frameworks/`:

```bash
# List embedded frameworks
ls -1 Frameworks/

# Example output:
# Alamofire.framework
# FirebaseAnalytics.framework
# GoogleMaps.framework
# Stripe.framework
```

Each `.framework` bundle contains an `Info.plist` with version info:

```bash
# Extract framework version
plutil -extract CFBundleShortVersionString raw Frameworks/Alamofire.framework/Info.plist
# Output: 5.8.1
```

### 2. Linked Libraries

From `otool -L` output, identify dynamically linked libraries:

```bash
# Key patterns in linked libraries output:
@rpath/Alamofire.framework/Alamofire          # Third-party framework
@rpath/libswiftCore.dylib                     # Swift runtime
/usr/lib/libz.1.dylib                         # System library
/System/Library/Frameworks/UIKit.framework    # Apple framework
```

Focus on `@rpath/` entries — these are third-party or custom frameworks.

### 3. Class Prefix Fingerprinting

Objective-C uses class prefixes to avoid namespace collisions. These are reliable SDK indicators:

| Prefix | SDK |
|--------|-----|
| `AF` | AFNetworking |
| `FIR` | Firebase |
| `GMS` | Google Maps |
| `GAD` | Google AdMob |
| `GAI` | Google Analytics |
| `FB`, `FBSDK` | Facebook SDK |
| `STP` | Stripe |
| `BT` | Braintree |
| `TWR` | Twitter Kit |
| `MXP` | Mixpanel |
| `AMP` | Amplitude |
| `SEG` | Segment |
| `ADJ` | Adjust |
| `SD` | SDWebImage |
| `KF` | Kingfisher |
| `RLM` | Realm |
| `PNub` | PubNub |
| `GID` | Google Sign-In |
| `ASA` | AuthenticationServices |
| `PLCrash` | PLCrashReporter |
| `TSK` | TrustKit |
| `SAM` | SAMKeychain |
| `LAContext` | LocalAuthentication (biometrics) |

Search in class-dump output:

```bash
# Find classes by prefix
grep -rh "^@interface" class-dump/ | grep "^@interface FIR" | sort -u
# Firebase classes: FIRApp, FIRAuth, FIRDatabase, etc.
```

### 4. String-Based Detection

SDKs leave identifiable strings in the binary:

```bash
# Firebase
grep -i "firebaseio\.com\|firebaseapp\.com\|GoogleService-Info\|GCM_SENDER_ID" strings-raw.txt

# AWS
grep -i "amazonaws\.com\|cognito\|amplifyconfiguration\|awsconfiguration" strings-raw.txt

# Stripe
grep -E "sk_(live|test)_|pk_(live|test)_" strings-raw.txt

# Analytics SDKs (version strings)
grep -iE "(mixpanel|amplitude|segment|adjust|appsflyer|branch)/[0-9]+\." strings-raw.txt
```

### 5. Symbol-Based Detection

For stripped binaries, check remaining symbols:

```bash
# Swift metadata survives stripping
nm binary | swift-demangle | grep -i "Alamofire\|Firebase\|Stripe"

# Protocol conformances
grep -i "TargetType\|MoyaProvider" symbols-demangled.txt  # Moya
grep -i "ServerTrustEvaluating" symbols-demangled.txt      # Alamofire 5+
```

## SDK Categories & Security Implications

### Networking SDKs
- **Risk**: MITM if pinning disabled, credential exposure, insecure defaults
- **Check**: SSL pinning configuration, ATS settings, debug logging
- **SDKs**: Alamofire, AFNetworking, Moya, Apollo GraphQL

### Analytics & Tracking
- **Risk**: PII leakage in event properties, tracking without consent
- **Check**: Event payloads, user identification, GDPR/ATT compliance
- **SDKs**: Firebase Analytics, Mixpanel, Amplitude, Segment, Adjust

### Authentication
- **Risk**: Token storage, OAuth misconfig, credential caching
- **Check**: Token storage location (Keychain vs UserDefaults), refresh flow
- **SDKs**: Firebase Auth, Google Sign-In, Facebook Login, Auth0

### Payments
- **Risk**: PCI compliance, key exposure, payment data handling
- **Check**: Secret key vs publishable key usage, card data flow
- **SDKs**: Stripe, Braintree, RevenueCat, Square

### Cloud Services
- **Risk**: Credential exposure, misconfigured access rules
- **Check**: API key restrictions, security rules, IAM policies
- **SDKs**: Firebase, AWS Amplify, Azure MSAL

### Advertising
- **Risk**: Data collection, IDFA usage without ATT, child privacy (COPPA)
- **Check**: ATTrackingManager usage, ad SDK initialization
- **SDKs**: AdMob, Facebook Ads, Unity Ads, AppLovin

## Version Extraction Methods

### From Framework Info.plist

```bash
# Most reliable method
for fw in Frameworks/*.framework; do
  name=$(basename "$fw" .framework)
  version=$(plutil -extract CFBundleShortVersionString raw "$fw/Info.plist" 2>/dev/null || echo "unknown")
  echo "$name: $version"
done
```

### From Binary Strings

```bash
# SDKs often embed version strings
grep -oE '(Alamofire|Firebase|Stripe|Mixpanel)/[0-9]+\.[0-9]+(\.[0-9]+)?' strings-raw.txt

# User-Agent strings
grep -i "user-agent" strings-raw.txt
# Example: "MyApp/1.0 Alamofire/5.8.1"
```

### From Metadata

```bash
# CocoaPods metadata (if present)
grep -r "COCOAPODS" strings-raw.txt
# Example: "COCOAPODS: 1.12.0"

# SPM package metadata
grep -r "swift-package-manager" strings-raw.txt
```

## Known CVE Database

When a version is identified, cross-reference with known vulnerabilities:

| SDK | Vulnerable Versions | CVE | Impact |
|-----|-------------------|-----|--------|
| AFNetworking | < 3.0 | CVE-2016-4117 | SSL pinning bypass |
| AFNetworking | < 2.6.0 | CVE-2015-3996 | MITM via cert validation |
| Alamofire | < 5.0.0 | CVE-2020-36241 | ServerTrust bypass |
| SDWebImage | < 5.6.0 | CVE-2020-28026 | Path traversal in cache |
| Realm | < 5.0 | CVE-2019-13143 | Unencrypted local DB |
| Facebook SDK | < 9.0 | CVE-2020-25375 | Token exposure in logs |
| Branch | < 0.31.0 | CVE-2019-12967 | Open redirect |
| CryptoSwift | < 1.3.0 | GHSA-8265 | HMAC timing attack |
| TrustKit | < 1.6.0 | CVE-2018-16491 | Pinning bypass |
| Stripe | < 21.0 | CVE-2021-32977 | Card data logging in debug |
| Auth0 | < 1.30 | CVE-2020-15119 | ID token bypass |

## LLM Analysis Guidelines

When analyzing SDK detection results:

1. **Assess attack surface** — Each SDK is a potential vector. More SDKs = larger attack surface
2. **Check for outdated versions** — Cross-reference with CVE database
3. **Verify API key safety** — Determine if exposed keys are client-safe or server-only
4. **Map data flow** — Understand what data each SDK collects and where it goes
5. **Check for conflicts** — Multiple analytics/tracking SDKs may indicate over-collection
6. **Evaluate necessity** — Unused SDKs increase risk without benefit
7. **Privacy compliance** — Verify ATT (App Tracking Transparency) for tracking SDKs
