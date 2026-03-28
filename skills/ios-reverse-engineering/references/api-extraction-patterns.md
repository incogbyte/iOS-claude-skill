# API Extraction Patterns

Patterns and grep commands for finding HTTP API calls in iOS applications. These patterns work on class-dump output, extracted strings, and any source code found in the app bundle.

## URLSession / NSURLSession

URLSession is the foundation-level HTTP client in iOS.

### Patterns to search for

```bash
# URLSession creation and usage
grep -rn 'URLSession\|NSURLSession\|URLSessionConfiguration\|defaultSessionConfiguration\|ephemeralSessionConfiguration' output/

# Data tasks
grep -rn 'dataTask\|uploadTask\|downloadTask\|\.resume()' output/

# Request construction
grep -rn 'URLRequest\|NSMutableURLRequest\|httpMethod\|httpBody\|setValue.*forHTTPHeaderField\|addValue.*forHTTPHeaderField' output/

# URL construction
grep -rn 'URLComponents\|NSURLComponents\|queryItems\|URLQueryItem\|appendingPathComponent' output/

# Response handling
grep -rn 'URLResponse\|HTTPURLResponse\|statusCode\|allHeaderFields' output/

# Session delegate
grep -rn 'URLSessionDelegate\|URLSessionDataDelegate\|URLSessionTaskDelegate\|didReceiveData\|didCompleteWithError' output/
```

### Typical URLSession call

```swift
var request = URLRequest(url: URL(string: "https://api.example.com/users")!)
request.httpMethod = "POST"
request.setValue("application/json", forHTTPHeaderField: "Content-Type")
request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
request.httpBody = try JSONEncoder().encode(body)

URLSession.shared.dataTask(with: request) { data, response, error in
    // handle response
}.resume()
```

## Alamofire

Alamofire is the most popular third-party HTTP library for iOS.

### Patterns to search for

```bash
# Request methods
grep -rn 'AF\.\|Session\.default\|\.request(\|\.upload(\|\.download(' output/

# Response handling
grep -rn '\.responseDecodable\|\.responseJSON\|\.responseData\|\.responseString\|\.response(' output/

# Configuration
grep -rn 'HTTPMethod\.\|\.get\|\.post\|\.put\|\.delete\|\.patch' output/

# Parameter encoding
grep -rn 'JSONEncoding\|URLEncoding\|ParameterEncoding\|JSONParameterEncoder\|URLEncodedFormParameterEncoder' output/

# Interceptors
grep -rn 'RequestInterceptor\|RequestAdapter\|RequestRetrier\|adapt\|retry' output/

# Server trust (cert pinning)
grep -rn 'ServerTrustManager\|ServerTrustEvaluating\|PinnedCertificatesTrustEvaluator\|PublicKeysTrustEvaluator\|DisabledTrustEvaluator' output/

# Validation
grep -rn '\.validate(\|\.validate(statusCode:' output/
```

### Typical Alamofire usage

```swift
AF.request("https://api.example.com/users/\(id)",
           method: .get,
           headers: ["Authorization": "Bearer \(token)"])
    .validate()
    .responseDecodable(of: User.self) { response in
        // handle response
    }
```

## AFNetworking (Objective-C, legacy)

```bash
# Session manager
grep -rn 'AFHTTPSessionManager\|AFURLSessionManager\|initWithBaseURL' output/

# Serializers
grep -rn 'AFHTTPRequestSerializer\|AFJSONRequestSerializer\|AFJSONResponseSerializer\|AFHTTPResponseSerializer' output/

# Reachability
grep -rn 'AFNetworkReachabilityManager\|startMonitoring\|reachabilityStatus' output/

# Security policy
grep -rn 'AFSecurityPolicy\|SSLPinningMode\|pinnedCertificates\|allowInvalidCertificates\|validatesDomainName' output/
```

### Typical AFNetworking usage

```objc
AFHTTPSessionManager *manager = [[AFHTTPSessionManager alloc] initWithBaseURL:[NSURL URLWithString:@"https://api.example.com"]];
manager.requestSerializer = [AFJSONRequestSerializer serializer];
[manager.requestSerializer setValue:@"Bearer token" forHTTPHeaderField:@"Authorization"];

[manager GET:@"/users" parameters:nil headers:nil progress:nil success:^(NSURLSessionDataTask *task, id responseObject) {
    // handle response
} failure:^(NSURLSessionDataTask *task, NSError *error) {
    // handle error
}];
```

## Moya

Moya is a type-safe networking abstraction over Alamofire.

```bash
# TargetType protocol (defines endpoints)
grep -rn 'TargetType\|baseURL\|\.path\|\.method\|\.task\|\.headers\|\.sampleData' output/

# Provider
grep -rn 'MoyaProvider\|\.request(\|\.rx\.request' output/

# Task types (how parameters are sent)
grep -rn '\.requestPlain\|\.requestData\|\.requestJSONEncodable\|\.requestParameters\|\.uploadMultipart' output/

# Plugins
grep -rn 'PluginType\|NetworkLoggerPlugin\|NetworkActivityPlugin' output/
```

### Typical Moya TargetType

```swift
enum UserAPI: TargetType {
    case getUser(id: String)
    case login(email: String, password: String)

    var baseURL: URL { URL(string: "https://api.example.com/v1")! }
    var path: String {
        switch self {
        case .getUser(let id): return "/users/\(id)"
        case .login: return "/auth/login"
        }
    }
    var method: Moya.Method {
        switch self {
        case .getUser: return .get
        case .login: return .post
        }
    }
}
```

## Swift Concurrency (async/await)

Modern iOS apps use structured concurrency.

```bash
# Async functions
grep -rn 'async\s\+throws\?\s\+->|async\s\+->' output/

# Await calls
grep -rn 'await\s' output/

# Task
grep -rn 'Task\s*{\|Task\.detached\|TaskGroup\|withTaskGroup\|withThrowingTaskGroup' output/

# AsyncSequence
grep -rn 'AsyncSequence\|AsyncStream\|AsyncThrowingStream\|for await\|for try await' output/

# Async URLSession
grep -rn 'URLSession.*\.data(\|\.bytes(\|\.upload(\|\.download(' output/
```

## Combine

```bash
# Publishers
grep -rn 'Publisher\|AnyPublisher\|PassthroughSubject\|CurrentValueSubject\|@Published' output/

# Subscribers
grep -rn '\.sink\s*{\|\.assign(to:\|Subscribers\.\|\.store(in:' output/

# Operators
grep -rn '\.map\s*{\|\.flatMap\|\.tryMap\|\.compactMap\|\.filter\|\.decode(\|\.eraseToAnyPublisher' output/

# URLSession + Combine
grep -rn 'dataTaskPublisher\|\.dataTaskPublisher(for:' output/

# Scheduling
grep -rn '\.receive(on:\|\.subscribe(on:\|DispatchQueue\.main\|RunLoop\.main' output/
```

## RxSwift / RxCocoa

```bash
# Observable types
grep -rn 'Observable<\|Single<\|Completable\|Maybe<\|Driver<\|Signal<\|BehaviorRelay\|PublishRelay' output/

# Subscription
grep -rn '\.subscribe(\|\.bind(to:\|\.drive(\|disposeBag\|DisposeBag\|disposed(by:' output/

# Operators
grep -rn '\.flatMap\|\.map\|\.filter\|\.withLatestFrom\|\.combineLatest\|\.merge\|\.zip' output/

# RxMoya
grep -rn '\.rx\.request\|\.rx\.requestWithProgress' output/
```

## GraphQL (Apollo iOS)

```bash
# Apollo Client
grep -rn 'ApolloClient\|ApolloStore\|NormalizedCache\|InMemoryNormalizedCache' output/

# Queries and mutations
grep -rn 'GraphQLQuery\|GraphQLMutation\|GraphQLSubscription' output/

# Operations
grep -rn '\.fetch(query:\|\.perform(mutation:\|\.subscribe(subscription:' output/

# Code generation types
grep -rn 'GraphQLSelectionSet\|GraphQLField\|GraphQLInputObject' output/

# Network transport
grep -rn 'NetworkTransport\|HTTPNetworkTransport\|WebSocketTransport\|SplitNetworkTransport' output/
```

## WebSocket

```bash
# Native URLSession WebSocket
grep -rn 'URLSessionWebSocketTask\|webSocketTask\|\.send(\|\.receive(\|WebSocketFrame' output/

# Starscream
grep -rn 'WebSocket\|WebSocketDelegate\|didReceive\|\.write(string:\|\.write(data:\|\.connect()' output/

# Socket.IO
grep -rn 'SocketManager\|SocketIOClient\|\.emit(\|\.on(\|\.connect()' output/

# Network.framework WebSocket
grep -rn 'NWConnection\|NWProtocolWebSocket\|NWEndpoint' output/

# WebSocket URLs
grep -rn 'wss\?://[^"]*"' output/
```

## gRPC

```bash
# gRPC client
grep -rn 'GRPCChannel\|ClientConnection\|GRPCManagedChannel\|CallOptions' output/

# Protobuf
grep -rn 'SwiftProtobuf\|GPBMessage\|Message\|GPBCodedInputStream' output/

# gRPC calls
grep -rn '\.makeUnaryCall\|\.makeServerStreamingCall\|\.makeBidirectionalStreamingCall' output/
```

## Hardcoded URLs and Secrets

```bash
# HTTP/HTTPS URLs
grep -rn '"https\?://[^"]*"' output/

# API keys and tokens
grep -rni 'api[_-]\?key\|api[_-]\?secret\|auth[_-]\?token\|bearer\|access[_-]\?token\|client[_-]\?secret' output/

# Base URL constants
grep -rni 'baseURL\|base_url\|apiURL\|api_url\|serverURL\|server_url\|ENDPOINT\|API_BASE\|kAPI' output/
```

## Security Patterns

### App Transport Security (ATS)

```bash
# ATS settings in Info.plist
grep -rn 'NSAppTransportSecurity\|NSAllowsArbitraryLoads\|NSExceptionDomains\|NSExceptionAllowsInsecureHTTPLoads' output/
```

### Certificate Pinning

```bash
# URLSession delegate pinning
grep -rn 'URLAuthenticationChallenge\|ServerTrust\|SecTrust\|SecCertificate\|SecTrustEvaluate' output/

# Alamofire pinning
grep -rn 'ServerTrustManager\|PinnedCertificatesTrustEvaluator\|PublicKeysTrustEvaluator\|ServerTrustEvaluating' output/

# TrustKit
grep -rn 'TrustKit\|TSKPinningValidator\|kTSKPublicKeyHashes\|kTSKEnforcePinning' output/

# AFNetworking pinning
grep -rn 'AFSecurityPolicy\|SSLPinningMode\|pinnedCertificates' output/
```

### Disabled Security (red flags)

```bash
# Dangerous: bypass certificate validation
grep -rn 'performDefaultHandling\|cancelAuthenticationChallenge\|continueWithoutCredential' output/
grep -rn 'DisabledTrustEvaluator\|disableEvaluation\|AllowAll\|trustAll\|insecure' output/
grep -rn 'allowInvalidCertificates.*YES\|allowInvalidCertificates.*true' output/
```

### Jailbreak Detection

```bash
# File-based detection
grep -rn 'Cydia\|/Applications/Cydia\.app\|/bin/bash\|/usr/sbin/sshd\|/etc/apt\|/private/var/lib/apt' output/

# URL scheme detection
grep -rn 'canOpenURL.*cydia\|cydia://' output/

# Dylib injection detection
grep -rn 'MobileSubstrate\|SubstrateLoader\|CydiaSubstrate\|DYLD_INSERT_LIBRARIES' output/

# Fork detection
grep -rn 'fork()\|isJailbroken\|jailbreak' output/
```

### Exposed Secrets

```bash
# Hardcoded passwords and keys
grep -rni 'password\s*=\s*"\|secret\s*=\s*"\|private[_-]\?key\|encryption[_-]\?key' output/

# Third-party API keys
grep -rni 'firebase[_-]\?key\|aws[_-]\?key\|google[_-]\?api\|maps[_-]\?key\|stripe[_-]\?key\|sendgrid\|twilio\|paypal' output/
```

### Crypto Usage

```bash
# CommonCrypto
grep -rn 'CCCrypt\|CC_MD5\|CC_SHA\|kCCAlgorithmAES\|kCCEncrypt\|kCCDecrypt\|CommonCrypto' output/

# CryptoKit (modern)
grep -rn 'CryptoKit\|AES\.GCM\|SHA256\|SHA512\|P256\|Curve25519\|HMAC\|SymmetricKey\|SecureEnclave' output/

# Security framework
grep -rn 'SecKey\|SecKeyCreateRandomKey\|SecKeyEncrypt\|SecKeyDecrypt\|kSecAttrKeyType' output/
```

### Keychain Usage

```bash
# Keychain API
grep -rn 'SecItemAdd\|SecItemCopyMatching\|SecItemUpdate\|SecItemDelete' output/

# Keychain attributes
grep -rn 'kSecClass\|kSecAttrAccount\|kSecValueData\|kSecAttrAccessible\|kSecAttrAccessGroup' output/

# Accessibility levels (security implications)
grep -rn 'kSecAttrAccessibleAlways\|kSecAttrAccessibleAfterFirstUnlock\|kSecAttrAccessibleWhenUnlocked\|kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly' output/

# Third-party keychain wrappers
grep -rn 'KeychainWrapper\|KeychainAccess\|SAMKeychain\|KeychainSwift\|Valet' output/
```

### Debug & Development Flags

```bash
grep -rni '#if\s*DEBUG\|isDebug\|debugMode\|staging\|dev[_-]\?mode\|enableLogging' output/
grep -rni 'NSLog\|print(\|os_log\|Logger\.\|\.debug(' output/
```

## Documentation Template

For each discovered API endpoint, document it using this template:

```markdown
### `METHOD /path/to/endpoint`

- **Source**: `MyApp.APIService` (class-dump header or strings reference)
- **Base URL**: `https://api.example.com/v1`
- **Full URL**: `https://api.example.com/v1/path/to/endpoint`
- **Path parameters**: `id` (String)
- **Query parameters**: `page` (Int), `limit` (Int)
- **Headers**:
  - `Authorization: Bearer <token>`
  - `Content-Type: application/json`
- **Request body**: `LoginRequest { email: String, password: String }`
- **Response type**: `Codable struct User`
- **Async pattern**: async/await / Combine / Completion handler / RxSwift
- **Notes**: Called from `LoginViewController.loginButtonTapped()`
```

## Search Strategy

1. Start with **strings extraction** — find URLs, API keys, and base URLs in the binary
2. Search **class-dump headers** — find network service classes and their method signatures
3. Check **linked frameworks** (`otool -L`) — identify Alamofire, AFNetworking, Moya, Apollo, etc.
4. Search for **URLSession usage** — catch any direct Foundation networking
5. Look for **WKWebView URLs** — some apps use hybrid web/native approaches
6. Search for **GraphQL operations** — catch apps using Apollo
7. Check **WebSocket connections** — find real-time communication endpoints
8. Run **security patterns** — identify ATS config, cert pinning, exposed secrets, jailbreak detection
