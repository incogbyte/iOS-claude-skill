# Call Flow Analysis

Techniques for tracing execution flows in iOS applications, from entry points down to network calls.

## 1. Start from Info.plist and the App Entry Point

The entry point for iOS apps is either `AppDelegate` or a SwiftUI `@main App` struct.

```bash
# Find AppDelegate
grep -rn 'AppDelegate\|UIApplicationDelegate\|application.*didFinishLaunching' output/

# Find SwiftUI App entry
grep -rn '@main\|WindowGroup\|App.*body.*Scene' output/

# Find SceneDelegate (iOS 13+)
grep -rn 'SceneDelegate\|UIWindowSceneDelegate\|scene.*willConnectTo' output/
```

## 2. Follow the iOS App Lifecycle

Typical call chain from UI to network:

```
AppDelegate.application(_:didFinishLaunchingWithOptions:)
  -> Setup networking client, base URL, DI
  -> Set root ViewController

ViewController.viewDidLoad()
  -> Setup UI
  -> Bind ViewModel / Configure Presenter
  -> button.addTarget(self, action: #selector(buttonTapped))
    -> buttonTapped()
      -> viewModel.login(email, password)
        -> apiService.login(request)
          -> URLSession.dataTask / AF.request
            -> HTTP request
```

Key lifecycle methods to search:

```bash
grep -rn 'viewDidLoad\|viewWillAppear\|viewDidAppear\|didFinishLaunching\|willConnectTo' output/
```

## 3. Identify User Action Handlers

User interactions trigger API calls. Common patterns:

```bash
# Target-Action
grep -rn 'addTarget\|@IBAction\|@objc.*func\|#selector\|Selector(' output/

# Gesture recognizers
grep -rn 'UITapGestureRecognizer\|UISwipeGestureRecognizer\|addGestureRecognizer' output/

# Table/Collection view delegates
grep -rn 'didSelectRowAt\|didSelectItemAt\|tableView.*didSelect\|collectionView.*didSelect' output/

# SwiftUI actions
grep -rn 'Button.*action\|onTapGesture\|\.onSubmit\|\.task\s*{' output/

# Navigation
grep -rn 'pushViewController\|present(\|performSegue\|NavigationLink\|\.sheet(\|\.fullScreenCover' output/
```

## 4. AppDelegate / SceneDelegate Initialization

The app delegate initializes global singletons (HTTP clients, DI frameworks, analytics):

```bash
# Find AppDelegate class
grep -rn 'class.*AppDelegate\|@interface.*AppDelegate' output/

# Check didFinishLaunching for initialization
grep -rn 'didFinishLaunchingWithOptions\|didFinishLaunching' output/

# Find service setup
grep -rn 'configure(\|setup(\|initialize(\|registerDefaults\|setupNetworking\|configureAPI' output/
```

Look for:
- URLSession/Alamofire/AFNetworking client setup
- Base URL configuration
- Dependency injection container setup (Swinject, etc.)
- Firebase/analytics initialization
- Push notification registration

## 5. Dependency Injection & Service Location

### Swinject

```bash
# Container registration
grep -rn 'Container\|\.register(\|\.resolve(\|Assembler\|Assembly' output/

# Auto-registration
grep -rn 'SwinjectStoryboard\|SwinjectAutoregistration' output/
```

### Manual DI (Constructor Injection)

```bash
# Init with dependencies
grep -rn 'init(\|convenience init' output/ | grep -i 'service\|client\|api\|network\|repository'

# Shared/singleton patterns
grep -rn '\.shared\|\.default\|static let\|static var.*=\|getInstance\|sharedInstance' output/
```

### Service Locator

```bash
grep -rn 'ServiceLocator\|Container\|Resolver\|Injected\|@Inject' output/
```

## 6. Swift Concurrency (async/await) Flow

Modern iOS apps use structured concurrency for network calls.

### ViewController → ViewModel → Service

```swift
// ViewController
class LoginViewController: UIViewController {
    let viewModel: LoginViewModel

    @IBAction func loginTapped() {
        Task {
            await viewModel.login(email: emailField.text, password: passwordField.text)
        }
    }
}

// ViewModel
class LoginViewModel: ObservableObject {
    let authService: AuthService
    @Published var state: LoginState = .idle

    func login(email: String, password: String) async {
        state = .loading
        do {
            let token = try await authService.login(email: email, password: password)
            state = .success(token)
        } catch {
            state = .error(error)
        }
    }
}

// Service
class AuthService {
    func login(email: String, password: String) async throws -> AuthToken {
        var request = URLRequest(url: baseURL.appendingPathComponent("/auth/login"))
        request.httpMethod = "POST"
        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode(AuthToken.self, from: data)
    }
}
```

### Key search patterns

```bash
# Task creation (entry point for async work)
grep -rn 'Task\s*{\|Task\.detached' output/

# Async function definitions
grep -rn 'func.*async\s\+throws\?\s\+->' output/

# Await calls
grep -rn 'try\?\s\+await\|await\s' output/

# @MainActor (UI thread)
grep -rn '@MainActor\|MainActor\.run' output/
```

## 7. Combine Flow

```bash
# Published properties (state source)
grep -rn '@Published\|CurrentValueSubject\|PassthroughSubject' output/

# Sink subscribers (consumption point)
grep -rn '\.sink\s*{\|\.sink(receiveCompletion:\|\.assign(to:' output/

# Scheduling
grep -rn '\.receive(on:\s*DispatchQueue\.main\|\.receive(on:\s*RunLoop\.main' output/

# Combine + URLSession
grep -rn 'dataTaskPublisher\|\.decode(type:' output/

# Store subscriptions
grep -rn '\.store(in:\|cancellables\|AnyCancellable\|Set<AnyCancellable>' output/
```

### Typical Combine chain

```
ViewController subscribes to viewModel.$state
  -> viewModel.login() is called
    -> authService.loginPublisher()
      -> URLSession.dataTaskPublisher(for: request)
        .decode(type: AuthToken.self, decoder: JSONDecoder())
        .receive(on: DispatchQueue.main)
        .sink(receiveCompletion:, receiveValue:)
```

## 8. RxSwift Flow

```bash
# Observable creation
grep -rn '\.rx\.\|Observable\.create\|Single\.create\|\.asObservable' output/

# Subscription (consumption)
grep -rn '\.subscribe(\|\.bind(to:\|\.drive(\|disposed(by:' output/

# DisposeBag (lifecycle)
grep -rn 'DisposeBag\|disposeBag' output/

# Schedulers
grep -rn 'MainScheduler\|ConcurrentDispatchQueueScheduler\|\.observe(on:\|\.subscribe(on:' output/
```

## 9. Completion Handler (Callback) Flow

Traditional pattern in Objective-C and older Swift:

```bash
# Completion handlers
grep -rn 'completion:\|completionHandler:\|callback:\|handler:\|block:' output/

# Typical patterns
grep -rn '@escaping\s*(\|void\s*(^\?\s*(' output/

# GCD dispatch
grep -rn 'DispatchQueue\.main\.async\|DispatchQueue\.global\|dispatch_async' output/
```

### Typical callback chain

```
ViewController.loginButtonTapped()
  -> APIClient.login(email:password:completion:)
    -> URLSession.dataTask(with:completionHandler:)
      -> DispatchQueue.main.async { completion(result) }
```

## 10. Find Constants and Configuration

Hardcoded values in iOS apps:

```bash
# Base URLs
grep -rni 'baseURL\|base_url\|apiURL\|api_url\|serverURL\|server_url\|kAPI\|kBase' output/

# API keys
grep -rni 'api[_-]\?key\|client[_-]\?id\|app[_-]\?key\|secret' output/

# Configuration files
grep -rn '\.plist\|\.json\|\.config\|Configuration\|Environment\|Config\.' output/

# UserDefaults keys
grep -rn 'UserDefaults\|NSUserDefaults\|standardUserDefaults\|\.set(\|\.string(forKey:\|\.object(forKey:' output/

# Build configuration
grep -rni 'BUILD_CONFIG\|CONFIGURATION\|ENVIRONMENT\|STAGING\|PRODUCTION\|DEVELOPMENT' output/

# Keychain stored config
grep -rn 'SecItemCopyMatching\|kSecAttrAccount' output/
```

## 11. Navigating Obfuscated Code

When code is obfuscated (SwiftShield, iXGuard, etc.):

### What gets obfuscated
- Class names → random strings
- Method names (Swift, not Objective-C selectors)
- Property names
- Module names

### What does NOT get obfuscated
- **String literals** — URLs, keys, error messages remain readable
- **UIKit/SwiftUI class names** — `UIViewController`, `View`, `Button` keep their names
- **System framework APIs** — Foundation, UIKit, etc. retain names
- **Objective-C selectors** — must be preserved for runtime message dispatch
- **Protocol conformances** — often preserved for runtime
- **Bundle resources** — storyboard names, asset names, file names
- **Info.plist contents** — bundle ID, URL schemes, ATS config
- **Entitlements** — must be valid for code signing

### Strategy for obfuscated apps

1. **Start from strings**: Search `strings-raw.txt` for URLs, error messages, and known constants
2. **Start from UIKit subclasses**: ViewControllers registered in storyboards keep references
3. **Follow framework calls**: Alamofire's `.request()`, URLSession's `dataTask` are readable even when the calling class is obfuscated
4. **Use `otool -oV`**: Objective-C metadata includes class names and method selectors
5. **Cross-reference**: If an obfuscated class creates `URLSession` instances, it's a networking class

## 12. Tracing a Complete Call Flow: Example

Goal: Find how login works in an iOS app.

```
1. strings output → find "auth/login" URL → referenced in binary
2. class-dump → find class with URLSession or Alamofire usage → AuthService
3. class-dump → find who calls AuthService → LoginViewModel
4. class-dump → find LoginViewModel usage → LoginViewController
5. class-dump → find LoginViewController → has loginButtonTapped: method
6. Follow: LoginViewController.loginButtonTapped → LoginViewModel.login → AuthService.login → POST /auth/login
```

Result: `LoginViewController → LoginViewModel → AuthService → POST /auth/login`

## 13. Tools and Commands Summary

| Goal | Command |
|---|---|
| Find entry point | `grep -rn 'AppDelegate\|@main' output/` |
| Find lifecycle methods | `grep -rn 'viewDidLoad\|viewWillAppear' output/` |
| Find button handlers | `grep -rn 'addTarget\|@IBAction\|#selector' output/` |
| Find DI setup | `grep -rn 'Container\|\.register\|\.shared' output/` |
| Find async calls | `grep -rn 'Task\s*{\|await\s' output/` |
| Find Combine sinks | `grep -rn '\.sink\s*{\|\.assign(to:' output/` |
| Find RxSwift subscriptions | `grep -rn '\.subscribe(\|disposed(by:' output/` |
| Find completion handlers | `grep -rn 'completion:\|@escaping' output/` |
| Find constants | `grep -rni 'baseURL\|api_key' output/` |
| Find usages of a class | `grep -rn 'ClassName' output/` |
| Follow a string | `grep -rn '"some text"' output/` |
| Find linked frameworks | `otool -L binary` |
| List all symbols | `nm binary \| swift demangle` |
