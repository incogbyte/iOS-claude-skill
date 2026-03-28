# ipsw class-dump CLI Reference

`ipsw` (blacktop/ipsw) is a comprehensive iOS/macOS research toolkit. Its `class-dump` subcommand extracts Objective-C and Swift class information from Mach-O binaries, replacing the legacy `class-dump` tool with better Swift support and active maintenance.

## Installation

```bash
# Recommended: Homebrew
brew install blacktop/tap/ipsw

# Or download from GitHub releases
# https://github.com/blacktop/ipsw/releases
```

## Basic Usage

```bash
ipsw class-dump [options] <mach-o-file>
```

Input can be a Mach-O executable, `.dylib`, `.framework` binary, or an `.app` bundle.

## Key Options

| Option | Description |
|---|---|
| `-H` | Output headers to directory (one file per class) |
| `-o <dir>` | Output directory for headers (used with `-H`) |
| `--arch <arch>` | Select architecture from fat/universal binary (`arm64`, `x86_64`) |
| `--deps` | Dump imported private framework headers |
| `--headers` | Dump headers from a dyld_shared_cache |
| `--re <regex>` | Filter classes/protocols by regex |

## Common Workflows

### Dump all headers to a directory

```bash
ipsw class-dump -H -o ./headers/ MyApp.app
```

Produces one `.h` file per class in the `headers/` directory.

### Dump a specific binary

```bash
ipsw class-dump -H -o ./headers/ MyApp
```

### Dump from a fat binary (specific architecture)

```bash
ipsw class-dump --arch arm64 -H -o ./headers/ MyApp
```

### Dump a framework

```bash
ipsw class-dump -H -o ./headers/ MyFramework.framework
ipsw class-dump -H -o ./headers/ MyFramework.framework/MyFramework
```

### Dump all to stdout

```bash
ipsw class-dump MyApp.app > all-headers.h
```

### Filter by class name regex

```bash
ipsw class-dump --re "ViewController|API|Network|Service" MyApp.app
```

## Understanding the Output

### Objective-C Interface

```objc
@interface LoginViewController : UIViewController <UITextFieldDelegate>
{
    UITextField *_emailField;
    UITextField *_passwordField;
    LoginViewModel *_viewModel;
}

@property(nonatomic, retain) UITextField *emailField;
@property(nonatomic, retain) UITextField *passwordField;
@property(nonatomic, retain) LoginViewModel *viewModel;

- (void)loginButtonTapped:(id)arg1;
- (void)viewDidLoad;
- (void)setupUI;
@end
```

Key information:
- **Superclass**: `UIViewController`
- **Protocols**: `UITextFieldDelegate`
- **Instance variables**: Types and names
- **Properties**: Public interface with attributes
- **Methods**: Selectors with argument types

### Objective-C Protocol

```objc
@protocol APIServiceProtocol <NSObject>
- (void)fetchUserWithId:(NSString *)arg1 completion:(void (^)(User *, NSError *))arg2;
- (void)loginWithEmail:(NSString *)arg1 password:(NSString *)arg2 completion:(void (^)(AuthToken *, NSError *))arg3;
@end
```

### Objective-C Category

```objc
@interface NSString (URLEncoding)
- (NSString *)urlEncodedString;
- (NSDictionary *)queryParameters;
@end
```

## Working with Swift Binaries

`ipsw class-dump` has improved support for Swift compared to the legacy `class-dump` tool.

### What ipsw class-dump shows for Swift

- Classes that subclass `NSObject` or Objective-C classes
- `@objc` exposed methods and properties
- Swift protocols marked as `@objc`
- Bridged types
- Better Swift metadata extraction than legacy class-dump

### What may still be limited

- Pure Swift structs and enums
- Swift protocols without `@objc`
- Generic types
- Extensions on Swift types
- Property wrappers

### Alternatives for deeper Swift analysis

```bash
# Use nm + swift-demangle for full symbol listing
nm MyApp | swift demangle > symbols.txt

# Use dsdump for Swift-aware class dumping
dsdump --swift MyApp
dsdump --objc MyApp

# Filter for specific patterns
nm MyApp | swift demangle | grep -i "api\|network\|service\|client"
```

## Other ipsw Features Useful for Reverse Engineering

Beyond class-dump, `ipsw` provides many other analysis capabilities:

```bash
# Analyze dyld shared cache
ipsw dyld info /path/to/dyld_shared_cache

# List images in dyld shared cache
ipsw dyld list /path/to/dyld_shared_cache

# Extract a dylib from dyld shared cache
ipsw dyld extract /path/to/dyld_shared_cache <dylib>

# Dump Mach-O info
ipsw macho info MyApp

# List Mach-O segments and sections
ipsw macho seg MyApp

# Dump symbols
ipsw macho sym MyApp

# Dump imports
ipsw macho imp MyApp

# Dump Objective-C info
ipsw macho objc MyApp

# Disassemble
ipsw disass MyApp --symbol <symbol_name>
```

## Analyzing Obfuscated Binaries

Some iOS apps use obfuscation tools (iXGuard, SwiftShield, etc.).

### What gets obfuscated
- Class names -> random strings
- Method names (except Objective-C selectors used at runtime)
- Property names

### What does NOT get obfuscated
- **String constants** — URLs, keys, error messages remain readable
- **UIKit class names** — `UIViewController`, `UITableView`, etc.
- **Framework method names** — system APIs keep their names
- **Protocol conformances** — often preserved for runtime use
- **Selector names** — Objective-C selectors must be preserved for message dispatch
- **Bundle identifiers** — in Info.plist
- **Entitlements** — must be valid for code signing

### Strategy for obfuscated apps

1. Use `strings` to find URLs, keys, and readable content
2. Follow UIKit subclass hierarchies (ViewControllers are usually named in storyboards)
3. Look at linked frameworks for known networking libraries
4. Search for selector names — `@selector(didReceiveData:)` etc.
5. Use Frida for dynamic analysis at runtime

## Mach-O Analysis with otool

Complement ipsw class-dump with otool for binary-level analysis:

```bash
# List linked libraries (what frameworks does the app use?)
otool -L MyApp

# List load commands (segments, sections, code signing info)
otool -l MyApp

# Dump Objective-C class list
otool -oV MyApp

# Disassemble text section
otool -tV MyApp

# Show data section (string constants, etc.)
otool -s __DATA __objc_methnames MyApp | strings
```

## Useful Patterns for Reverse Engineering

### Finding the networking stack

```bash
# Check linked frameworks
otool -L MyApp | grep -i "alamofire\|afnetworking\|moya\|urlsession"

# Search ipsw class-dump output
grep -rl "URLSession\|NSURLSession\|Alamofire\|AFHTTPSessionManager" headers/
grep -rl "APIService\|NetworkManager\|HTTPClient\|APIClient" headers/

# Find Retrofit-like patterns (Moya TargetType)
grep -rl "TargetType\|baseURL\|path\|method\|task\|headers" headers/
```

### Finding ViewControllers

```bash
# List all ViewControllers
ls headers/ | grep -i "controller\|VC"

# Find which ViewControllers reference networking
grep -rl "viewModel\|presenter\|interactor\|service\|api\|network" headers/*Controller* headers/*VC*
```

### Finding data models

```bash
# Codable/NSCoding conformances
grep -rl "NSCoding\|Codable\|Decodable\|Encodable\|NSSecureCoding" headers/

# Models with JSON keys
grep -rl "CodingKeys\|coding[Kk]ey" headers/
```
