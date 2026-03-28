# Anti-Tampering & Protection Patterns Guide

Comprehensive reference for detecting and analyzing security protections, anti-tampering mechanisms, obfuscation, and anti-debugging techniques in iOS applications.

## Protection Categories

### 1. Obfuscation

Code obfuscation makes reverse engineering harder by transforming code to be difficult to understand while preserving functionality.

#### Known iOS Obfuscation Tools

| Tool | Vendor | Detection Indicators |
|------|--------|---------------------|
| **iXGuard** | GuardSquare | `iXGuard`, `GuardSquare` strings; heavily renamed classes |
| **SwiftShield** | Open source | `SwiftShield` strings; renamed Swift classes |
| **Obfuscator-LLVM** | Open source | Control flow flattening; switch-based dispatch; bogus control flow |
| **Arxan/TransformIT** | Digital.ai | `Arxan`, `TransformIT`, `digital.ai` strings |
| **DexProtector** | Licel | `liprotector`, `dexprotect` strings |
| **PreEmptive** | PreEmptive Solutions | Dotfuscator-style patterns |

#### Obfuscation Indicators

**Class/Method Name Obfuscation:**
```bash
# Count short/random class names (obfuscation indicator)
find class-dump/ -name "*.h" -exec basename {} .h \; | grep -cE '^[a-zA-Z]{1,3}$|^[a-zA-Z][0-9]+$'

# Compare against total headers
find class-dump/ -name "*.h" | wc -l

# If ratio > 30%, likely obfuscated
```

**String Encryption:**
```bash
# Look for string decryption functions
grep -ri "decryptString\|unscramble\|deobfuscate\|xor.*key\|decode.*const" class-dump/ symbols.txt

# Unusually many base64-like strings (encrypted constants)
grep -cE '^[A-Za-z0-9+/]{40,}=*$' strings-raw.txt
```

**Control Flow Flattening (OLLVM):**
- Functions contain large switch statements dispatching to blocks
- State variable incremented/modified before each switch case
- All basic blocks at the same nesting level
- In decompiled code: `while(1) { switch(state) { case 0: ... state = 3; break; } }`

### 2. Anti-Debugging

Techniques to detect or prevent debugger attachment.

#### ptrace(PT_DENY_ATTACH)

The most common iOS anti-debug technique. Prevents debugger attachment:

```c
// Detection pattern
#include <sys/ptrace.h>
ptrace(PT_DENY_ATTACH, 0, 0, 0);  // Kills process if debugger attached

// Inline syscall variant (harder to hook)
// ARM64 assembly:
// mov x0, #31        (PT_DENY_ATTACH)
// mov x1, #0
// mov x2, #0
// mov x3, #0
// mov x16, #26       (ptrace syscall number)
// svc #0x80
```

**Search patterns:**
```bash
grep -i "ptrace\|PT_DENY_ATTACH" strings-raw.txt symbols.txt class-dump/**/*.h
```

#### sysctl-Based Detection

Queries kernel for debugger status:

```c
// Detection pattern
struct kinfo_proc info;
size_t size = sizeof(info);
int name[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
sysctl(name, 4, &info, &size, NULL, 0);
if (info.kp_proc.p_flag & P_TRACED) {
    // Debugger detected
}
```

**Search patterns:**
```bash
grep -i "sysctl\|CTL_KERN\|KERN_PROC\|P_TRACED\|kinfo_proc\|isDebugged\|debuggerAttached" strings-raw.txt symbols.txt
```

#### Timing-Based Detection

Measures execution time to detect single-stepping:

```c
// Detection pattern
uint64_t start = mach_absolute_time();
// ... code block ...
uint64_t elapsed = mach_absolute_time() - start;
if (elapsed > THRESHOLD) {
    // Likely being debugged (single-stepped)
}
```

#### Exception Port Detection

```c
// Detection pattern
mach_port_t port = MACH_PORT_NULL;
task_set_exception_ports(mach_task_self(), EXC_MASK_ALL, port,
                         EXCEPTION_DEFAULT, THREAD_STATE_NONE);
// If exception ports already set, debugger may be attached
```

#### Process Status Detection

```c
// getppid() — debugger becomes parent process
if (getppid() != 1) {
    // Parent PID is not launchd; might be debugger
}
```

### 3. Dylib Injection Prevention

Prevents runtime code injection via `DYLD_INSERT_LIBRARIES` and other mechanisms.

#### __RESTRICT Segment

A `__RESTRICT,__restrict` section in the Mach-O binary tells dyld to ignore `DYLD_INSERT_LIBRARIES`:

```bash
# Check for __RESTRICT segment
otool -l binary | grep -A2 "__RESTRICT"

# Expected output:
#   sectname __restrict
#   segname __RESTRICT
```

**How to add (at build time):**
In Xcode: Other Linker Flags: `-Wl,-sectcreate,__RESTRICT,__restrict,/dev/null`

#### DYLD Environment Variable Check

```objc
// Detection pattern
char *env = getenv("DYLD_INSERT_LIBRARIES");
if (env != NULL) {
    // Injection detected
}
```

#### Loaded Library Validation

```objc
// Detection pattern — enumerate loaded dylibs
uint32_t count = _dyld_image_count();
for (uint32_t i = 0; i < count; i++) {
    const char *name = _dyld_get_image_name(i);
    // Check against whitelist of expected libraries
    if (!isAllowedLibrary(name)) {
        // Unexpected library injection detected
    }
}
```

#### Substrate/Frida Detection

```bash
# Patterns for detecting hooking frameworks
grep -i "MobileSubstrate\|SubstrateLoader\|CydiaSubstrate\|MSHookFunction" strings-raw.txt
grep -i "frida\|FridaGadget\|frida-server\|gum-js-loop" strings-raw.txt
grep -i "fishhook\|rebind_symbols" symbols.txt
```

### 4. Integrity Verification

Runtime checks to detect binary modification.

#### Code Signing Validation

```objc
// Runtime code signing verification
SecStaticCodeRef staticCode;
OSStatus status = SecStaticCodeCreateWithPath(bundleURL, kSecCSDefaultFlags, &staticCode);
status = SecStaticCodeCheckValidity(staticCode, kSecCSCheckAllArchitectures, NULL);
if (status != errSecSuccess) {
    // Binary has been modified
}
```

#### Hash-Based Integrity

```c
// Self-hashing pattern
// 1. Read own binary from disk
// 2. Calculate hash of code sections
// 3. Compare against embedded expected hash
unsigned char hash[CC_SHA256_DIGEST_LENGTH];
CC_SHA256(codeSection, codeSize, hash);
if (memcmp(hash, expectedHash, CC_SHA256_DIGEST_LENGTH) != 0) {
    // Tampering detected
}
```

#### Team ID Verification

```objc
// Check signing team hasn't changed (prevents re-signing)
NSDictionary *info = [NSBundle mainBundle].infoDictionary;
NSString *teamID = info[@"TeamIdentifier"]; // From provisioning profile
if (![teamID isEqualToString:@"EXPECTED_TEAM_ID"]) {
    // Re-signed by different team
}
```

#### App Store Receipt Validation

```objc
// Verify app was purchased from App Store
NSURL *receiptURL = [[NSBundle mainBundle] appStoreReceiptURL];
NSData *receipt = [NSData dataWithContentsOfURL:receiptURL];
// Validate receipt signature, bundle ID, version
```

### 5. Jailbreak Detection

Checks for jailbroken environment.

#### File Existence Checks

Common jailbreak paths:

```
/Applications/Cydia.app
/Applications/Sileo.app
/Applications/Zebra.app
/Library/MobileSubstrate/MobileSubstrate.dylib
/bin/bash
/usr/sbin/sshd
/etc/apt
/private/var/lib/apt
/var/jb                          (rootless jailbreaks)
/var/binpack
/usr/lib/TweakInject
```

#### URL Scheme Checks

```objc
[[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://"]];
[[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"sileo://"]];
```

#### Sandbox Escape Test

```c
// fork() should fail in app sandbox
pid_t pid = fork();
if (pid >= 0) {
    // fork succeeded — jailbroken (sandbox escaped)
}
```

#### Known Detection Libraries

| Library | Detection Method |
|---------|-----------------|
| **IOSSecuritySuite** | Comprehensive Swift library |
| **DTTJailbreakDetection** | Simple file-based checks |
| **Talsec freeRASP** | Multi-layered detection |

### 6. Binary Encryption (FairPlay DRM)

#### Detection

```bash
# Check LC_ENCRYPTION_INFO
otool -l binary | grep -A4 "LC_ENCRYPTION_INFO"

# cryptid = 1 → encrypted
# cryptid = 0 → decrypted (dumped)
```

#### Impact on Analysis

- **Encrypted (cryptid=1)**: class-dump fails, strings extraction incomplete, disassembly of encrypted sections impossible
- **Decrypted (cryptid=0)**: Full analysis possible

#### Decryption Methods

For authorized security testing:
- **frida-ios-dump**: Dumps decrypted binary from memory at runtime
- **Clutch**: Legacy tool; may not work on newer iOS
- **bfdecrypt**: Frida-based decryption

## Protection Score Assessment

| Score | Level | Typical Indicators |
|-------|-------|-------------------|
| 15-20 | Heavily Protected | Obfuscation + anti-debug + injection prevention + integrity checks + jailbreak detection |
| 10-14 | Well Protected | Multiple protection layers; organized security approach |
| 5-9 | Moderately Protected | Some protections; gaps in coverage |
| 1-4 | Lightly Protected | Basic checks only (e.g., just jailbreak file paths) |
| 0 | Unprotected | No anti-tampering detected |

## LLM Analysis Guidelines

When analyzing protection detection results:

1. **Assess protection quality** — Are protections layered? Or single-point-of-failure?
2. **Identify bypass potential** — Single-function checks are easily patched; distributed checks are harder
3. **Check for consistency** — Protections that only run once at startup are weaker than continuous checks
4. **Evaluate obfuscation coverage** — Partial obfuscation may leave sensitive code readable
5. **Map detection vs response** — Does the app crash? Report to server? Degrade gracefully?
6. **Consider timing** — Are checks only at launch or periodic? Background checks are stronger
7. **Note server-side validation** — Client-side jailbreak detection can be bypassed; server-side attestation (DeviceCheck, App Attest) cannot
