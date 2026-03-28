# Setup Guide: Dependencies for iOS Reverse Engineering

## Xcode Command Line Tools (otool, strings, codesign, lipo, nm)

Most analysis tools are included with Xcode Command Line Tools on macOS.

### macOS

```bash
xcode-select --install
```

### Verify

```bash
otool --version
strings --version
codesign --help
```

> **Note**: On Linux, `otool` is not available. Use `objdump` or `rabin2` as alternatives. The `strings` command is part of `binutils`.

---

## ipsw (primary tool — includes class-dump)

`ipsw` (blacktop/ipsw) is a comprehensive iOS/macOS research toolkit that includes class-dump functionality, dyld shared cache analysis, Mach-O inspection, and much more. It replaces the legacy `class-dump` tool with better Swift support and active maintenance.

### Option 1: Homebrew (recommended)

```bash
brew install blacktop/tap/ipsw
```

### Option 2: Download from GitHub releases

Download the latest release for your platform from:
https://github.com/blacktop/ipsw/releases

```bash
# macOS arm64 example
curl -LO https://github.com/blacktop/ipsw/releases/latest/download/ipsw_macOS_arm64.tar.gz
tar xzf ipsw_macOS_arm64.tar.gz
mv ipsw /usr/local/bin/
```

### Verify

```bash
ipsw version
```

### Key features

- **class-dump**: Extract Objective-C and Swift headers (`ipsw class-dump`)
- **dyld shared cache**: Analyze and extract from dyld shared caches (`ipsw dyld`)
- **Mach-O analysis**: Inspect segments, symbols, imports, ObjC metadata (`ipsw macho`)
- **Disassembly**: Disassemble functions and symbols (`ipsw disass`)
- **IPSW firmware**: Download and analyze iOS firmware files (`ipsw download`)

### Limitations

- **Encrypted binaries**: Cannot process encrypted (FairPlay DRM) binaries. Decrypt first (e.g., via `frida-ios-dump`, `Clutch`, or `bfdecrypt` on a jailbroken device).
- **Pure Swift apps**: While ipsw has better Swift support than legacy class-dump, some pure Swift types may not appear. Use `nm` + `swift-demangle` for full symbol analysis.

---

## jtool2 (optional, recommended)

jtool2 is a comprehensive Mach-O analyzer, replacement for otool, nm, and codesign.

### Download

```bash
# Download from the official source
curl -o jtool2.tgz http://www.newosxbook.com/tools/jtool2.tgz
mkdir -p ~/jtool2
tar xzf jtool2.tgz -C ~/jtool2
cp ~/jtool2/jtool2 /usr/local/bin/
```

### Verify

```bash
jtool2 --help
```

### Key features over otool

- Color-coded output
- Better symbol resolution
- Entitlements extraction
- Code signature analysis
- Disassembly with symbolic references

---

## Frida (optional)

Frida is a dynamic instrumentation toolkit for runtime analysis of iOS apps.

### Install

```bash
pip3 install frida-tools
```

### Verify

```bash
frida --version
```

### Usage for iOS

Requires a jailbroken device with `frida-server` running, or a repackaged app with `FridaGadget.dylib`:

```bash
# List running processes on USB device
frida-ps -U

# Attach to an app
frida -U com.example.app

# Run a script
frida -U -f com.example.app -l hook-script.js
```

---

## libimobiledevice (optional)

Tools for communicating with iOS devices without iTunes/Finder.

### macOS

```bash
brew install libimobiledevice ideviceinstaller
```

### Linux

```bash
# Ubuntu/Debian
sudo apt install libimobiledevice-utils ideviceinstaller

# Fedora
sudo dnf install libimobiledevice-utils
```

### Verify

```bash
ideviceinfo --help
```

### Useful commands

```bash
# Get device info
ideviceinfo

# List installed apps
ideviceinstaller -l

# Install an IPA
ideviceinstaller -i app.ipa

# Pull crash logs
idevicecrashreport -e ./crashlogs/
```

---

## Optional Tools

### swift-demangle

Demangles Swift symbols to human-readable names. Included with the Swift toolchain.

```bash
# macOS (included with Xcode)
swift demangle '_$s7MyClass4nameSSvg'
# Output: MyClass.name.getter

# Or pipe symbols
nm binary | swift demangle
```

### dsdump (modern class-dump alternative)

Better support for Swift and modern Objective-C:

```bash
brew install DerekSelander/brew/dsdump

# Dump Swift classes
dsdump --swift MyApp

# Dump Objective-C classes
dsdump --objc MyApp
```

### radare2 / rizin

Open-source reverse engineering framework:

```bash
brew install radare2
# Or the modern fork:
brew install rizin

# Analyze a binary
r2 MyApp
# or
rizin MyApp
```

### Ghidra

NSA's open-source reverse engineering suite with iOS support:

1. Download from https://ghidra-sre.org/
2. Extract and run
3. Import the Mach-O binary
4. Auto-analyze

Ghidra provides full decompilation to C-like pseudocode, which is invaluable for complex analysis.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `ipsw: command not found` | Install via `brew install blacktop/tap/ipsw` or add to PATH |
| ipsw class-dump outputs nothing | Binary may be encrypted (FairPlay). Decrypt first on jailbroken device |
| ipsw class-dump limited Swift output | Use `dsdump --swift` or `nm` + `swift-demangle` for deeper analysis |
| `otool: command not found` | Install Xcode Command Line Tools: `xcode-select --install` |
| Fat binary issues | Use `lipo -thin arm64 binary -output binary-arm64` to extract one arch |
| Encrypted IPA from App Store | Must decrypt on jailbroken device or use `frida-ios-dump` |
| `codesign` permission denied | May need to run with `sudo` or adjust entitlements |
| jtool2 won't run on macOS | Right-click → Open, or `xattr -d com.apple.quarantine jtool2` |
| Frida can't find device | Ensure `frida-server` is running on jailbroken device, or use `frida-gadget` |
| IPA won't unzip | Rename to `.zip` and try again, or use `7z x app.ipa` |
