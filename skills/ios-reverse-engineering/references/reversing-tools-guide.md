# CLI Reversing Tools Guide

Guide for using CLI-based reverse engineering tools (radare2/rizin, Ghidra headless) to perform deep binary analysis on iOS Mach-O binaries. The output from these tools is fed to the LLM for automated analysis.

## Tool Overview

| Tool | Purpose | Strengths |
|------|---------|-----------|
| **radare2/rizin** | Interactive RE framework | Fast disassembly, cross-references, function analysis |
| **Ghidra (headless)** | NSA's RE framework | Decompilation to pseudo-C, type recovery, advanced analysis |
| **ipsw** | Apple-focused toolkit | Class-dump, dyld cache, Apple-specific Mach-O features |
| **otool** | macOS native | Load commands, linked libraries, basic disassembly |
| **nm** | Symbol listing | Quick symbol enumeration |

## radare2 / rizin

radare2 (r2) and rizin (rz) are open-source reverse engineering frameworks. rizin is a fork with improved UX. Commands are nearly identical.

### Installation

```bash
# macOS
brew install radare2
# or
brew install rizin

# Linux
apt install radare2
# or
apt install rizin
```

### Non-interactive CLI commands

All r2/rz commands can be run non-interactively for LLM analysis:

```bash
# Analyze and list all functions
r2 -q -c "aaa; aflj" binary > functions.json

# List all strings with cross-references
r2 -q -c "aaa; izj" binary > strings.json

# List imports
r2 -q -c "iij" binary > imports.json

# List exports
r2 -q -c "iEj" binary > exports.json

# List sections
r2 -q -c "iSj" binary > sections.json

# List classes (ObjC)
r2 -q -c "icj" binary > classes.json

# List methods (ObjC)
r2 -q -c "ic" binary > methods.txt

# Disassemble a function
r2 -q -c "aaa; s sym.func_name; pdf" binary > func_disasm.txt

# Cross-references to a function
r2 -q -c "aaa; s sym.func_name; axtj" binary > xrefs.json

# Cross-references to a string
r2 -q -c 'aaa; / https://api.; axtj @@ hit*' binary > string_xrefs.json

# Decompile a function (with r2ghidra plugin)
r2 -q -c "aaa; s sym.func_name; pdg" binary > func_decompiled.c

# Find all URL strings and their references
r2 -q -c "aaa; izqq~http" binary > urls.txt

# Binary info (architecture, endianness, etc.)
r2 -q -c "ij" binary > binary_info.json

# List all symbols
r2 -q -c "isj" binary > symbols.json

# Entropy analysis (detect packed/encrypted sections)
r2 -q -c "p=ej" binary > entropy.json
```

### rizin equivalents

```bash
# rizin uses the same commands with `rz-bin` for static info
rz-bin -I binary              # Binary info
rz-bin -z binary              # Strings
rz-bin -i binary              # Imports
rz-bin -E binary              # Exports
rz-bin -c binary              # Classes
rz-bin -S binary              # Sections

# Interactive analysis (non-interactive mode)
rizin -q -c "aaa; aflj" binary > functions.json
```

### Key analysis patterns for iOS

```bash
# Find Objective-C method implementations
r2 -q -c "aaa; ic~+URL\|+API\|+auth\|+login\|+token\|+secret\|+key\|+password\|+firebase\|+aws\|+azure\|+google" binary

# Find functions calling networking APIs
r2 -q -c "aaa; axt @ sym.imp.NSURLSession" binary

# Find functions referencing crypto
r2 -q -c "aaa; axt @ sym.imp.CCCrypt; axt @ sym.imp.CC_MD5; axt @ sym.imp.CC_SHA256" binary

# Trace call graph from a function
r2 -q -c "aaa; s sym.func_name; agCd" binary > callgraph.dot

# Find hardcoded IPs
r2 -q -c 'aaa; /x 0a\|/x c0a8\|izqq~[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]' binary
```

## Ghidra Headless Analyzer

Ghidra can run without its GUI for automated analysis.

### Installation

```bash
# macOS (requires JDK 17+)
brew install --cask ghidra

# Or download from https://ghidra-sre.org/
# Extract and add to PATH:
export GHIDRA_INSTALL_DIR=/path/to/ghidra

# Verify
${GHIDRA_INSTALL_DIR}/support/analyzeHeadless --help
```

### Headless analysis commands

```bash
GHIDRA="${GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
PROJECT_DIR="/tmp/ghidra_projects"
PROJECT_NAME="ios_analysis"

# Import and analyze a binary (creates project)
$GHIDRA "$PROJECT_DIR" "$PROJECT_NAME" \
  -import binary \
  -overwrite \
  -postScript DecompileAllFunctions.java output_dir/ \
  -scriptPath ${CLAUDE_PLUGIN_ROOT}/skills/ios-reverse-engineering/scripts/ghidra/

# Run a specific analysis script
$GHIDRA "$PROJECT_DIR" "$PROJECT_NAME" \
  -process binary \
  -postScript FindSecrets.java output_dir/ \
  -scriptPath ${CLAUDE_PLUGIN_ROOT}/skills/ios-reverse-engineering/scripts/ghidra/

# Export decompiled functions
$GHIDRA "$PROJECT_DIR" "$PROJECT_NAME" \
  -process binary \
  -postScript ExportDecompilation.java output_dir/decompiled.c

# Export function list
$GHIDRA "$PROJECT_DIR" "$PROJECT_NAME" \
  -process binary \
  -postScript ExportFunctions.java output_dir/functions.json
```

### Custom Ghidra scripts for iOS analysis

Place these in the ghidra scripts directory for automated analysis:

**Key scripts to create:**
- `DecompileAllFunctions.java` — Decompile all functions to pseudo-C
- `FindSecrets.java` — Search decompiled code for credentials
- `ExportAPICalls.java` — Find and export network API calls
- `ExportCryptoUsage.java` — Find crypto function usage
- `ExportStringXrefs.java` — Export strings with cross-references

## Combined Analysis Workflow

### Step 1: Static info extraction (fast)

```bash
# Quick overview with r2/rz
r2 -q -c "ij; iij; iEj; izj" binary > static_info.json

# Or with rizin
rz-bin -I -i -E -z binary > static_info.txt
```

### Step 2: Deep analysis (slower)

```bash
# Full function analysis
r2 -q -c "aaa; aflj" binary > functions.json

# String cross-references for URLs and secrets
r2 -q -c 'aaa; izqq~http\|api\|key\|secret\|token\|password\|firebase\|aws\|azure\|google' binary > interesting_strings.txt
```

### Step 3: Targeted decompilation

```bash
# Decompile specific functions of interest (with r2ghidra or Ghidra)
# Focus on: auth, network, crypto, config functions
r2 -q -c "aaa; s sym.objc.AuthService.login; pdg" binary > auth_decompiled.c
r2 -q -c "aaa; s sym.objc.NetworkManager.request; pdg" binary > network_decompiled.c
```

### Step 4: Cross-reference analysis

```bash
# Where are secrets used?
r2 -q -c 'aaa; iz~api_key; axtj @@ str.*api_key*' binary > secret_xrefs.json

# What calls the auth functions?
r2 -q -c "aaa; axtj @ sym.objc.AuthService.login" binary > auth_callers.json
```

## Output Formats for LLM Analysis

### JSON output (preferred)

Use `j` suffix on r2 commands for JSON:
- `aflj` → function list as JSON
- `izj` → strings as JSON
- `iij` → imports as JSON
- `axtj` → cross-references as JSON

### Structured text output

For non-JSON output, the reversing script structures it as:

```
=== SECTION: Function List ===
[function data]

=== SECTION: Strings Analysis ===
[string data]

=== SECTION: Cross References ===
[xref data]
```

## LLM Analysis Guidelines for Reversing Output

When analyzing disassembly/decompilation output, the LLM should:

1. **Identify security-sensitive functions** — auth, crypto, network, keychain
2. **Trace data flow** — how secrets move from storage to network calls
3. **Find hardcoded values** — constants used in crypto, auth, API calls
4. **Detect anti-tampering** — jailbreak detection, debugger detection, integrity checks
5. **Map the attack surface** — exported functions, URL handlers, IPC endpoints
6. **Identify obfuscation** — encrypted strings, dynamic class loading, reflection
7. **Flag dangerous patterns** — disabled cert pinning, weak crypto, hardcoded credentials

### Analysis report format

```markdown
## Deep Binary Analysis Report

### Functions of Interest
| Function | Purpose | Risk | Notes |
|----------|---------|------|-------|
| `AuthService.login` | User authentication | Medium | Sends credentials over HTTPS |
| `CryptoHelper.encrypt` | Data encryption | High | Uses hardcoded IV |

### Data Flow: Authentication
1. User enters credentials in `LoginViewController`
2. `AuthService.login()` called with email/password
3. Creates URLRequest to `POST /api/v1/auth/login`
4. Token stored in Keychain via `TokenManager.save()`

### Security Findings
- [CRITICAL] Hardcoded AES key at `0x100012340`
- [HIGH] Certificate pinning disabled in debug builds
- [MEDIUM] JWT token stored with `kSecAttrAccessibleAfterFirstUnlock`
```
