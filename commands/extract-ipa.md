---
allowed-tools: Bash, Read, Glob, Grep, Write, Edit
description: Extract an iOS IPA and analyze its structure
user-invocable: true
argument-hint: <path to IPA or .app bundle>
argument: path to IPA or .app bundle (optional)
---

# /extract-ipa

Extract an iOS application and perform initial structure analysis.

## Instructions

You are starting the iOS reverse engineering workflow. Follow these steps:

### Step 1: Get the target file

If the user provided a file path as an argument, use that. Otherwise, ask the user for the path to the IPA or .app bundle they want to analyze.

### Step 2: Check and install dependencies

Run the dependency check:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/skills/ios-reverse-engineering/scripts/check-deps.sh
```

Parse the output looking for `INSTALL_REQUIRED:` and `INSTALL_OPTIONAL:` lines.

**If required dependencies are missing**, install them one by one:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/skills/ios-reverse-engineering/scripts/install-dep.sh ipsw
```

The install script auto-detects the OS and installs via Homebrew when possible (`brew install blacktop/tap/ipsw`), or falls back to downloading from GitHub releases. If installation fails, the script prints exact manual instructions (exit code 2). Show those instructions to the user and stop.

**For optional dependencies** (`INSTALL_OPTIONAL:jtool2`, `INSTALL_OPTIONAL:frida`, etc.), ask the user if they want to install them.

After any installations, re-run `check-deps.sh` to verify. Do not proceed until all required dependencies pass.

### Step 3: Extract and analyze

Run the extraction script on the target file:

```bash
bash ${CLAUDE_PLUGIN_ROOT}/skills/ios-reverse-engineering/scripts/extract-ipa.sh <file>
```

For **IPA** files: the script extracts the ZIP, locates the .app bundle inside `Payload/`, runs `ipsw class-dump` on the main binary, and extracts metadata.

For **.app bundles**: the script works directly on the bundle.

Options:
- `-o <dir>` — Custom output directory
- `--no-classdump` — Skip class-dump (faster, metadata-only analysis)
- `--thin <arch>` — Extract a specific architecture from fat binaries (e.g., `arm64`)

For obfuscated apps (if the user mentions it or you detect mangled names):

```bash
bash ${CLAUDE_PLUGIN_ROOT}/skills/ios-reverse-engineering/scripts/extract-ipa.sh --swift-demangle <file>
```

### Step 4: Analyze structure

After extraction completes:

1. Read `Info.plist` from the output directory
2. List frameworks and embedded dylibs
3. Review the class-dump output for key classes (ViewControllers, networking, models)
4. Identify the app's main architecture pattern (MVC, MVVM, VIPER, etc.)
5. Report a summary to the user

### Step 5: Offer next steps

Tell the user what they can do next:
- **Trace call flows**: "I can follow the execution flow from ViewControllers to API calls"
- **Extract APIs**: "I can search for all HTTP endpoints (URLSession, Alamofire, Moya, AFNetworking) and document them"
- **Security audit**: "I can scan for ATS exceptions, cert pinning, keychain usage, jailbreak detection, and exposed secrets"
- **Cloud credential scan**: "I can deep-scan for leaked API keys and credentials (Firebase, AWS, GCP, Azure, Stripe, Twilio, etc.) and analyze each finding"
- **Deep binary reversing**: "I can use radare2/rizin to decompile functions, trace cross-references, and analyze crypto/auth/network code at the assembly level"
- **Swift/ObjC analysis**: "I can trace Swift/Objective-C class hierarchies and protocol conformances"
- **Generate report**: "I can generate a full Markdown report of all findings"
- **Analyze specific classes**: "Point me to a specific class or feature to analyze"

Refer to the full skill documentation in `${CLAUDE_PLUGIN_ROOT}/skills/ios-reverse-engineering/SKILL.md` for the complete workflow.
