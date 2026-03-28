#!/usr/bin/env bash
# reversing-analyze.sh — Deep binary analysis using CLI reversing tools (radare2/rizin/Ghidra)
# Produces structured output for LLM analysis
set -euo pipefail

usage() {
  cat <<EOF
Usage: reversing-analyze.sh [OPTIONS] <binary>

Perform deep binary analysis on a Mach-O binary using CLI reversing tools.
Produces structured output optimized for LLM analysis.

Arguments:
  <binary>          Path to Mach-O binary, .dylib, or extracted binary from extract-ipa.sh

Options:
  -o, --output DIR      Output directory (default: <binary>-reversing)
  --tool TOOL           Force specific tool: r2, rizin, ghidra (default: auto-detect)
  --functions           List all functions with sizes and types
  --strings             Extract strings with cross-references
  --imports             List imported functions
  --exports             List exported functions
  --classes             List ObjC/Swift classes and methods
  --xrefs TARGET        Cross-references to/from TARGET (function name or address)
  --decompile FUNC      Decompile a specific function
  --decompile-pattern P Decompile all functions matching pattern
  --secrets             Focus on secret/credential-related functions
  --network             Focus on networking functions
  --crypto              Focus on cryptographic functions
  --auth                Focus on authentication functions
  --entropy             Analyze binary entropy (detect packing/encryption)
  --callgraph FUNC      Generate call graph for a function
  --all                 Run all analyses (default)
  --quick               Quick scan: functions + strings + imports only
  -h, --help            Show this help message

Tool detection priority: rizin > radare2 > ghidra-headless
If no tool is available, outputs guidance for installation.

Output:
  Structured text/JSON files in the output directory, ready for LLM analysis.
EOF
  exit 0
}

BINARY=""
OUTPUT_DIR=""
FORCE_TOOL=""
DO_FUNCTIONS=false
DO_STRINGS=false
DO_IMPORTS=false
DO_EXPORTS=false
DO_CLASSES=false
XREFS_TARGET=""
DECOMPILE_FUNC=""
DECOMPILE_PATTERN=""
DO_SECRETS=false
DO_NETWORK=false
DO_CRYPTO=false
DO_AUTH=false
DO_ENTROPY=false
CALLGRAPH_FUNC=""
DO_ALL=true
QUICK_MODE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output)         OUTPUT_DIR="$2"; shift 2 ;;
    --tool)              FORCE_TOOL="$2"; shift 2 ;;
    --functions)         DO_FUNCTIONS=true;  DO_ALL=false; shift ;;
    --strings)           DO_STRINGS=true;    DO_ALL=false; shift ;;
    --imports)           DO_IMPORTS=true;    DO_ALL=false; shift ;;
    --exports)           DO_EXPORTS=true;    DO_ALL=false; shift ;;
    --classes)           DO_CLASSES=true;    DO_ALL=false; shift ;;
    --xrefs)             XREFS_TARGET="$2";  DO_ALL=false; shift 2 ;;
    --decompile)         DECOMPILE_FUNC="$2"; DO_ALL=false; shift 2 ;;
    --decompile-pattern) DECOMPILE_PATTERN="$2"; DO_ALL=false; shift 2 ;;
    --secrets)           DO_SECRETS=true;    DO_ALL=false; shift ;;
    --network)           DO_NETWORK=true;    DO_ALL=false; shift ;;
    --crypto)            DO_CRYPTO=true;     DO_ALL=false; shift ;;
    --auth)              DO_AUTH=true;        DO_ALL=false; shift ;;
    --entropy)           DO_ENTROPY=true;    DO_ALL=false; shift ;;
    --callgraph)         CALLGRAPH_FUNC="$2"; DO_ALL=false; shift 2 ;;
    --all)               DO_ALL=true; shift ;;
    --quick)             QUICK_MODE=true; DO_ALL=false; shift ;;
    -h|--help)           usage ;;
    -*)                  echo "Error: Unknown option $1" >&2; usage ;;
    *)                   BINARY="$1"; shift ;;
  esac
done

if [[ -z "$BINARY" ]]; then
  echo "Error: No binary specified." >&2
  usage
fi

if [[ ! -f "$BINARY" ]]; then
  echo "Error: File not found: $BINARY" >&2
  exit 1
fi

BINARY_ABS=$(realpath "$BINARY")
BASENAME=$(basename "$BINARY")

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="${BASENAME}-reversing"
fi

mkdir -p "$OUTPUT_DIR"

# =====================================================================
# Detect available tool
# =====================================================================

R2_CMD=""
GHIDRA_CMD=""
TOOL_NAME=""

detect_tools() {
  if [[ -n "$FORCE_TOOL" ]]; then
    case "$FORCE_TOOL" in
      r2|radare2)
        if command -v r2 &>/dev/null; then
          R2_CMD="r2"
          TOOL_NAME="radare2"
        elif command -v radare2 &>/dev/null; then
          R2_CMD="radare2"
          TOOL_NAME="radare2"
        else
          echo "Error: radare2 not found. Install with: brew install radare2" >&2
          exit 1
        fi
        ;;
      rizin|rz)
        if command -v rizin &>/dev/null; then
          R2_CMD="rizin"
          TOOL_NAME="rizin"
        else
          echo "Error: rizin not found. Install with: brew install rizin" >&2
          exit 1
        fi
        ;;
      ghidra)
        if [[ -n "${GHIDRA_INSTALL_DIR:-}" ]] && [[ -f "${GHIDRA_INSTALL_DIR}/support/analyzeHeadless" ]]; then
          GHIDRA_CMD="${GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
          TOOL_NAME="ghidra"
        elif command -v analyzeHeadless &>/dev/null; then
          GHIDRA_CMD="analyzeHeadless"
          TOOL_NAME="ghidra"
        else
          echo "Error: Ghidra headless not found. Set GHIDRA_INSTALL_DIR or install Ghidra." >&2
          exit 1
        fi
        ;;
    esac
    return
  fi

  # Auto-detect: prefer rizin > radare2 > ghidra
  if command -v rizin &>/dev/null; then
    R2_CMD="rizin"
    TOOL_NAME="rizin"
  elif command -v r2 &>/dev/null; then
    R2_CMD="r2"
    TOOL_NAME="radare2"
  elif command -v radare2 &>/dev/null; then
    R2_CMD="radare2"
    TOOL_NAME="radare2"
  elif [[ -n "${GHIDRA_INSTALL_DIR:-}" ]] && [[ -f "${GHIDRA_INSTALL_DIR}/support/analyzeHeadless" ]]; then
    GHIDRA_CMD="${GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
    TOOL_NAME="ghidra"
  elif command -v analyzeHeadless &>/dev/null; then
    GHIDRA_CMD="analyzeHeadless"
    TOOL_NAME="ghidra"
  fi

  if [[ -z "$TOOL_NAME" ]]; then
    echo "WARNING: No reversing tool found!" >&2
    echo "INSTALL_REQUIRED:radare2" >&2
    echo "" >&2
    echo "Install one of the following:" >&2
    echo "  brew install radare2    # Recommended" >&2
    echo "  brew install rizin      # Fork of radare2" >&2
    echo "  brew install --cask ghidra  # NSA's RE tool" >&2
    echo "" >&2
    echo "Falling back to basic analysis with otool/nm/strings..." >&2
    TOOL_NAME="basic"
  fi
}

detect_tools
echo "=== Binary Reversing Analysis ==="
echo "Binary: $BASENAME"
echo "Tool: $TOOL_NAME"
echo "Output: $OUTPUT_DIR"
echo

# =====================================================================
# r2/rizin analysis functions
# =====================================================================

r2_run() {
  local cmds="$1"
  local timeout_val="${2:-120}"
  timeout "$timeout_val" "$R2_CMD" -q -c "$cmds" "$BINARY_ABS" 2>/dev/null || true
}

r2_functions() {
  echo "  [*] Extracting function list..."
  r2_run "aaa; aflj" 300 > "$OUTPUT_DIR/functions.json"
  r2_run "aaa; afl" 300 > "$OUTPUT_DIR/functions.txt"
  local count
  count=$(grep -c '"name"' "$OUTPUT_DIR/functions.json" 2>/dev/null || echo "0")
  echo "  Functions found: $count"
}

r2_strings() {
  echo "  [*] Extracting strings with references..."
  r2_run "aaa; izj" 120 > "$OUTPUT_DIR/strings.json"
  r2_run "aaa; iz" 120 > "$OUTPUT_DIR/strings-all.txt"

  # Filter interesting strings
  r2_run 'aaa; izqq~http\|api\|key\|secret\|token\|password\|firebase\|aws\|azure\|google\|auth\|login\|cert\|crypt' 120 \
    > "$OUTPUT_DIR/strings-interesting.txt"

  local count
  count=$(wc -l < "$OUTPUT_DIR/strings-interesting.txt" 2>/dev/null | tr -d ' ')
  echo "  Interesting strings: $count"
}

r2_imports() {
  echo "  [*] Extracting imports..."
  r2_run "iij" 60 > "$OUTPUT_DIR/imports.json"
  r2_run "ii" 60 > "$OUTPUT_DIR/imports.txt"
  local count
  count=$(grep -c '"name"' "$OUTPUT_DIR/imports.json" 2>/dev/null || echo "0")
  echo "  Imports: $count"
}

r2_exports() {
  echo "  [*] Extracting exports..."
  r2_run "iEj" 60 > "$OUTPUT_DIR/exports.json"
  r2_run "iE" 60 > "$OUTPUT_DIR/exports.txt"
  local count
  count=$(grep -c '"name"' "$OUTPUT_DIR/exports.json" 2>/dev/null || echo "0")
  echo "  Exports: $count"
}

r2_classes() {
  echo "  [*] Extracting ObjC classes and methods..."
  r2_run "icj" 120 > "$OUTPUT_DIR/classes.json"
  r2_run "ic" 120 > "$OUTPUT_DIR/classes.txt"

  # Filter security-relevant classes
  grep -iE 'auth\|login\|token\|crypto\|keychain\|secret\|api\|network\|service\|manager\|firebase\|aws\|azure\|google' \
    "$OUTPUT_DIR/classes.txt" > "$OUTPUT_DIR/classes-interesting.txt" 2>/dev/null || true

  local count
  count=$(wc -l < "$OUTPUT_DIR/classes-interesting.txt" 2>/dev/null | tr -d ' ')
  echo "  Interesting classes: $count"
}

r2_xrefs() {
  local target="$1"
  echo "  [*] Finding cross-references for: $target..."
  r2_run "aaa; s $target; axtj" 120 > "$OUTPUT_DIR/xrefs-${target//[^a-zA-Z0-9]/_}.json"
  r2_run "aaa; s $target; axt" 120 > "$OUTPUT_DIR/xrefs-${target//[^a-zA-Z0-9]/_}.txt"
}

r2_decompile() {
  local func="$1"
  echo "  [*] Decompiling: $func..."
  # Try r2ghidra first (pdg), fall back to r2dec (pdd), then disassembly (pdf)
  local result
  result=$(r2_run "aaa; s $func; pdg" 120)
  if [[ -z "$result" ]] || echo "$result" | grep -q "Cannot find function"; then
    result=$(r2_run "aaa; s $func; pdd" 120)
  fi
  if [[ -z "$result" ]]; then
    result=$(r2_run "aaa; s $func; pdf" 120)
  fi
  echo "$result" > "$OUTPUT_DIR/decompiled-${func//[^a-zA-Z0-9]/_}.c"
}

r2_decompile_pattern() {
  local pattern="$1"
  echo "  [*] Decompiling functions matching: $pattern..."
  local funcs
  funcs=$(r2_run "aaa; afl~$pattern" 120 | awk '{print $4}' | head -20)
  local count=0
  while IFS= read -r func; do
    [[ -z "$func" ]] && continue
    r2_decompile "$func"
    count=$((count + 1))
  done <<< "$funcs"
  echo "  Decompiled $count functions"
}

r2_secrets() {
  echo "  [*] Analyzing secret/credential functions..."
  r2_run 'aaa; afl~secret\|key\|crypt\|token\|password\|auth\|credential\|keychain\|firebase\|aws\|azure\|google' 120 \
    > "$OUTPUT_DIR/functions-secrets.txt"

  # Find xrefs to crypto imports
  {
    echo "=== Cross-references to security-relevant imports ==="
    echo
    echo "--- CCCrypt ---"
    r2_run "aaa; axt @ sym.imp.CCCrypt" 120
    echo
    echo "--- SecItemAdd (Keychain) ---"
    r2_run "aaa; axt @ sym.imp.SecItemAdd" 120
    echo
    echo "--- SecItemCopyMatching (Keychain) ---"
    r2_run "aaa; axt @ sym.imp.SecItemCopyMatching" 120
    echo
    echo "--- CC_MD5 ---"
    r2_run "aaa; axt @ sym.imp.CC_MD5" 120
    echo
    echo "--- CC_SHA256 ---"
    r2_run "aaa; axt @ sym.imp.CC_SHA256" 120
  } > "$OUTPUT_DIR/xrefs-security.txt"
}

r2_network() {
  echo "  [*] Analyzing networking functions..."
  r2_run 'aaa; afl~URL\|HTTP\|request\|session\|network\|api\|endpoint\|fetch\|download\|upload\|socket\|connect' 120 \
    > "$OUTPUT_DIR/functions-network.txt"

  {
    echo "=== Cross-references to networking imports ==="
    for sym in \
      "sym.imp.NSURLSession" \
      "sym.imp.URLSession" \
      "sym.imp.NSURLConnection" \
      "sym.imp.CFHTTPMessageCreateRequest" \
      "sym.imp.CFStreamCreatePairWithSocketToHost"; do
      echo
      echo "--- $sym ---"
      r2_run "aaa; axt @ $sym" 60
    done
  } > "$OUTPUT_DIR/xrefs-network.txt"
}

r2_crypto() {
  echo "  [*] Analyzing crypto functions..."
  r2_run 'aaa; afl~crypt\|hash\|aes\|rsa\|sha\|md5\|hmac\|encrypt\|decrypt\|cipher\|sign\|verify\|random\|SecKey' 120 \
    > "$OUTPUT_DIR/functions-crypto.txt"

  {
    echo "=== Crypto function analysis ==="
    echo
    echo "--- Imports containing crypto ---"
    r2_run 'ii~crypt\|CC_\|SecKey\|CommonCrypto\|CryptoKit' 60
  } > "$OUTPUT_DIR/analysis-crypto.txt"
}

r2_auth() {
  echo "  [*] Analyzing authentication functions..."
  r2_run 'aaa; afl~auth\|login\|logout\|signin\|signup\|register\|credential\|session\|token\|oauth\|saml\|biometric\|LAContext\|FIRAuth' 120 \
    > "$OUTPUT_DIR/functions-auth.txt"
}

r2_entropy() {
  echo "  [*] Analyzing binary entropy..."
  r2_run "p=e" 60 > "$OUTPUT_DIR/entropy.txt"
  r2_run "iSj" 60 > "$OUTPUT_DIR/sections.json"
  echo "  Entropy data saved"
}

r2_callgraph() {
  local func="$1"
  echo "  [*] Generating call graph for: $func..."
  r2_run "aaa; s $func; agCd" 120 > "$OUTPUT_DIR/callgraph-${func//[^a-zA-Z0-9]/_}.dot"
  echo "  Call graph saved (DOT format)"
}

r2_binary_info() {
  echo "  [*] Extracting binary info..."
  r2_run "ij" 60 > "$OUTPUT_DIR/binary-info.json"
}

# =====================================================================
# Basic analysis (no reversing tool)
# =====================================================================

basic_analysis() {
  echo "  [*] Running basic analysis (no reversing tool available)..."

  if command -v otool &>/dev/null; then
    echo "  Using otool for basic analysis..."
    otool -L "$BINARY_ABS" > "$OUTPUT_DIR/linked-libraries.txt" 2>/dev/null || true
    otool -l "$BINARY_ABS" > "$OUTPUT_DIR/load-commands.txt" 2>/dev/null || true
    otool -oV "$BINARY_ABS" > "$OUTPUT_DIR/objc-metadata.txt" 2>/dev/null || true
  fi

  if command -v nm &>/dev/null; then
    echo "  Using nm for symbol extraction..."
    nm "$BINARY_ABS" > "$OUTPUT_DIR/symbols.txt" 2>/dev/null || true
    # Filter security-relevant symbols
    grep -iE 'auth\|login\|token\|crypto\|keychain\|secret\|api\|network\|firebase\|aws\|azure\|google' \
      "$OUTPUT_DIR/symbols.txt" > "$OUTPUT_DIR/symbols-interesting.txt" 2>/dev/null || true
  fi

  if command -v strings &>/dev/null; then
    echo "  Using strings for string extraction..."
    strings "$BINARY_ABS" > "$OUTPUT_DIR/strings-raw.txt" 2>/dev/null || true
    grep -iE 'http\|api\|key\|secret\|token\|password\|firebase\|aws\|azure\|google\|auth\|cert\|crypt' \
      "$OUTPUT_DIR/strings-raw.txt" > "$OUTPUT_DIR/strings-interesting.txt" 2>/dev/null || true
  fi
}

# =====================================================================
# Main execution
# =====================================================================

case "$TOOL_NAME" in
  radare2|rizin)
    r2_binary_info

    if [[ "$QUICK_MODE" == true ]]; then
      r2_functions
      r2_strings
      r2_imports
    elif [[ "$DO_ALL" == true ]]; then
      r2_functions
      r2_strings
      r2_imports
      r2_exports
      r2_classes
      r2_secrets
      r2_network
      r2_crypto
      r2_auth
      r2_entropy
    else
      [[ "$DO_FUNCTIONS" == true ]] && r2_functions
      [[ "$DO_STRINGS" == true ]] && r2_strings
      [[ "$DO_IMPORTS" == true ]] && r2_imports
      [[ "$DO_EXPORTS" == true ]] && r2_exports
      [[ "$DO_CLASSES" == true ]] && r2_classes
      [[ "$DO_SECRETS" == true ]] && r2_secrets
      [[ "$DO_NETWORK" == true ]] && r2_network
      [[ "$DO_CRYPTO" == true ]] && r2_crypto
      [[ "$DO_AUTH" == true ]] && r2_auth
      [[ "$DO_ENTROPY" == true ]] && r2_entropy
    fi

    [[ -n "$XREFS_TARGET" ]] && r2_xrefs "$XREFS_TARGET"
    [[ -n "$DECOMPILE_FUNC" ]] && r2_decompile "$DECOMPILE_FUNC"
    [[ -n "$DECOMPILE_PATTERN" ]] && r2_decompile_pattern "$DECOMPILE_PATTERN"
    [[ -n "$CALLGRAPH_FUNC" ]] && r2_callgraph "$CALLGRAPH_FUNC"
    ;;

  ghidra)
    echo "  [*] Ghidra headless analysis..."
    echo "  NOTE: Ghidra analysis can take several minutes for large binaries."

    GHIDRA_PROJECT="/tmp/ghidra_ios_analysis_$$"
    GHIDRA_PROJECT_NAME="analysis"
    mkdir -p "$GHIDRA_PROJECT"

    # Locate Ghidra scripts directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ghidra"
    GHIDRA_SCRIPT_OPTS=""
    if [[ -d "$SCRIPT_DIR" ]]; then
      GHIDRA_SCRIPT_OPTS="-scriptPath $SCRIPT_DIR"
    fi

    # Import and analyze the binary
    echo "  [*] Importing binary into Ghidra project..."
    $GHIDRA_CMD "$GHIDRA_PROJECT" "$GHIDRA_PROJECT_NAME" \
      -import "$BINARY_ABS" \
      -overwrite \
      2>"$OUTPUT_DIR/ghidra-import-log.txt" || true

    ghidra_run_script() {
      local script_name="$1"
      shift
      echo "  [*] Running Ghidra script: $script_name..."
      $GHIDRA_CMD "$GHIDRA_PROJECT" "$GHIDRA_PROJECT_NAME" \
        -process "$(basename "$BINARY_ABS")" \
        -noanalysis \
        $GHIDRA_SCRIPT_OPTS \
        -postScript "$script_name" "$@" \
        2>>"$OUTPUT_DIR/ghidra-log.txt" || true
    }

    if [[ "$QUICK_MODE" == true ]]; then
      # Quick: decompile security functions + string xrefs
      ghidra_run_script "DecompileAllFunctions.java" "$OUTPUT_DIR" "--security-only"
      ghidra_run_script "ExportStringXrefs.java" "$OUTPUT_DIR"
    elif [[ "$DO_ALL" == true ]]; then
      # Full analysis: all scripts
      ghidra_run_script "DecompileAllFunctions.java" "$OUTPUT_DIR"
      ghidra_run_script "FindSecrets.java" "$OUTPUT_DIR"
      ghidra_run_script "ExportAPICalls.java" "$OUTPUT_DIR"
      ghidra_run_script "ExportCryptoUsage.java" "$OUTPUT_DIR"
      ghidra_run_script "ExportStringXrefs.java" "$OUTPUT_DIR"
    else
      # Selective analysis
      if [[ "$DO_FUNCTIONS" == true ]] || [[ "$DO_CLASSES" == true ]]; then
        ghidra_run_script "DecompileAllFunctions.java" "$OUTPUT_DIR"
      fi
      if [[ "$DO_STRINGS" == true ]]; then
        ghidra_run_script "ExportStringXrefs.java" "$OUTPUT_DIR"
      fi
      if [[ "$DO_SECRETS" == true ]]; then
        ghidra_run_script "FindSecrets.java" "$OUTPUT_DIR"
        ghidra_run_script "DecompileAllFunctions.java" "$OUTPUT_DIR" "--security-only"
      fi
      if [[ "$DO_NETWORK" == true ]]; then
        ghidra_run_script "ExportAPICalls.java" "$OUTPUT_DIR"
      fi
      if [[ "$DO_CRYPTO" == true ]]; then
        ghidra_run_script "ExportCryptoUsage.java" "$OUTPUT_DIR"
      fi
      if [[ "$DO_AUTH" == true ]]; then
        ghidra_run_script "DecompileAllFunctions.java" "$OUTPUT_DIR" "--security-only"
      fi
    fi

    # Decompile specific function if requested
    if [[ -n "$DECOMPILE_FUNC" ]] || [[ -n "$DECOMPILE_PATTERN" ]]; then
      ghidra_run_script "DecompileAllFunctions.java" "$OUTPUT_DIR"
      echo "  NOTE: Use grep on decompiled-all.c to find specific functions"
    fi

    # Cleanup project (keep output)
    rm -rf "$GHIDRA_PROJECT"
    echo "  Ghidra analysis complete. See $OUTPUT_DIR/ for results."
    ;;

  basic)
    basic_analysis
    ;;
esac

# =====================================================================
# Generate LLM analysis summary
# =====================================================================

{
  echo "=== LLM Analysis Summary ==="
  echo
  echo "Binary: $BASENAME"
  echo "Tool: $TOOL_NAME"
  echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo
  echo "=== Available Output Files ==="
  echo
  ls -la "$OUTPUT_DIR/" 2>/dev/null
  echo
  echo "=== Analysis Instructions for LLM ==="
  echo
  echo "1. Read functions.json/txt to understand the binary structure"
  echo "2. Read strings-interesting.txt for URLs, API keys, credentials"
  echo "3. Read classes-interesting.txt for security-relevant classes"
  echo "4. Read functions-secrets.txt for credential-handling code"
  echo "5. Read functions-network.txt for networking code"
  echo "6. Read functions-crypto.txt for cryptographic operations"
  echo "7. Read functions-auth.txt for authentication logic"
  echo "8. Read xrefs-security.txt for how crypto/keychain APIs are called"
  echo "9. Read xrefs-network.txt for how network APIs are called"
  echo "10. Use --decompile to get pseudo-code for specific functions of interest"
  echo
  echo "Focus areas:"
  echo "- Hardcoded credentials and API keys"
  echo "- Weak cryptographic implementations"
  echo "- Insecure data storage"
  echo "- Missing certificate pinning"
  echo "- Authentication bypass possibilities"
  echo "- Data flow from user input to network/storage"
} > "$OUTPUT_DIR/llm-analysis-guide.txt"

echo
echo "=== Reversing analysis complete ==="
echo "Output directory: $OUTPUT_DIR"
echo
echo "Contents:"
ls -1 "$OUTPUT_DIR/" 2>/dev/null
echo
echo "Next steps:"
echo "  1. Read the output files for LLM analysis"
echo "  2. Use --decompile <func> to decompile specific functions"
echo "  3. Use --xrefs <target> to trace cross-references"
echo "  4. Use --callgraph <func> to visualize call paths"
