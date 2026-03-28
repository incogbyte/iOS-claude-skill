#!/usr/bin/env bash
# check-deps.sh — Verify dependencies for iOS reverse engineering
# Output includes machine-readable INSTALL_REQUIRED/INSTALL_OPTIONAL lines.
set -euo pipefail

errors=0
missing_required=()
missing_optional=()

echo "=== iOS Reverse Engineering: Dependency Check ==="
echo

# --- ipsw (includes class-dump functionality) ---
ipsw_found=false
if command -v ipsw &>/dev/null; then
  echo "[OK] ipsw detected ($(ipsw version 2>/dev/null || echo 'unknown version'))"
  ipsw_found=true
else
  # Check common install locations
  for candidate in \
    "$HOME/.local/bin/ipsw" \
    "/usr/local/bin/ipsw" \
    "/opt/homebrew/bin/ipsw"; do
    if [[ -f "$candidate" ]] && [[ -x "$candidate" ]]; then
      echo "[OK] ipsw found: $candidate"
      ipsw_found=true
      break
    fi
  done
fi
if [[ "$ipsw_found" == false ]]; then
  echo "[MISSING] ipsw is not installed or not in PATH"
  errors=$((errors + 1))
  missing_required+=("ipsw")
fi

# --- otool (part of Xcode Command Line Tools) ---
if command -v otool &>/dev/null; then
  echo "[OK] otool detected"
else
  echo "[MISSING] otool is not installed (install Xcode Command Line Tools)"
  errors=$((errors + 1))
  missing_required+=("xcode-cli-tools")
fi

# --- strings ---
if command -v strings &>/dev/null; then
  echo "[OK] strings detected"
else
  echo "[MISSING] strings is not installed"
  errors=$((errors + 1))
  missing_required+=("strings")
fi

# --- plutil ---
if command -v plutil &>/dev/null; then
  echo "[OK] plutil detected"
elif command -v plistutil &>/dev/null; then
  echo "[OK] plistutil detected (Linux alternative to plutil)"
else
  echo "[MISSING] plutil/plistutil not found (optional — needed for plist parsing)"
  missing_optional+=("plutil")
fi

# --- codesign ---
if command -v codesign &>/dev/null; then
  echo "[OK] codesign detected"
else
  echo "[MISSING] codesign not found (optional — macOS only, for entitlements extraction)"
  missing_optional+=("codesign")
fi

# --- unzip ---
if command -v unzip &>/dev/null; then
  echo "[OK] unzip detected"
else
  echo "[MISSING] unzip is not installed"
  errors=$((errors + 1))
  missing_required+=("unzip")
fi

# --- Optional: jtool2 ---
if command -v jtool2 &>/dev/null; then
  echo "[OK] jtool2 detected (optional)"
elif command -v jtool &>/dev/null; then
  echo "[OK] jtool detected (optional)"
else
  echo "[MISSING] jtool2 not found (optional — advanced Mach-O analysis)"
  missing_optional+=("jtool2")
fi

# --- Optional: swift-demangle ---
if command -v swift-demangle &>/dev/null; then
  echo "[OK] swift-demangle detected (optional)"
elif command -v swift &>/dev/null; then
  echo "[OK] swift detected (swift demangle available via 'swift demangle')"
else
  echo "[MISSING] swift-demangle not found (optional — for demangling Swift symbols)"
  missing_optional+=("swift-demangle")
fi

# --- Optional: frida ---
if command -v frida &>/dev/null; then
  echo "[OK] frida detected (optional)"
else
  echo "[MISSING] frida not found (optional — dynamic instrumentation)"
  missing_optional+=("frida")
fi

# --- Optional: ideviceinstaller / libimobiledevice ---
if command -v ideviceinstaller &>/dev/null || command -v ideviceinfo &>/dev/null; then
  echo "[OK] libimobiledevice tools detected (optional)"
else
  echo "[MISSING] libimobiledevice not found (optional — for device interaction)"
  missing_optional+=("libimobiledevice")
fi

# --- Optional: lipo ---
if command -v lipo &>/dev/null; then
  echo "[OK] lipo detected (optional)"
else
  echo "[MISSING] lipo not found (optional — for fat binary manipulation)"
  missing_optional+=("lipo")
fi

# --- Optional: nm ---
if command -v nm &>/dev/null; then
  echo "[OK] nm detected (optional)"
else
  echo "[MISSING] nm not found (optional — symbol listing)"
  missing_optional+=("nm")
fi

# --- Optional: radare2 / rizin ---
if command -v rizin &>/dev/null; then
  echo "[OK] rizin detected (optional — deep binary analysis)"
elif command -v r2 &>/dev/null || command -v radare2 &>/dev/null; then
  echo "[OK] radare2 detected (optional — deep binary analysis)"
else
  echo "[MISSING] radare2/rizin not found (optional — deep binary reversing & decompilation)"
  missing_optional+=("radare2")
fi

# --- Optional: Ghidra headless ---
ghidra_found=false
if [[ -n "${GHIDRA_INSTALL_DIR:-}" ]] && [[ -f "${GHIDRA_INSTALL_DIR}/support/analyzeHeadless" ]]; then
  echo "[OK] Ghidra headless detected at GHIDRA_INSTALL_DIR (optional)"
  ghidra_found=true
elif command -v analyzeHeadless &>/dev/null; then
  echo "[OK] Ghidra headless detected in PATH (optional)"
  ghidra_found=true
fi
if [[ "$ghidra_found" == false ]]; then
  echo "[MISSING] Ghidra headless not found (optional — decompilation & advanced analysis)"
  missing_optional+=("ghidra")
fi

# --- Machine-readable summary ---
echo
if [[ ${#missing_required[@]} -gt 0 ]]; then
  for dep in "${missing_required[@]}"; do
    echo "INSTALL_REQUIRED:$dep"
  done
fi
if [[ ${#missing_optional[@]} -gt 0 ]]; then
  for dep in "${missing_optional[@]}"; do
    echo "INSTALL_OPTIONAL:$dep"
  done
fi

echo
if (( errors > 0 )); then
  echo "*** ${#missing_required[@]} required dependency/ies missing. ***"
  echo "Run install-dep.sh <name> to install, or see references/setup-guide.md."
  exit 1
else
  if [[ ${#missing_optional[@]} -gt 0 ]]; then
    echo "Required dependencies OK. ${#missing_optional[@]} optional dependency/ies missing."
    echo "Run install-dep.sh <name> to install optional tools."
  else
    echo "All dependencies are installed. Ready to analyze."
  fi
  exit 0
fi
