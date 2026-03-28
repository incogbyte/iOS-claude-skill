// ExportCryptoUsage.java — Ghidra headless script
// Finds cryptographic function usage, traces callers, and decompiles crypto-related code
// Usage: analyzeHeadless <project> <name> -process <binary> -postScript ExportCryptoUsage.java <output_dir>
//@category iOS-Reversing

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;
import java.util.regex.Pattern;

public class ExportCryptoUsage extends GhidraScript {

    // CommonCrypto / Security framework symbols
    private static final String[] CRYPTO_SYMBOLS = {
        // CommonCrypto
        "CCCrypt", "CCCryptorCreate", "CCCryptorUpdate", "CCCryptorFinal",
        "CCHmac", "CCHmacInit", "CCHmacUpdate", "CCHmacFinal",
        "CC_MD5", "CC_MD5_Init", "CC_MD5_Update", "CC_MD5_Final",
        "CC_SHA1", "CC_SHA1_Init", "CC_SHA1_Update", "CC_SHA1_Final",
        "CC_SHA256", "CC_SHA256_Init", "CC_SHA256_Update", "CC_SHA256_Final",
        "CC_SHA512", "CC_SHA512_Init",
        "CCKeyDerivationPBKDF",
        // Security framework
        "SecKeyCreateRandomKey", "SecKeyCreateEncryptedData", "SecKeyCreateDecryptedData",
        "SecKeyCreateSignature", "SecKeyVerifySignature",
        "SecKeyGeneratePair", "SecKeyCopyPublicKey",
        "SecRandomCopyBytes",
        // Keychain
        "SecItemAdd", "SecItemCopyMatching", "SecItemUpdate", "SecItemDelete",
        // Certificate / Trust
        "SecTrustEvaluate", "SecTrustEvaluateWithError", "SecTrustSetAnchorCertificates",
        "SecCertificateCreateWithData", "SecTrustCreateWithCertificates",
        "SecPolicyCreateSSL",
    };

    private static final Pattern WEAK_CRYPTO_PATTERN = Pattern.compile(
        "(?i)(kCCAlgorithmDES|kCCModeCBC|kCCOptionECBMode|CC_MD5|" +
        "kSecAttrAccessibleAlways|kSecAttrAccessibleAlwaysThisDeviceOnly|" +
        "kCCOptionPKCS7Padding.*kCCAlgorithmDES|MD5|ECB)"
    );

    private static final Pattern HARDCODED_KEY_PATTERN = Pattern.compile(
        "(?i)(key|iv|salt|nonce|secret)\\s*=\\s*(0x[0-9a-f]+|\\{[^}]+\\}|\"[^\"]+\")"
    );

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: ExportCryptoUsage.java <output_dir>");
            return;
        }

        String outputDir = args[0];
        File outDir = new File(outputDir);
        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        SymbolTable symbolTable = currentProgram.getSymbolTable();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        File reportFile = new File(outDir, "crypto-analysis.txt");
        PrintWriter writer = new PrintWriter(new FileWriter(reportFile));
        writer.println("=== Cryptographic Usage Analysis ===");
        writer.println("Binary: " + currentProgram.getName());
        writer.println("Date: " + new java.util.Date());
        writer.println();

        List<String> weakFindings = new ArrayList<>();
        List<String> hardcodedKeyFindings = new ArrayList<>();

        // Phase 1: Find crypto symbol references
        writer.println("== Crypto API Usage ==");
        writer.println();
        int totalRefs = 0;

        for (String symName : CRYPTO_SYMBOLS) {
            SymbolIterator symbols = symbolTable.getSymbols(symName);
            while (symbols.hasNext()) {
                Symbol sym = symbols.next();
                List<String> callers = new ArrayList<>();

                ReferenceIterator refs = currentProgram.getReferenceManager()
                    .getReferencesTo(sym.getAddress());
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Function caller = currentProgram.getFunctionManager()
                        .getFunctionContaining(ref.getFromAddress());
                    if (caller != null) {
                        callers.add(caller.getName() + " @ " + ref.getFromAddress());
                        totalRefs++;
                    }
                }

                if (!callers.isEmpty()) {
                    writer.println("--- " + symName + " ---");
                    writer.println("Address: " + sym.getAddress());
                    writer.println("Referenced by:");
                    for (String caller : callers) {
                        writer.println("  " + caller);
                    }
                    writer.println();
                }
            }
        }
        writer.println("Total crypto references: " + totalRefs);
        writer.println();

        // Phase 2: Decompile and analyze crypto-calling functions
        writer.println("== Decompiled Crypto Functions ==");
        writer.println();

        Set<Function> cryptoFunctions = new HashSet<>();
        for (String symName : CRYPTO_SYMBOLS) {
            SymbolIterator symbols = symbolTable.getSymbols(symName);
            while (symbols.hasNext()) {
                Symbol sym = symbols.next();
                ReferenceIterator refs = currentProgram.getReferenceManager()
                    .getReferencesTo(sym.getAddress());
                while (refs.hasNext()) {
                    Reference ref = refs.next();
                    Function caller = currentProgram.getFunctionManager()
                        .getFunctionContaining(ref.getFromAddress());
                    if (caller != null) {
                        cryptoFunctions.add(caller);
                    }
                }
            }
        }

        for (Function func : cryptoFunctions) {
            if (monitor.isCancelled()) break;
            try {
                DecompileResults results = decompiler.decompileFunction(func, 20, monitor);
                if (results != null && results.getDecompiledFunction() != null) {
                    String code = results.getDecompiledFunction().getC();
                    if (code != null) {
                        writer.println("// === " + func.getName() + " @ " + func.getEntryPoint() + " ===");
                        writer.println(code);
                        writer.println();

                        // Check for weak crypto
                        java.util.regex.Matcher weakMatcher = WEAK_CRYPTO_PATTERN.matcher(code);
                        while (weakMatcher.find()) {
                            weakFindings.add("[WEAK CRYPTO] " + weakMatcher.group() + " in " + func.getName());
                        }

                        // Check for hardcoded keys
                        java.util.regex.Matcher keyMatcher = HARDCODED_KEY_PATTERN.matcher(code);
                        while (keyMatcher.find()) {
                            hardcodedKeyFindings.add("[HARDCODED KEY] " + keyMatcher.group() + " in " + func.getName());
                        }
                    }
                }
            } catch (Exception e) {
                // Skip
            }
        }

        // Phase 3: Security findings
        writer.println("== Security Findings ==");
        writer.println();

        if (!weakFindings.isEmpty()) {
            writer.println("--- Weak Cryptography ---");
            for (String f : weakFindings) {
                writer.println("  " + f);
            }
            writer.println();
        }

        if (!hardcodedKeyFindings.isEmpty()) {
            writer.println("--- Hardcoded Keys/IVs ---");
            for (String f : hardcodedKeyFindings) {
                writer.println("  " + f);
            }
            writer.println();
        }

        if (weakFindings.isEmpty() && hardcodedKeyFindings.isEmpty()) {
            writer.println("No obvious weak crypto or hardcoded keys detected in decompiled code.");
            writer.println("Manual review of decompiled output recommended.");
        }

        writer.close();
        decompiler.dispose();

        println("Crypto analysis complete: " + cryptoFunctions.size() + " functions analyzed");
        println("Weak crypto findings: " + weakFindings.size());
        println("Hardcoded key findings: " + hardcodedKeyFindings.size());
    }
}
