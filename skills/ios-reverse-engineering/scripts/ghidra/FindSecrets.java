// FindSecrets.java — Ghidra headless script
// Searches decompiled code for hardcoded credentials, API keys, and secrets
// Usage: analyzeHeadless <project> <name> -process <binary> -postScript FindSecrets.java <output_dir>
//@category iOS-Reversing

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FindSecrets extends GhidraScript {

    private static class SecretPattern {
        String name;
        String severity;
        Pattern pattern;

        SecretPattern(String name, String severity, String regex) {
            this.name = name;
            this.severity = severity;
            this.pattern = Pattern.compile(regex);
        }
    }

    private static final SecretPattern[] PATTERNS = {
        // Critical
        new SecretPattern("AWS Secret Key", "CRITICAL", "(?i)aws.{0,20}(secret|key).{0,10}['\"][A-Za-z0-9/+=]{40}['\"]"),
        new SecretPattern("AWS Access Key", "CRITICAL", "AKIA[0-9A-Z]{16}"),
        new SecretPattern("Stripe Secret Key", "CRITICAL", "sk_(live|test)_[0-9a-zA-Z]{24,}"),
        new SecretPattern("Private Key Block", "CRITICAL", "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),
        new SecretPattern("Generic Secret Assignment", "CRITICAL", "(?i)(password|passwd|secret|private.?key)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]"),

        // High
        new SecretPattern("Firebase API Key", "HIGH", "AIza[0-9A-Za-z_-]{35}"),
        new SecretPattern("GCP Service Account", "HIGH", "[a-z0-9-]+@[a-z0-9-]+\\.iam\\.gserviceaccount\\.com"),
        new SecretPattern("Twilio Account SID", "HIGH", "AC[0-9a-f]{32}"),
        new SecretPattern("SendGrid API Key", "HIGH", "SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}"),
        new SecretPattern("Slack Token", "HIGH", "xox[bpors]-[0-9]{10,}"),
        new SecretPattern("Stripe Publishable Key", "HIGH", "pk_(live|test)_[0-9a-zA-Z]{24,}"),

        // Medium
        new SecretPattern("Hardcoded URL with Credentials", "MEDIUM", "https?://[^:]+:[^@]+@"),
        new SecretPattern("JWT Token", "MEDIUM", "eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*"),
        new SecretPattern("Firebase Database URL", "MEDIUM", "https://[a-z0-9-]+\\.firebaseio\\.com"),
        new SecretPattern("Azure Connection String", "MEDIUM", "(?i)DefaultEndpointsProtocol=https?;AccountName="),
        new SecretPattern("Cognito Pool ID", "MEDIUM", "[a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36}"),

        // Low
        new SecretPattern("Hardcoded API Endpoint", "LOW", "(?i)(api[_-]?(url|endpoint|base|host)|base[_-]?url)\\s*[:=]\\s*['\"]https?://"),
        new SecretPattern("Hardcoded IP Address", "LOW", "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"),
        new SecretPattern("Encryption Key Assignment", "LOW", "(?i)(aes|encryption|crypto).{0,20}(key|iv|salt|nonce)\\s*[:=]"),
    };

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: FindSecrets.java <output_dir>");
            return;
        }

        String outputDir = args[0];
        File outDir = new File(outputDir);
        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        List<String> findings = new ArrayList<>();

        // Phase 1: Search in defined strings
        println("Phase 1: Scanning defined strings...");
        DataIterator dataIt = currentProgram.getListing().getDefinedData(true);
        while (dataIt.hasNext() && !monitor.isCancelled()) {
            Data data = dataIt.next();
            if (data.getDataType() instanceof StringDataType ||
                data.getDataType().getName().contains("string") ||
                data.getDataType().getName().contains("String")) {
                String value = data.getDefaultValueRepresentation();
                if (value != null) {
                    for (SecretPattern sp : PATTERNS) {
                        Matcher m = sp.pattern.matcher(value);
                        if (m.find()) {
                            String addr = data.getAddress().toString();
                            findings.add(sp.severity + " | " + sp.name + " | " + addr + " | " + truncate(value, 120));
                        }
                    }
                }
            }
        }
        println("  String scan: " + findings.size() + " findings");

        // Phase 2: Search in decompiled code
        println("Phase 2: Scanning decompiled functions...");
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        int preDecompCount = findings.size();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            try {
                DecompileResults results = decompiler.decompileFunction(func, 15, monitor);
                if (results != null && results.getDecompiledFunction() != null) {
                    String code = results.getDecompiledFunction().getC();
                    if (code != null) {
                        for (SecretPattern sp : PATTERNS) {
                            Matcher m = sp.pattern.matcher(code);
                            while (m.find()) {
                                String match = m.group();
                                String addr = func.getEntryPoint().toString();
                                findings.add(sp.severity + " | " + sp.name + " | " + func.getName() + " @ " + addr + " | " + truncate(match, 120));
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Skip functions that fail to decompile
            }
        }
        decompiler.dispose();
        println("  Decompilation scan: " + (findings.size() - preDecompCount) + " additional findings");

        // Write report
        File reportFile = new File(outDir, "secrets-findings.txt");
        PrintWriter writer = new PrintWriter(new FileWriter(reportFile));
        writer.println("=== Ghidra Secret/Credential Analysis ===");
        writer.println("Binary: " + currentProgram.getName());
        writer.println("Date: " + new java.util.Date());
        writer.println("Total findings: " + findings.size());
        writer.println();
        writer.println("Severity | Type | Location | Match");
        writer.println("---------|------|----------|------");

        // Sort by severity
        findings.sort((a, b) -> {
            int sa = severityOrder(a.split("\\|")[0].trim());
            int sb = severityOrder(b.split("\\|")[0].trim());
            return sa - sb;
        });

        for (String finding : findings) {
            writer.println(finding);
        }

        writer.close();
        println("Secrets analysis complete: " + findings.size() + " findings");
        println("Report: " + reportFile.getAbsolutePath());
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        s = s.replace("\n", " ").replace("\r", "");
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    private int severityOrder(String severity) {
        switch (severity) {
            case "CRITICAL": return 0;
            case "HIGH": return 1;
            case "MEDIUM": return 2;
            case "LOW": return 3;
            default: return 4;
        }
    }
}
