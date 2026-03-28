// DecompileAllFunctions.java — Ghidra headless script
// Decompiles all functions (or security-relevant subset) to pseudo-C output
// Usage: analyzeHeadless <project> <name> -import <binary> -postScript DecompileAllFunctions.java <output_dir> [--security-only]
//@category iOS-Reversing

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.regex.Pattern;

public class DecompileAllFunctions extends GhidraScript {

    private static final Pattern SECURITY_PATTERN = Pattern.compile(
        "(?i)(auth|login|logout|token|secret|key|crypt|encrypt|decrypt|hash|" +
        "sign|verify|password|credential|keychain|certificate|ssl|tls|pinning|" +
        "firebase|aws|azure|google|api|network|request|session|cookie|" +
        "biometric|LAContext|SecItem|CCCrypt|CC_SHA|CC_MD5|HMAC|AES|RSA|" +
        "jailbreak|cydia|substrate|ptrace|sysctl|fork|dlopen|dlsym)",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: DecompileAllFunctions.java <output_dir> [--security-only]");
            return;
        }

        String outputDir = args[0];
        boolean securityOnly = args.length > 1 && args[1].equals("--security-only");

        File outDir = new File(outputDir);
        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        FunctionManager funcManager = currentProgram.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        int totalFunctions = 0;
        int decompiledCount = 0;
        int errorCount = 0;

        // Count total functions
        for (Function f : funcManager.getFunctions(true)) {
            totalFunctions++;
        }

        println("DecompileAllFunctions: " + totalFunctions + " functions found");
        if (securityOnly) {
            println("Mode: security-relevant functions only");
        }

        // Decompile all functions to a single file + individual files for large ones
        File allFile = new File(outDir, "decompiled-all.c");
        File summaryFile = new File(outDir, "decompilation-summary.txt");
        File securityFile = new File(outDir, "decompiled-security.c");

        PrintWriter allWriter = new PrintWriter(new FileWriter(allFile));
        PrintWriter summaryWriter = new PrintWriter(new FileWriter(summaryFile));
        PrintWriter securityWriter = new PrintWriter(new FileWriter(securityFile));

        allWriter.println("// Decompiled output from Ghidra headless analysis");
        allWriter.println("// Binary: " + currentProgram.getName());
        allWriter.println("// Date: " + new java.util.Date());
        allWriter.println();

        securityWriter.println("// Security-relevant decompiled functions");
        securityWriter.println("// Binary: " + currentProgram.getName());
        securityWriter.println();

        summaryWriter.println("=== Decompilation Summary ===");
        summaryWriter.println("Binary: " + currentProgram.getName());
        summaryWriter.println("Total functions: " + totalFunctions);
        summaryWriter.println();
        summaryWriter.println("Function | Address | Size | Security-Relevant");
        summaryWriter.println("---------|---------|------|------------------");

        functions = funcManager.getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            String funcName = func.getName();
            String addr = func.getEntryPoint().toString();
            long size = func.getBody().getNumAddresses();
            boolean isSecurity = SECURITY_PATTERN.matcher(funcName).find();

            summaryWriter.println(funcName + " | " + addr + " | " + size + " | " + (isSecurity ? "YES" : ""));

            if (securityOnly && !isSecurity) {
                continue;
            }

            try {
                DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
                if (results != null && results.depiledFunction() != null) {
                    String code = results.getDecompiledFunction().getC();
                    if (code != null && !code.isEmpty()) {
                        allWriter.println("// === " + funcName + " @ " + addr + " ===");
                        allWriter.println(code);
                        allWriter.println();

                        if (isSecurity) {
                            securityWriter.println("// === " + funcName + " @ " + addr + " ===");
                            securityWriter.println(code);
                            securityWriter.println();
                        }

                        // Write individual files for security-relevant functions
                        if (isSecurity) {
                            String safeName = funcName.replaceAll("[^a-zA-Z0-9_.-]", "_");
                            File funcFile = new File(outDir, "func-" + safeName + ".c");
                            PrintWriter funcWriter = new PrintWriter(new FileWriter(funcFile));
                            funcWriter.println("// " + funcName + " @ " + addr);
                            funcWriter.println(code);
                            funcWriter.close();
                        }

                        decompiledCount++;
                    }
                }
            } catch (Exception e) {
                errorCount++;
            }
        }

        summaryWriter.println();
        summaryWriter.println("Decompiled: " + decompiledCount);
        summaryWriter.println("Errors: " + errorCount);

        allWriter.close();
        summaryWriter.close();
        securityWriter.close();
        decompiler.dispose();

        println("Decompilation complete: " + decompiledCount + " functions, " + errorCount + " errors");
        println("Output: " + outputDir);
    }
}
