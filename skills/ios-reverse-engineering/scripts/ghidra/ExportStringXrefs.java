// ExportStringXrefs.java — Ghidra headless script
// Exports all strings with their cross-references (which functions reference them)
// Usage: analyzeHeadless <project> <name> -process <binary> -postScript ExportStringXrefs.java <output_dir>
//@category iOS-Reversing

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;
import java.util.regex.Pattern;

public class ExportStringXrefs extends GhidraScript {

    private static final Pattern INTERESTING_PATTERN = Pattern.compile(
        "(?i)(https?://|wss?://|api[_./]|/v[0-9]+/|token|key|secret|password|" +
        "auth|bearer|firebase|aws|azure|google|cognito|stripe|paypal|" +
        "encrypt|decrypt|crypt|hash|md5|sha|aes|rsa|" +
        "login|register|oauth|jwt|certificate|keychain|" +
        "\\.com/|\\.io/|\\.net/|\\.org/)"
    );

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: ExportStringXrefs.java <output_dir>");
            return;
        }

        String outputDir = args[0];
        File outDir = new File(outputDir);
        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        // Collect all strings with xrefs
        List<StringEntry> allStrings = new ArrayList<>();
        List<StringEntry> interestingStrings = new ArrayList<>();

        println("Scanning strings and cross-references...");

        DataIterator dataIt = currentProgram.getListing().getDefinedData(true);
        int totalStrings = 0;

        while (dataIt.hasNext() && !monitor.isCancelled()) {
            Data data = dataIt.next();
            String typeName = data.getDataType().getName().toLowerCase();
            if (!typeName.contains("string") && !typeName.contains("char") && !typeName.contains("unicode")) {
                continue;
            }

            String value = data.getDefaultValueRepresentation();
            if (value == null || value.length() < 4) continue;

            // Remove surrounding quotes
            if (value.startsWith("\"") && value.endsWith("\"")) {
                value = value.substring(1, value.length() - 1);
            }

            totalStrings++;
            Address addr = data.getAddress();

            // Find functions that reference this string
            List<String> referencingFunctions = new ArrayList<>();
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(addr);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Function func = currentProgram.getFunctionManager()
                    .getFunctionContaining(ref.getFromAddress());
                if (func != null) {
                    referencingFunctions.add(func.getName());
                }
            }

            StringEntry entry = new StringEntry(addr.toString(), value, referencingFunctions);
            allStrings.add(entry);

            if (INTERESTING_PATTERN.matcher(value).find()) {
                interestingStrings.add(entry);
            }
        }

        println("Total strings: " + totalStrings);
        println("Interesting strings: " + interestingStrings.size());

        // Write all strings with xrefs
        File allFile = new File(outDir, "strings-xrefs-all.txt");
        PrintWriter allWriter = new PrintWriter(new FileWriter(allFile));
        allWriter.println("=== All Strings with Cross-References ===");
        allWriter.println("Binary: " + currentProgram.getName());
        allWriter.println("Total: " + allStrings.size());
        allWriter.println();

        for (StringEntry entry : allStrings) {
            allWriter.println("Address: " + entry.address);
            allWriter.println("Value: " + truncate(entry.value, 200));
            if (!entry.referencedBy.isEmpty()) {
                allWriter.println("Referenced by: " + String.join(", ", entry.referencedBy));
            } else {
                allWriter.println("Referenced by: (none — possibly dead string)");
            }
            allWriter.println();
        }
        allWriter.close();

        // Write interesting strings
        File interestingFile = new File(outDir, "strings-xrefs-interesting.txt");
        PrintWriter intWriter = new PrintWriter(new FileWriter(interestingFile));
        intWriter.println("=== Interesting Strings with Cross-References ===");
        intWriter.println("Binary: " + currentProgram.getName());
        intWriter.println("Total: " + interestingStrings.size());
        intWriter.println();
        intWriter.println("These strings match patterns for URLs, API keys, secrets, auth,");
        intWriter.println("crypto, and cloud services. Review each with its referencing functions.");
        intWriter.println();

        // Group by category
        Map<String, List<StringEntry>> categorized = new LinkedHashMap<>();
        categorized.put("URLs", new ArrayList<>());
        categorized.put("Auth/Credentials", new ArrayList<>());
        categorized.put("Crypto", new ArrayList<>());
        categorized.put("Cloud Services", new ArrayList<>());
        categorized.put("Other", new ArrayList<>());

        for (StringEntry entry : interestingStrings) {
            String v = entry.value.toLowerCase();
            if (v.contains("http") || v.contains("wss") || v.contains(".com/") || v.contains(".io/")) {
                categorized.get("URLs").add(entry);
            } else if (v.contains("auth") || v.contains("token") || v.contains("login") || v.contains("password") || v.contains("bearer") || v.contains("oauth") || v.contains("jwt")) {
                categorized.get("Auth/Credentials").add(entry);
            } else if (v.contains("crypt") || v.contains("hash") || v.contains("aes") || v.contains("rsa") || v.contains("md5") || v.contains("sha")) {
                categorized.get("Crypto").add(entry);
            } else if (v.contains("firebase") || v.contains("aws") || v.contains("azure") || v.contains("google") || v.contains("cognito") || v.contains("stripe")) {
                categorized.get("Cloud Services").add(entry);
            } else {
                categorized.get("Other").add(entry);
            }
        }

        for (Map.Entry<String, List<StringEntry>> cat : categorized.entrySet()) {
            if (cat.getValue().isEmpty()) continue;
            intWriter.println("== " + cat.getKey() + " (" + cat.getValue().size() + ") ==");
            intWriter.println();
            for (StringEntry entry : cat.getValue()) {
                intWriter.println("  [" + entry.address + "] " + truncate(entry.value, 150));
                if (!entry.referencedBy.isEmpty()) {
                    intWriter.println("    -> " + String.join(", ", entry.referencedBy));
                }
            }
            intWriter.println();
        }
        intWriter.close();

        println("String xref analysis complete.");
        println("Reports: " + outDir.getAbsolutePath());
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    private static class StringEntry {
        String address;
        String value;
        List<String> referencedBy;

        StringEntry(String address, String value, List<String> referencedBy) {
            this.address = address;
            this.value = value;
            this.referencedBy = referencedBy;
        }
    }
}
