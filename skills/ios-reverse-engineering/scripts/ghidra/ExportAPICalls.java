// ExportAPICalls.java — Ghidra headless script
// Finds networking API calls and traces their callers via cross-references
// Usage: analyzeHeadless <project> <name> -process <binary> -postScript ExportAPICalls.java <output_dir>
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

public class ExportAPICalls extends GhidraScript {

    private static final String[] NETWORK_SYMBOLS = {
        // URLSession
        "NSURLSession", "URLSession", "NSURLConnection", "NSURLRequest", "NSMutableURLRequest",
        "dataTaskWithRequest", "dataTaskWithURL", "uploadTaskWithRequest", "downloadTaskWithRequest",
        // Alamofire
        "AF_request", "SessionManager", "ServerTrustManager", "ServerTrustEvaluating",
        // CFNetwork
        "CFHTTPMessageCreateRequest", "CFStreamCreatePairWithSocketToHost",
        "CFURLCreateWithString", "CFHTTPMessageSetHeaderFieldValue",
        // WebSocket
        "NSURLSessionWebSocketTask", "webSocketTaskWithURL",
        // Low-level
        "connect", "send", "recv", "socket", "getaddrinfo",
    };

    private static final Pattern URL_PATTERN = Pattern.compile(
        "https?://[a-zA-Z0-9._/\\-?&=#+%:@]+|wss?://[a-zA-Z0-9._/\\-?&=#+%:@]+"
    );

    private static final Pattern ENDPOINT_PATTERN = Pattern.compile(
        "(?i)(/api/|/v[0-9]+/|/graphql|/auth/|/login|/register|/token|/oauth|/webhook)"
    );

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("Usage: ExportAPICalls.java <output_dir>");
            return;
        }

        String outputDir = args[0];
        File outDir = new File(outputDir);
        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        SymbolTable symbolTable = currentProgram.getSymbolTable();
        Map<String, List<String>> apiCallers = new LinkedHashMap<>();
        Set<String> discoveredURLs = new TreeSet<>();
        Set<String> discoveredEndpoints = new TreeSet<>();

        // Phase 1: Find network-related symbols and their cross-references
        println("Phase 1: Finding network API symbols and callers...");
        for (String symName : NETWORK_SYMBOLS) {
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
                    }
                }

                if (!callers.isEmpty()) {
                    apiCallers.put(symName + " @ " + sym.getAddress(), callers);
                }
            }
        }

        // Also search for symbols containing network-related keywords
        SymbolIterator allSymbols = symbolTable.getAllSymbols(true);
        Pattern networkPattern = Pattern.compile(
            "(?i)(URL|HTTP|request|session|network|api|endpoint|fetch|download|upload|socket|connect|websocket)"
        );
        while (allSymbols.hasNext()) {
            Symbol sym = allSymbols.next();
            if (networkPattern.matcher(sym.getName()).find()) {
                Function func = currentProgram.getFunctionManager().getFunctionAt(sym.getAddress());
                if (func != null) {
                    List<String> callers = new ArrayList<>();
                    ReferenceIterator refs = currentProgram.getReferenceManager()
                        .getReferencesTo(sym.getAddress());
                    while (refs.hasNext()) {
                        Reference ref = refs.next();
                        Function caller = currentProgram.getFunctionManager()
                            .getFunctionContaining(ref.getFromAddress());
                        if (caller != null && !caller.equals(func)) {
                            callers.add(caller.getName() + " @ " + ref.getFromAddress());
                        }
                    }
                    if (!callers.isEmpty()) {
                        apiCallers.put(func.getName() + " @ " + sym.getAddress(), callers);
                    }
                }
            }
        }

        println("  Found " + apiCallers.size() + " network-related symbols with callers");

        // Phase 2: Extract URLs from decompiled code
        println("Phase 2: Extracting URLs from decompiled functions...");
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            try {
                DecompileResults results = decompiler.decompileFunction(func, 10, monitor);
                if (results != null && results.getDecompiledFunction() != null) {
                    String code = results.getDecompiledFunction().getC();
                    if (code != null) {
                        java.util.regex.Matcher urlMatcher = URL_PATTERN.matcher(code);
                        while (urlMatcher.find()) {
                            String url = urlMatcher.group();
                            discoveredURLs.add(url + " | found in: " + func.getName());
                        }

                        java.util.regex.Matcher endpointMatcher = ENDPOINT_PATTERN.matcher(code);
                        while (endpointMatcher.find()) {
                            discoveredEndpoints.add(endpointMatcher.group() + " | found in: " + func.getName());
                        }
                    }
                }
            } catch (Exception e) {
                // Skip
            }
        }
        decompiler.dispose();

        println("  URLs found: " + discoveredURLs.size());
        println("  Endpoints found: " + discoveredEndpoints.size());

        // Write reports
        File callersFile = new File(outDir, "api-callers.txt");
        PrintWriter callersWriter = new PrintWriter(new FileWriter(callersFile));
        callersWriter.println("=== Network API Call Analysis ===");
        callersWriter.println("Binary: " + currentProgram.getName());
        callersWriter.println();

        for (Map.Entry<String, List<String>> entry : apiCallers.entrySet()) {
            callersWriter.println("--- " + entry.getKey() + " ---");
            callersWriter.println("Called by:");
            for (String caller : entry.getValue()) {
                callersWriter.println("  " + caller);
            }
            callersWriter.println();
        }
        callersWriter.close();

        File urlsFile = new File(outDir, "discovered-urls.txt");
        PrintWriter urlsWriter = new PrintWriter(new FileWriter(urlsFile));
        urlsWriter.println("=== Discovered URLs ===");
        for (String url : discoveredURLs) {
            urlsWriter.println(url);
        }
        urlsWriter.println();
        urlsWriter.println("=== API Endpoints ===");
        for (String endpoint : discoveredEndpoints) {
            urlsWriter.println(endpoint);
        }
        urlsWriter.close();

        println("API call analysis complete.");
        println("Reports: " + outDir.getAbsolutePath());
    }
}
