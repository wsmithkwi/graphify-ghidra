// Export a Ghidra Program as a graphify-ghidra/1 JSON document.
//
// Read-only: never mutates the Program, never saves it. Designed to run as a
// -postScript under analyzeHeadless against an ephemeral project, but it also
// works from the Script Manager in the GUI (it then asks for an output file).
//
// Script arguments (all optional, order-independent after the first):
//   <out.json>            output path (required headless; GUI prompts)
//   decompile=N           decompile up to N functions (largest/most-called
//                         first); 0 = off (default). Pseudo-C is truncated.
//   decompile_timeout=S   per-function decompiler timeout in seconds (def 20)
//   pseudo_chars=N        max pseudo-C chars kept per function (def 1500)
//   max_strings=N         cap on exported strings (def 50000)
//   max_string_len=N      cap on characters kept per string (def 512)
//   max_data_refs=N       cap on data-symbol refs kept per function (def 64)
//   max_mnemonics=N       cap on mnemonics kept per function for similarity (def 3000)
//   max_locals=N          cap on local variables kept per function (def 40)
//
// @category GraphifyGhidra

import java.io.File;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class GraphifyGhidraExport extends GhidraScript {

    private static final String SCHEMA = "graphify-ghidra/1";

    private Listing listing;
    private ReferenceManager refMgr;
    private SymbolTable symTab;

    private int decompileLimit = 0;
    private int decompileTimeout = 20;
    private int pseudoChars = 1500;
    private int maxStrings = 50000;
    private int maxStringLen = 512;
    private int maxDataRefs = 64;
    private int maxMnemonics = 3000;
    private int maxLocals = 40;

    /** String data address -> index of its row in the strings array. */
    private final Map<Address, JsonObject> stringsByAddress = new HashMap<>();

    @Override
    protected void run() throws Exception {
        listing = currentProgram.getListing();
        refMgr = currentProgram.getReferenceManager();
        symTab = currentProgram.getSymbolTable();

        File out = parseArgs();
        if (out == null) {
            printerr("GraphifyGhidraExport: no output path given");
            return;
        }

        JsonObject doc = new JsonObject();
        doc.addProperty("schema", SCHEMA);
        doc.add("producer", producer());
        doc.add("program", programInfo());
        doc.add("segments", segments());

        // Strings first so functions can attach references to them.
        JsonArray strings = strings();
        JsonArray imports = imports();

        Map<Address, Function> functionByEntry = new HashMap<>();
        List<Function> functions = new ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function f = it.next();
            functions.add(f);
            functionByEntry.put(f.getEntryPoint(), f);
        }

        Set<Address> entryPoints = new HashSet<>();
        AddressIterator epIt = symTab.getExternalEntryPointIterator();
        while (epIt.hasNext()) entryPoints.add(epIt.next());

        JsonArray fnArray = new JsonArray();
        JsonArray callArray = new JsonArray();
        Map<Address, Integer> inDegree = new HashMap<>();
        // Call edges are collected during the function pass; in-degree is
        // needed afterwards to pick decompile candidates.
        List<JsonObject> fnObjects = new ArrayList<>();
        for (Function f : functions) {
            monitor.checkCancelled();
            JsonObject fo = functionObject(f, entryPoints.contains(f.getEntryPoint()), callArray, inDegree);
            fnObjects.add(fo);
            fnArray.add(fo);
        }

        if (decompileLimit > 0) {
            decompileTop(functions, fnObjects, inDegree);
        }

        doc.add("functions", fnArray);
        doc.add("calls", callArray);
        doc.add("imports", imports);
        doc.add("exports", exports());
        doc.add("strings", strings);
        doc.add("data", namedData());

        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        File parent = out.getAbsoluteFile().getParentFile();
        if (parent != null) parent.mkdirs();
        try (Writer w = Files.newBufferedWriter(out.toPath(), StandardCharsets.UTF_8)) {
            gson.toJson(doc, w);
        }
        println("GraphifyGhidraExport: wrote " + fnArray.size() + " functions, "
            + callArray.size() + " calls, " + strings.size() + " strings, "
            + imports.size() + " imports -> " + out);
    }

    // ------------------------------------------------------------------ args

    private File parseArgs() throws Exception {
        String[] args = getScriptArgs();
        File out = null;
        if (args != null) {
            // analyzeHeadless.bat on Windows splits "key=value" at the '=' (cmd.exe
            // treats '=' as an argument delimiter), so a value can arrive as the
            // next token. Accept key=value, key:value and the split "key" "value".
            Set<String> known = Set.of("decompile", "decompile_timeout", "pseudo_chars",
                "max_strings", "max_string_len", "max_data_refs", "max_mnemonics", "max_locals", "out");
            List<String> tokens = new ArrayList<>();
            for (int i = 0; i < args.length; i++) {
                String a = args[i];
                int eq = a.indexOf('=');
                int colon = a.indexOf(':');
                if (eq > 0) {
                    tokens.add(a.substring(0, eq).trim().toLowerCase());
                    tokens.add(a.substring(eq + 1).trim());
                } else if (colon > 0 && known.contains(a.substring(0, colon).trim().toLowerCase())) {
                    tokens.add(a.substring(0, colon).trim().toLowerCase());
                    tokens.add(a.substring(colon + 1).trim());
                } else {
                    tokens.add(a);
                }
            }
            for (int i = 0; i < tokens.size(); i++) {
                String t = tokens.get(i);
                if (!known.contains(t.toLowerCase())) {
                    if (out == null) out = new File(t);
                    continue;
                }
                if (i + 1 >= tokens.size()) {
                    printerr("GraphifyGhidraExport: option " + t + " needs a value");
                    break;
                }
                String k = t.toLowerCase();
                String v = tokens.get(++i);
                try {
                    switch (k) {
                        case "decompile": decompileLimit = Integer.parseInt(v); break;
                        case "decompile_timeout": decompileTimeout = Integer.parseInt(v); break;
                        case "pseudo_chars": pseudoChars = Integer.parseInt(v); break;
                        case "max_strings": maxStrings = Integer.parseInt(v); break;
                        case "max_string_len": maxStringLen = Integer.parseInt(v); break;
                        case "max_data_refs": maxDataRefs = Integer.parseInt(v); break;
                        case "max_mnemonics": maxMnemonics = Integer.parseInt(v); break;
                        case "max_locals": maxLocals = Integer.parseInt(v); break;
                        case "out": out = new File(v); break;
                        default: printerr("GraphifyGhidraExport: ignoring unknown option " + k);
                    }
                } catch (NumberFormatException e) {
                    printerr("GraphifyGhidraExport: bad value for " + k + ": " + v);
                }
            }
        }
        if (out == null && !isRunningHeadless()) {
            out = askFile("Export graphify-ghidra JSON", "Save");
        }
        return out;
    }

    // -------------------------------------------------------------- metadata

    private JsonObject producer() {
        JsonObject p = new JsonObject();
        p.addProperty("name", "GraphifyGhidraExport");
        p.addProperty("ghidra_version", Application.getApplicationVersion());
        p.addProperty("ghidra_release", Application.getApplicationReleaseName());
        return p;
    }

    private JsonObject programInfo() {
        JsonObject p = new JsonObject();
        p.addProperty("name", currentProgram.getName());
        p.addProperty("executable_path", currentProgram.getExecutablePath());
        p.addProperty("format", currentProgram.getExecutableFormat());
        p.addProperty("md5", currentProgram.getExecutableMD5());
        p.addProperty("sha256", currentProgram.getExecutableSHA256());
        p.addProperty("language", currentProgram.getLanguageID().getIdAsString());
        p.addProperty("processor", currentProgram.getLanguage().getProcessor().toString());
        p.addProperty("endian", currentProgram.getLanguage().isBigEndian() ? "big" : "little");
        p.addProperty("pointer_size", currentProgram.getDefaultPointerSize());
        p.addProperty("compiler", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
        p.addProperty("image_base", addr(currentProgram.getImageBase()));
        p.addProperty("function_count", currentProgram.getFunctionManager().getFunctionCount());
        return p;
    }

    private JsonArray segments() {
        JsonArray arr = new JsonArray();
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            JsonObject o = new JsonObject();
            o.addProperty("name", b.getName());
            o.addProperty("start", addr(b.getStart()));
            o.addProperty("end", addr(b.getEnd()));
            o.addProperty("size", b.getSize());
            o.addProperty("read", b.isRead());
            o.addProperty("write", b.isWrite());
            o.addProperty("execute", b.isExecute());
            o.addProperty("initialized", b.isInitialized());
            o.addProperty("overlay", b.isOverlay());
            arr.add(o);
        }
        return arr;
    }

    // -------------------------------------------------------------- functions

    private JsonObject functionObject(Function f, boolean isEntry, JsonArray callArray,
                                      Map<Address, Integer> inDegree) throws Exception {
        JsonObject o = new JsonObject();
        Address entry = f.getEntryPoint();
        o.addProperty("address", addr(entry));
        o.addProperty("name", f.getName());
        o.addProperty("qualified_name", f.getName(true));
        o.addProperty("signature", f.getPrototypeString(false, false));
        o.addProperty("calling_convention", f.getCallingConventionName());
        o.addProperty("return_type", f.getReturn().getDataType().getName());
        o.addProperty("param_count", f.getParameterCount());
        o.addProperty("size", f.getBody().getNumAddresses());
        o.addProperty("is_thunk", f.isThunk());
        o.addProperty("is_external", f.isExternal());
        o.addProperty("is_entry", isEntry);
        o.addProperty("no_return", f.hasNoReturn());
        o.addProperty("is_inline", f.isInline());
        o.addProperty("has_varargs", f.hasVarArgs());
        Symbol sym = f.getSymbol();
        SourceType src = sym == null ? SourceType.DEFAULT : sym.getSource();
        o.addProperty("name_source", src.toString());
        o.addProperty("user_named", src == SourceType.USER_DEFINED);
        o.addProperty("auto_named", src == SourceType.DEFAULT);
        String comment = f.getComment();
        if (comment != null && !comment.isBlank()) o.addProperty("comment", comment);
        String repeatable = f.getRepeatableComment();
        if (repeatable != null && !repeatable.isBlank()) o.addProperty("repeatable_comment", repeatable);
        if (f.getParentNamespace() != null && !f.getParentNamespace().isGlobal()) {
            o.addProperty("namespace", f.getParentNamespace().getName(true));
        }

        if (f.isThunk()) {
            Function target = f.getThunkedFunction(true);
            if (target != null) {
                o.addProperty("thunk_target", addr(target.getEntryPoint()));
                o.addProperty("thunk_target_name", target.getName());
                if (target.isExternal()) {
                    ExternalLocation el = target.getExternalLocation();
                    if (el != null) o.addProperty("thunk_library", el.getLibraryName());
                }
            }
        }
        if (f.isExternal()) {
            ExternalLocation el = f.getExternalLocation();
            if (el != null) {
                o.addProperty("library", el.getLibraryName());
                o.addProperty("original_name", el.getOriginalImportedName());
            }
            return o; // no body to walk
        }

        // Walk the body once for instructions, calls, string and data refs.
        Set<String> stringRefs = new LinkedHashSet<>();
        Set<String> dataRefs = new LinkedHashSet<>();
        Set<String> apiCalls = new LinkedHashSet<>();
        Set<String> dataWrites = new LinkedHashSet<>();
        Set<String> constants = new LinkedHashSet<>();
        StringBuilder mnemonics = new StringBuilder();
        int mnemonicCount = 0;
        int instrCount = 0;
        int callSites = 0;
        int unresolvedSites = 0;
        int indirectCalls = 0;
        InstructionIterator ii = listing.getInstructions(f.getBody(), true);
        while (ii.hasNext()) {
            Instruction ins = ii.next();
            instrCount++;
            // Similarity features: the mnemonic stream (operands stripped, so it survives
            // re-linking and register allocation changes) and large scalar constants.
            if (mnemonicCount < maxMnemonics) {
                if (mnemonicCount > 0) mnemonics.append(' ');
                mnemonics.append(ins.getMnemonicString().toLowerCase());
                mnemonicCount++;
            }
            if (constants.size() < 48) {
                for (int op = 0; op < ins.getNumOperands(); op++) {
                    ghidra.program.model.scalar.Scalar sc = ins.getScalar(op);
                    if (sc == null) continue;
                    long v = sc.getUnsignedValue();
                    if (v < 0x10000L) continue; // small immediates carry no signal
                    Address asAddr = null;
                    try { asAddr = f.getEntryPoint().getNewAddress(v); } catch (Exception e) { /* not an address */ }
                    if (asAddr != null && currentProgram.getMemory().contains(asAddr)) continue; // pointer, not a magic number
                    constants.add("0x" + Long.toHexString(v));
                }
            }
            boolean isCall = ins.getFlowType().isCall();
            boolean sawCallRef = false;
            for (Reference ref : ins.getReferencesFrom()) {
                RefType rt = ref.getReferenceType();
                if (isCall && rt.isCall()) {
                    sawCallRef = true;
                    callSites++;
                    JsonObject ce = resolveCall(f, ins.getAddress(), ref);
                    // "Indirect" means the target is chosen at runtime (function
                    // pointer, vtable, register). A call through an import slot
                    // (CALL [IAT]) is computed in Ghidra's flow types but its target
                    // is fixed at load time, so it is not counted as indirect.
                    if ((rt.isComputed() || rt.isIndirect()) && ce != null && !ce.has("external_name")) {
                        indirectCalls++;
                    }
                    if (ce != null) {
                        callArray.add(ce);
                        if (ce.has("to")) {
                            Address to = parseAddr(ce.get("to").getAsString());
                            if (to != null) inDegree.merge(to, 1, Integer::sum);
                        }
                        if (ce.has("external_name")) apiCalls.add(ce.get("external_name").getAsString());
                    }
                    continue;
                }
                Address to = ref.getToAddress();
                if (to == null || !to.isMemoryAddress()) continue;
                if (rt.isData() || rt.isRead() || rt.isWrite() || rt.isIndirect()) {
                    JsonObject s = stringsByAddress.get(to);
                    if (s != null) {
                        // Per-function dedupe: a function referencing one string from
                        // several instructions still counts as a single reference.
                        if (stringRefs.add(addr(to))) {
                            s.getAsJsonArray("refs").add(addr(entry));
                        }
                        continue;
                    }
                    if (dataRefs.size() < maxDataRefs) {
                        Data d = listing.getDefinedDataAt(to);
                        if (d != null) {
                            Symbol ds = symTab.getPrimarySymbol(to);
                            boolean keep = false;
                            if (ds != null && ds.getSource() != SourceType.DEFAULT) {
                                keep = true;
                            } else if (d.getBaseDataType() != null && d.isPointer()) {
                                keep = true;
                            }
                            if (keep) {
                                dataRefs.add(addr(to));
                                if (rt.isWrite()) dataWrites.add(addr(to));
                            }
                        }
                    }
                }
            }
            if (isCall && !sawCallRef) {
                // Register/memory-indirect call (CALL RAX, CALL [RBX+8]): Ghidra has
                // no reference to follow. Record it so the blind spot is explicit
                // instead of the call silently vanishing from the graph.
                unresolvedSites++;
                indirectCalls++;
                JsonObject ue = new JsonObject();
                ue.addProperty("from", addr(entry));
                ue.addProperty("call_site", addr(ins.getAddress()));
                ue.addProperty("kind", ins.getFlowType().getName());
                ue.addProperty("unresolved", true);
                ue.addProperty("reason", "no_resolved_target");
                callArray.add(ue);
            }
        }
        o.addProperty("instruction_count", instrCount);
        o.addProperty("call_sites", callSites + unresolvedSites);
        o.addProperty("indirect_calls", indirectCalls);
        addBlockMetrics(f, o);
        o.add("string_refs", toArray(stringRefs));
        o.add("data_refs", toArray(dataRefs));
        o.add("data_writes", toArray(dataWrites));
        o.add("api_calls", toArray(apiCalls));
        o.addProperty("mnemonics", mnemonics.toString());
        o.add("constants", toArray(constants));
        o.add("params", variables(f.getParameters(), 24));
        o.add("locals", variables(f.getLocalVariables(), maxLocals));
        return o;
    }

    /** Parameters / locals as {name, type, auto}. "auto" = still Ghidra's default name. */
    private JsonArray variables(ghidra.program.model.listing.Variable[] vars, int cap) {
        JsonArray arr = new JsonArray();
        for (ghidra.program.model.listing.Variable v : vars) {
            if (arr.size() >= cap) break;
            JsonObject vo = new JsonObject();
            vo.addProperty("name", v.getName());
            vo.addProperty("type", v.getDataType() == null ? "undefined" : v.getDataType().getDisplayName());
            vo.addProperty("auto", v.getSource() == SourceType.DEFAULT);
            arr.add(vo);
        }
        return arr;
    }

    private void addBlockMetrics(Function f, JsonObject o) {
        try {
            BasicBlockModel model = new BasicBlockModel(currentProgram);
            CodeBlockIterator blocks = model.getCodeBlocksContaining(f.getBody(), monitor);
            int nodes = 0;
            int edges = 0;
            while (blocks.hasNext()) {
                CodeBlock b = blocks.next();
                nodes++;
                CodeBlockReferenceIterator dests = b.getDestinations(monitor);
                while (dests.hasNext()) {
                    CodeBlockReference r = dests.next();
                    if (r.getFlowType().isCall()) continue;
                    if (f.getBody().contains(r.getDestinationAddress())) edges++;
                }
            }
            o.addProperty("block_count", nodes);
            o.addProperty("edge_count", edges);
            o.addProperty("cyclomatic_complexity", Math.max(1, edges - nodes + 2));
        } catch (Exception e) {
            // Metrics are best-effort; leave them out rather than fail the export.
        }
    }

    /** Resolve one call reference to a call-edge JSON object, or null. */
    private JsonObject resolveCall(Function caller, Address site, Reference ref) {
        JsonObject ce = new JsonObject();
        ce.addProperty("from", addr(caller.getEntryPoint()));
        ce.addProperty("call_site", addr(site));
        ce.addProperty("kind", ref.getReferenceType().getName());
        Address to = ref.getToAddress();

        Function target = to == null ? null : currentProgram.getFunctionManager().getFunctionAt(to);
        if (target == null && to != null && to.isExternalAddress()) {
            Symbol s = symTab.getPrimarySymbol(to);
            if (s != null) {
                ExternalLocation el = currentProgram.getExternalManager().getExternalLocation(s);
                if (el != null) {
                    stampExternal(ce, el);
                    return ce;
                }
            }
        }
        if (target == null && to != null) {
            // Indirect call through a pointer slot (IAT / GOT): follow the slot's
            // own references to find an external location or a function.
            for (Reference slotRef : refMgr.getReferencesFrom(to)) {
                if (slotRef.isExternalReference()) {
                    ExternalLocation el = ((ghidra.program.model.symbol.ExternalReference) slotRef).getExternalLocation();
                    if (el != null) {
                        stampExternal(ce, el);
                        return ce;
                    }
                }
                Function viaSlot = currentProgram.getFunctionManager().getFunctionAt(slotRef.getToAddress());
                if (viaSlot != null) {
                    target = viaSlot;
                    break;
                }
            }
        }
        if (target == null) {
            if (to != null) {
                Function inside = currentProgram.getFunctionManager().getFunctionContaining(to);
                if (inside != null) target = inside;
            }
        }
        if (target == null) {
            ce.addProperty("unresolved", true);
            if (to != null) ce.addProperty("target_address", addr(to));
            return ce;
        }

        if (target.isThunk()) {
            Function real = target.getThunkedFunction(true);
            ce.addProperty("via_thunk", addr(target.getEntryPoint()));
            if (real != null) target = real;
        }
        if (target.isExternal()) {
            ExternalLocation el = target.getExternalLocation();
            if (el != null) {
                stampExternal(ce, el);
                return ce;
            }
        }
        ce.addProperty("to", addr(target.getEntryPoint()));
        ce.addProperty("to_name", target.getName());
        return ce;
    }

    private void stampExternal(JsonObject ce, ExternalLocation el) {
        String name = el.getOriginalImportedName() != null ? el.getOriginalImportedName() : el.getLabel();
        ce.addProperty("external_name", name);
        ce.addProperty("external_library", el.getLibraryName());
        if (el.getAddress() != null) ce.addProperty("external_address", addr(el.getAddress()));
    }

    // -------------------------------------------------------------- imports

    private JsonArray imports() {
        JsonArray arr = new JsonArray();
        ExternalManager em = currentProgram.getExternalManager();
        Set<String> seen = new HashSet<>();
        for (String lib : em.getExternalLibraryNames()) {
            ExternalLocationIterator eli;
            try {
                eli = em.getExternalLocations(lib);
            } catch (Exception e) {
                continue;
            }
            while (eli.hasNext()) {
                ExternalLocation el = eli.next();
                String name = el.getOriginalImportedName() != null ? el.getOriginalImportedName() : el.getLabel();
                String key = lib + "::" + name;
                if (!seen.add(key)) continue;
                JsonObject o = new JsonObject();
                o.addProperty("name", name);
                o.addProperty("label", el.getLabel());
                o.addProperty("library", lib);
                if (el.getAddress() != null) o.addProperty("address", addr(el.getAddress()));
                o.addProperty("is_function", el.isFunction());
                arr.add(o);
            }
        }
        return arr;
    }

    private JsonArray exports() {
        JsonArray arr = new JsonArray();
        AddressIterator it = symTab.getExternalEntryPointIterator();
        while (it.hasNext()) {
            Address a = it.next();
            JsonObject o = new JsonObject();
            Symbol s = symTab.getPrimarySymbol(a);
            o.addProperty("address", addr(a));
            o.addProperty("name", s == null ? addr(a) : s.getName());
            Function f = currentProgram.getFunctionManager().getFunctionAt(a);
            o.addProperty("is_function", f != null);
            arr.add(o);
        }
        return arr;
    }

    // -------------------------------------------------------------- strings

    private JsonArray strings() throws Exception {
        JsonArray arr = new JsonArray();
        DataIterator di = listing.getDefinedData(true);
        while (di.hasNext() && arr.size() < maxStrings) {
            monitor.checkCancelled();
            Data d = di.next();
            if (!d.hasStringValue()) continue;
            StringDataInstance sdi = StringDataInstance.getStringDataInstance(d);
            String value = sdi == null ? null : sdi.getStringValue();
            if (value == null) value = d.getDefaultValueRepresentation();
            if (value == null || value.isEmpty()) continue;
            JsonObject o = new JsonObject();
            o.addProperty("address", addr(d.getAddress()));
            boolean truncated = value.length() > maxStringLen;
            o.addProperty("value", truncated ? value.substring(0, maxStringLen) : value);
            if (truncated) o.addProperty("truncated", true);
            o.addProperty("length", d.getLength());
            o.addProperty("type", d.getDataType().getName());
            o.add("refs", new JsonArray());
            arr.add(o);
            stringsByAddress.put(d.getAddress(), o);
        }
        return arr;
    }

    // ----------------------------------------------------- named data symbols

    private JsonArray namedData() {
        JsonArray arr = new JsonArray();
        DataIterator di = listing.getDefinedData(true);
        int cap = 20000;
        while (di.hasNext() && arr.size() < cap) {
            Data d = di.next();
            if (d.hasStringValue()) continue;
            Symbol s = symTab.getPrimarySymbol(d.getAddress());
            if (s == null || s.getSource() == SourceType.DEFAULT) continue;
            if (s.getSymbolType() != ghidra.program.model.symbol.SymbolType.LABEL) continue;
            JsonObject o = new JsonObject();
            o.addProperty("address", addr(d.getAddress()));
            o.addProperty("name", s.getName());
            o.addProperty("type", d.getDataType().getName());
            o.addProperty("size", d.getLength());
            o.addProperty("user_named", s.getSource() == SourceType.USER_DEFINED);
            JsonArray refs = new JsonArray();
            Set<Address> seenFns = new HashSet<>();
            for (Reference r : refMgr.getReferencesTo(d.getAddress())) {
                Function from = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
                if (from != null && seenFns.add(from.getEntryPoint())) refs.add(addr(from.getEntryPoint()));
                if (refs.size() >= 64) break;
            }
            o.add("refs", refs);
            arr.add(o);
        }
        return arr;
    }

    // ------------------------------------------------------------- decompile

    private void decompileTop(List<Function> functions, List<JsonObject> fnObjects,
                              Map<Address, Integer> inDegree) {
        DecompInterface ifc = new DecompInterface();
        try {
            if (!ifc.openProgram(currentProgram)) {
                printerr("GraphifyGhidraExport: decompiler unavailable: " + ifc.getLastMessage());
                return;
            }
            // Prefer functions that matter: many callers, many outgoing calls,
            // many string references. Skip tiny stubs and externals.
            List<Integer> order = new ArrayList<>();
            for (int i = 0; i < functions.size(); i++) {
                Function f = functions.get(i);
                if (f.isExternal() || f.isThunk()) continue;
                order.add(i);
            }
            Collections.sort(order, new Comparator<Integer>() {
                @Override
                public int compare(Integer a, Integer b) {
                    return Double.compare(score(functions.get(b), fnObjects.get(b), inDegree),
                                          score(functions.get(a), fnObjects.get(a), inDegree));
                }
            });
            int done = 0;
            int ok = 0;
            String lastError = null;
            for (int idx : order) {
                if (done >= decompileLimit || monitor.isCancelled()) break;
                Function f = functions.get(idx);
                try {
                    DecompileResults r = ifc.decompileFunction(f, decompileTimeout, monitor);
                    if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                        String c = r.getDecompiledFunction().getC();
                        if (c != null) {
                            JsonObject fo = fnObjects.get(idx);
                            boolean cut = c.length() > pseudoChars;
                            fo.addProperty("pseudo_c", cut ? c.substring(0, pseudoChars) : c);
                            if (cut) fo.addProperty("pseudo_c_truncated", true);
                            fo.addProperty("pseudo_c_lines", c.split("\n").length);
                            ok++;
                        }
                    } else if (r != null) {
                        lastError = r.getErrorMessage();
                    }
                } catch (Exception e) {
                    // One failing function must not abort the export.
                    lastError = e.toString();
                }
                done++;
            }
            println("GraphifyGhidraExport: decompiled " + ok + "/" + done + " functions"
                + (lastError == null ? "" : " (last error: " + lastError + ")"));
        } finally {
            ifc.dispose();
        }
    }

    private double score(Function f, JsonObject fo, Map<Address, Integer> inDegree) {
        double s = 0;
        s += 3.0 * inDegree.getOrDefault(f.getEntryPoint(), 0);
        s += fo.has("call_sites") ? fo.get("call_sites").getAsInt() : 0;
        s += fo.has("string_refs") ? 2.0 * fo.getAsJsonArray("string_refs").size() : 0;
        s += fo.has("api_calls") ? 4.0 * fo.getAsJsonArray("api_calls").size() : 0;
        if (fo.has("user_named") && fo.get("user_named").getAsBoolean()) s += 25;
        if (fo.has("is_entry") && fo.get("is_entry").getAsBoolean()) s += 50;
        return s;
    }

    // ---------------------------------------------------------------- helpers

    private static JsonArray toArray(Set<String> values) {
        JsonArray a = new JsonArray();
        for (String v : values) a.add(v);
        return a;
    }

    /** Lowercase 0x-hex for default-space addresses; "space:0x.." otherwise (REA convention). */
    private String addr(Address a) {
        if (a == null) return null;
        if (a.getAddressSpace().equals(currentProgram.getAddressFactory().getDefaultAddressSpace())) {
            return "0x" + Long.toHexString(a.getOffset());
        }
        return a.getAddressSpace().getName() + ":0x" + Long.toHexString(a.getOffset());
    }

    private Address parseAddr(String s) {
        try {
            if (s == null) return null;
            int colon = s.indexOf(':');
            if (colon < 0) {
                return currentProgram.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(Long.parseUnsignedLong(s.substring(2), 16));
            }
            return currentProgram.getAddressFactory().getAddress(s);
        } catch (Exception e) {
            return null;
        }
    }
}
