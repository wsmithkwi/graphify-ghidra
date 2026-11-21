// Live, read-only queries against an already-analysed Ghidra Program.
//
// Two ways to run it, both with `analyzeHeadless <proj> <name> -process <program>
// -noanalysis -readOnly` so the (expensive) analysis done by GraphifyGhidraExport is
// reused:
//
//   one-shot   <out.json> <mode> [key:value ...]        one query, then exit (~20s: JVM startup)
//   server     serve <info.json> <token> [idle:SEC]     stay up and answer requests over a
//                                                       localhost socket (~50ms per query)
//
// Server protocol: one JSON object per line.
//   request   {"token": "...", "mode": "decompile", "addrs": ["0x401000"], "opts": {"chars": "4000"}}
//   response  {"mode": ..., "program": ..., "results": [...]}      or {"error": "..."}
//   mode "quit" stops the server. The socket is bound to 127.0.0.1 only and every request
//   must carry the random token written to <info.json>.
//
// Modes: decompile (timeout, chars) | disasm (limit) | xrefs (direction, limit)
//
// @category GraphifyGhidra

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Writer;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;

public class GraphifyGhidraQuery extends GhidraScript {

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().create();
    private static final int MAX_REQUEST_BYTES = 1 << 20;
    private DecompInterface decompiler;   // opened lazily, kept warm in server mode

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args == null || args.length < 2) {
            printerr("usage: GraphifyGhidraQuery <out.json> <mode> [key:value ...]  |  serve <info.json> <token> [idle:SEC]");
            return;
        }
        try {
            if (args[0].equals("serve")) {
                serve(args);
            } else {
                oneShot(args);
            }
        } finally {
            if (decompiler != null) decompiler.dispose();
        }
    }

    // ------------------------------------------------------------------ drivers

    private void oneShot(String[] args) throws Exception {
        File out = new File(args[0]);
        String mode = args[1].toLowerCase();
        Map<String, String> opts = new HashMap<>();
        for (int i = 2; i < args.length; i++) {
            String a = args[i];
            int c = a.indexOf(':');
            if (c > 0) {
                opts.put(a.substring(0, c).toLowerCase(), a.substring(c + 1));
            } else if (i + 1 < args.length && !args[i + 1].contains(":")) {
                opts.put(a.toLowerCase(), args[++i]);
            }
        }
        List<String> addrs = new ArrayList<>();
        String v = opts.get("addrs");
        if (v != null) for (String s : v.split(",")) if (!s.isBlank()) addrs.add(s.trim());
        JsonObject doc = handle(mode, addrs, opts);
        File parent = out.getAbsoluteFile().getParentFile();
        if (parent != null) parent.mkdirs();
        try (Writer w = Files.newBufferedWriter(out.toPath(), StandardCharsets.UTF_8)) {
            GSON.toJson(doc, w);
        }
        println("GraphifyGhidraQuery: " + mode + " done -> " + out);
    }

    private void serve(String[] args) throws Exception {
        File info = new File(args[1]);
        String token = args[2];
        long idleMs = 900_000L;
        for (int i = 3; i < args.length; i++) {
            if (args[i].toLowerCase().startsWith("idle:")) idleMs = Long.parseLong(args[i].substring(5)) * 1000L;
        }
        try (ServerSocket server = new ServerSocket(0, 8, InetAddress.getLoopbackAddress())) {
            server.setSoTimeout(1000);
            JsonObject meta = new JsonObject();
            meta.addProperty("port", server.getLocalPort());
            meta.addProperty("token", token);
            meta.addProperty("program", currentProgram.getName());
            // Written last, atomically: the client polls for this file as the "ready" signal.
            File tmp = new File(info.getPath() + ".tmp");
            Files.writeString(tmp.toPath(), GSON.toJson(meta), StandardCharsets.UTF_8);
            Files.move(tmp.toPath(), info.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            println("GraphifyGhidraQuery: serving on 127.0.0.1:" + server.getLocalPort());

            long lastUse = System.currentTimeMillis();
            while (!monitor.isCancelled()) {
                Socket s;
                try {
                    s = server.accept();
                } catch (java.net.SocketTimeoutException e) {
                    if (System.currentTimeMillis() - lastUse > idleMs) {
                        println("GraphifyGhidraQuery: idle timeout, shutting down");
                        break;
                    }
                    continue;
                }
                lastUse = System.currentTimeMillis();
                boolean quit = false;
                try (Socket sock = s) {
                    sock.setSoTimeout(30_000);
                    BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream(), StandardCharsets.UTF_8));
                    PrintWriter outw = new PrintWriter(new OutputStreamWriter(sock.getOutputStream(), StandardCharsets.UTF_8), true);
                    String line = readBounded(in);
                    JsonObject resp;
                    try {
                        JsonObject req = JsonParser.parseString(line).getAsJsonObject();
                        if (!token.equals(req.has("token") ? req.get("token").getAsString() : "")) {
                            resp = error("bad token");
                        } else if ("quit".equals(req.get("mode").getAsString())) {
                            quit = true;
                            resp = new JsonObject();
                            resp.addProperty("mode", "quit");
                        } else {
                            List<String> addrs = new ArrayList<>();
                            if (req.has("addrs")) for (JsonElement e : req.getAsJsonArray("addrs")) addrs.add(e.getAsString());
                            Map<String, String> opts = new HashMap<>();
                            if (req.has("opts")) for (Map.Entry<String, JsonElement> e : req.getAsJsonObject("opts").entrySet()) {
                                opts.put(e.getKey().toLowerCase(), e.getValue().getAsString());
                            }
                            resp = handle(req.get("mode").getAsString().toLowerCase(), addrs, opts);
                        }
                    } catch (Exception e) {
                        resp = error(e.toString());
                    }
                    outw.println(GSON.toJson(resp));
                } catch (Exception e) {
                    // A broken client connection must not take the server down.
                }
                if (quit) break;
            }
        } finally {
            info.delete();
        }
    }

    private static String readBounded(BufferedReader in) throws Exception {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = in.read()) != -1 && c != '\n') {
            sb.append((char) c);
            if (sb.length() > MAX_REQUEST_BYTES) throw new Exception("request too large");
        }
        return sb.toString();
    }

    private static JsonObject error(String msg) {
        JsonObject o = new JsonObject();
        o.addProperty("error", msg);
        return o;
    }

    private JsonObject handle(String mode, List<String> addrs, Map<String, String> opts) throws Exception {
        JsonObject doc = new JsonObject();
        doc.addProperty("mode", mode);
        doc.addProperty("program", currentProgram.getName());
        switch (mode) {
            case "decompile": doc.add("results", decompile(addrs, opts)); break;
            case "disasm": doc.add("results", disasm(addrs, opts)); break;
            case "xrefs": doc.add("results", xrefs(addrs, opts)); break;
            case "ping": break;
            default: doc.addProperty("error", "unknown mode " + mode);
        }
        return doc;
    }

    // ------------------------------------------------------------------ helpers

    private int intOpt(Map<String, String> opts, String k, int def) {
        try { return Integer.parseInt(opts.getOrDefault(k, "" + def)); } catch (Exception e) { return def; }
    }

    private Address parse(String s) {
        try {
            if (s.contains(":")) return currentProgram.getAddressFactory().getAddress(s);
            String h = s.toLowerCase().startsWith("0x") ? s.substring(2) : s;
            AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
            return sp.getAddress(Long.parseUnsignedLong(h, 16));
        } catch (Exception e) {
            return null;
        }
    }

    private String addr(Address a) {
        if (a == null) return null;
        if (a.getAddressSpace().equals(currentProgram.getAddressFactory().getDefaultAddressSpace())) {
            return "0x" + Long.toHexString(a.getOffset());
        }
        return a.getAddressSpace().getName() + ":0x" + Long.toHexString(a.getOffset());
    }

    private Function fnAt(Address a) {
        Function f = currentProgram.getFunctionManager().getFunctionContaining(a);
        return f != null ? f : currentProgram.getFunctionManager().getFunctionAt(a);
    }

    // ---------------------------------------------------------------- decompile

    private JsonArray decompile(List<String> addrs, Map<String, String> opts) throws Exception {
        JsonArray results = new JsonArray();
        int timeout = intOpt(opts, "timeout", 30);
        int chars = intOpt(opts, "chars", 12000);
        if (decompiler == null) {
            DecompInterface ifc = new DecompInterface();
            if (!ifc.openProgram(currentProgram)) {
                results.add(error("decompiler unavailable: " + ifc.getLastMessage()));
                return results;
            }
            decompiler = ifc;
        }
        for (String s : addrs) {
            monitor.checkCancelled();
            JsonObject o = new JsonObject();
            o.addProperty("query", s);
            Address a = parse(s);
            Function f = a == null ? null : fnAt(a);
            if (f == null) {
                o.addProperty("error", "no function at or containing " + s);
                results.add(o);
                continue;
            }
            o.addProperty("address", addr(f.getEntryPoint()));
            o.addProperty("name", f.getName());
            o.addProperty("signature", f.getPrototypeString(false, false));
            try {
                DecompileResults r = decompiler.decompileFunction(f, timeout, monitor);
                if (r == null || !r.decompileCompleted() || r.getDecompiledFunction() == null) {
                    o.addProperty("error", r == null ? "decompile failed" : String.valueOf(r.getErrorMessage()));
                } else {
                    String c = r.getDecompiledFunction().getC();
                    o.addProperty("pseudo_c_lines", c.split("\n").length);
                    o.addProperty("pseudo_c_total_chars", c.length());
                    boolean cut = c.length() > chars;
                    o.addProperty("pseudo_c", cut ? c.substring(0, chars) : c);
                    o.addProperty("pseudo_c_truncated", cut);
                    HighFunction hf = r.getHighFunction();
                    if (hf != null) {
                        JsonArray vars = new JsonArray();
                        LocalSymbolMap lm = hf.getLocalSymbolMap();
                        java.util.Iterator<HighSymbol> it = lm.getSymbols();
                        while (it.hasNext() && vars.size() < 80) {
                            HighSymbol hs = it.next();
                            JsonObject vo = new JsonObject();
                            vo.addProperty("name", hs.getName());
                            vo.addProperty("type", hs.getDataType() == null ? "undefined" : hs.getDataType().getDisplayName());
                            vo.addProperty("param", hs.isParameter());
                            vars.add(vo);
                        }
                        o.add("variables", vars);
                    }
                }
            } catch (Exception e) {
                o.addProperty("error", e.toString());
            }
            results.add(o);
        }
        return results;
    }

    // ------------------------------------------------------------------ disasm

    private JsonArray disasm(List<String> addrs, Map<String, String> opts) throws Exception {
        JsonArray results = new JsonArray();
        int limit = intOpt(opts, "limit", 120);
        Listing listing = currentProgram.getListing();
        for (String s : addrs) {
            JsonObject o = new JsonObject();
            o.addProperty("query", s);
            Address a = parse(s);
            Function f = a == null ? null : fnAt(a);
            if (f == null) {
                o.addProperty("error", "no function at or containing " + s);
                results.add(o);
                continue;
            }
            o.addProperty("address", addr(f.getEntryPoint()));
            o.addProperty("name", f.getName());
            JsonArray lines = new JsonArray();
            int total = 0;
            InstructionIterator ii = listing.getInstructions(f.getBody(), true);
            while (ii.hasNext()) {
                Instruction ins = ii.next();
                total++;
                if (lines.size() >= limit) continue;
                JsonObject l = new JsonObject();
                l.addProperty("address", addr(ins.getAddress()));
                l.addProperty("text", ins.toString());
                String eol = listing.getComment(ghidra.program.model.listing.CommentType.EOL, ins.getAddress());
                if (eol != null) l.addProperty("comment", eol);
                StringBuilder refs = new StringBuilder();
                for (Reference r : ins.getReferencesFrom()) {
                    Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(r.getToAddress());
                    if (sym == null) continue;
                    if (refs.length() > 0) refs.append(", ");
                    refs.append(sym.getName());
                    if (refs.length() > 120) break;
                }
                if (refs.length() > 0) l.addProperty("refs", refs.toString());
                lines.add(l);
            }
            o.addProperty("instruction_count", total);
            o.addProperty("truncated", total > lines.size());
            o.add("lines", lines);
            results.add(o);
        }
        return results;
    }

    // ------------------------------------------------------------------- xrefs

    private JsonArray xrefs(List<String> addrs, Map<String, String> opts) throws Exception {
        JsonArray results = new JsonArray();
        int limit = intOpt(opts, "limit", 40);
        String direction = opts.getOrDefault("direction", "both");
        ReferenceManager rm = currentProgram.getReferenceManager();
        for (String s : addrs) {
            JsonObject o = new JsonObject();
            o.addProperty("query", s);
            Address a = parse(s);
            if (a == null) {
                o.addProperty("error", "bad address " + s);
                results.add(o);
                continue;
            }
            o.addProperty("address", addr(a));
            if (!direction.equals("from")) {
                JsonArray to = new JsonArray();
                int total = 0;
                ReferenceIterator it = rm.getReferencesTo(a);
                while (it.hasNext()) {
                    Reference r = it.next();
                    total++;
                    if (to.size() < limit) to.add(refObj(r));
                }
                o.add("to", to);
                o.addProperty("to_total", total);
            }
            if (!direction.equals("to")) {
                JsonArray from = new JsonArray();
                int total = 0;
                Function f = fnAt(a);
                if (f != null && f.getEntryPoint().equals(a)) {
                    InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
                    while (ii.hasNext()) {
                        for (Reference r : ii.next().getReferencesFrom()) {
                            if (r.getReferenceType().isFlow() && !r.getReferenceType().isCall()) continue; // skip local jumps
                            if (r.getToAddress().isStackAddress()) continue;                              // stack slots are noise
                            total++;
                            if (from.size() < limit) from.add(refObj(r));
                        }
                    }
                } else {
                    for (Reference r : rm.getReferencesFrom(a)) {
                        total++;
                        if (from.size() < limit) from.add(refObj(r));
                    }
                }
                o.add("from", from);
                o.addProperty("from_total", total);
            }
            results.add(o);
        }
        return results;
    }

    private JsonObject refObj(Reference r) {
        JsonObject o = new JsonObject();
        o.addProperty("from", addr(r.getFromAddress()));
        o.addProperty("to", addr(r.getToAddress()));
        o.addProperty("type", r.getReferenceType().getName());
        o.addProperty("call", r.getReferenceType().isCall());
        o.addProperty("data", r.getReferenceType().isData());
        o.addProperty("write", r.getReferenceType().isWrite());
        Function ff = fnAt(r.getFromAddress());
        if (ff != null) {
            o.addProperty("from_function", ff.getName());
            o.addProperty("from_function_address", addr(ff.getEntryPoint()));
        }
        Symbol ts = currentProgram.getSymbolTable().getPrimarySymbol(r.getToAddress());
        if (ts != null) o.addProperty("to_symbol", ts.getName());
        return o;
    }
}
