# graphify-ghidra

Ghidra support for [graphify](https://github.com/Graphify-Labs/graphify), built to work alongside
[REA (Reverse Engineer Anything)](https://github.com/morluto/rea).

Point it at a binary and get a graphify knowledge graph of what the program *is*: functions, the
call graph, imports, strings, named globals, and **capabilities** (networking, injection, crypto,
anti-analysis, ...), plus a ranked "where do I start reading" report and call-chain queries that
actually follow calls.

```bash
pip install graphifyy          # graphify itself
pip install -e .               # this extension (from this directory)

export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.x_PUBLIC     # same variable REA uses
graphify-ghidra doctor
graphify-ghidra analyze ./target.exe --decompile 40
```

You get, in `graphify-out-ghidra/` (its own folder; see below):

| File | What |
|---|---|
| `graph.json` | An ordinary graphify graph. `graphify explain`/`path`, graphify's own graph loader (the one `graphify-mcp` uses) and `to_html` were verified against it; it merges with any source-code graph already in `graphify-out/`. Wiki export and a live `graphify-mcp` session were not exercised. |
| `GHIDRA_REPORT_<name>_<hash>.md` | Entry points, ranked starting points with reasons, capability matrix, libraries called, and a **Blind spots** section. |
| `ghidra/<scope>/pseudo/<addr>.c` | Full pseudo-C for the functions decompiled with `--decompile N`. |
| `ghidra/<name>.ghidra.json` | The raw `graphify-ghidra/1` export, re-ingestable without re-running Ghidra. |

```bash
graphify-ghidra callchain entry CryptEncrypt        # how does the entry point reach it?
graphify-ghidra callchain entry "Networking"        # ...or reach anything with a capability
graphify-ghidra callers WriteProcessMemory          # who calls it; entry points are marked
graphify-ghidra report target.ghidra.json           # triage report only, no graph
graphify-ghidra install-skill --apply               # Claude Code skill (dry run without --apply)
```

## Why not just `graphify path`?

In the full graph every function and import hangs off the binary node, so `graphify path A B`
returns the meaningless two-hop route `A <- binary -> B`. `callchain` and `callers` walk only
`calls` / `thunks_to` edges, using graphify's `_src`/`_tgt` so direction is right even in an
undirected graph. On a real binary (`whoami.exe`):

```
$ graphify-ghidra callchain entry LookupPrivilegeNameW
Chain 1 (5 calls):
     entry [0x140001cb0]
  -> FUN_140001af0 [0x140001af0]  [EXTRACTED]
  -> FUN_140002c4c [0x140002c4c]  [EXTRACTED]
  -> FUN_140007d18 [0x140007d18]  [EXTRACTED]
  -> FUN_1400033d0 [0x1400033d0]  [EXTRACTED]
  -> LookupPrivilegeNameW  [EXTRACTED]
```

## How it works

```
 Ghidra headless ──GraphifyGhidraExport.java──┐
 (read-only; project kept for live tools)    ├─> graphify-ghidra/1 JSON ─> Program ─> analysis ─> graphify extraction ─> graph.json
 saved REA results ──────rea_adapter.py───────┘      (one neutral doc)        index      roles,       nodes/edges/             (build_merge,
                                                                                         triage,      hyperedges               cluster, to_json)
                                                                                         capabilities
```

- `ghidra_scripts/GraphifyGhidraExport.java` runs under `analyzeHeadless` and walks the Program:
  functions, call sites (resolving through thunks and import slots), strings and their referrers,
  imports, exports, segments, named globals, basic-block complexity, optional decompilation.
  It never mutates or saves the Program.
- `capabilities.py` maps API names and string literals to behaviours. It is plain data, extendable
  with `register_api_rules(...)`.
- `analysis.py` computes reachability from entry points, roles (`entry`, `wrapper`, `dispatcher`,
  `hub`, `unreferenced`, `library`, ...) and a transparent triage score with the reasons attached.
- Statically linked CRT/STL code that Ghidra's Function ID analyzer matched gets the `library` role
  and is pushed down the ranking. Those matches are machine annotations, not analyst notes.

## An engine that names the program itself (agent tools)

The graph is only the substrate. The point is that an AI agent can drive it, **naming functions as it
understands them**, so a program with tens of thousands of anonymous functions becomes readable over
time, and so everything it learns survives a re-analysis.

Fifteen tools (`ghidra_*`), exposed to the [Pi](https://pi.dev) harness as native tools and runnable from
the shell as `graphify-ghidra tool <name> --args '{...}'`:

| Tool | Purpose |
|---|---|
| `analyze` | **Start a background Ghidra analysis of one binary** (the way into everything else; returns at once, keeps running if the session ends, poll `status`) |
| `status` | Coverage: functions named by whom, behaviours, links; what to do next. Before any analysis it reports the running job, or exactly how to start one |
| `worklist` | Next unnamed functions with context. **Bottom-up** by default: functions whose callees are already named are the easiest to resolve |
| `function` | One function's dossier: callers, callees, APIs, strings, globals, types, similar code, hints |
| `refs` | **Pull references** to/from a function, string, import or global. Hard cap (default 40, max 200), `offset` paging, `incoming`/`outgoing`, `live=true` for instruction-level xrefs from Ghidra |
| `name` | Name functions, globals and *variables* in batches (max 80), with `confidence` and `evidence`. `note` marks "examined, unclear" so a function leaves the worklist |
| `suggest` | Rule-based hints; `apply_wrappers` auto-names unambiguous thunks and thin wrappers |
| `similar` | Functionally similar code across the whole graph and across binaries |
| `propagate` | Carry known names onto near-copies (same binary, or from a symbolised build onto a stripped one). Dry run by default |
| `link` | Assert what static analysis cannot see: `similar`, `related`, `shares_data`, `implements`, `variant_of`, or `calls` (an indirect call you resolved) |
| `behavior` | Group the functions that implement one job, nested with `parent`; `candidates` proposes groups from graph communities |
| `decompile` | Live pseudo-C from a **warm Ghidra** (about 0.1s after a one-time start) with your names and variable names substituted |
| `disasm`, `search`, `callchain` | Live disassembly; search names, strings, APIs, constants, pseudo-C; how X reaches Y |

**Encouraging the naming loop.** Every tool result ends with a coverage line telling the agent how many functions
are still `FUN_xxxx` and to name what it understands now, even at `confidence: low`. The Pi extension adds the
same protocol to the system prompt whenever the project has a Ghidra graph (static text, so provider caching
still works), and the skill spells out the worklist -> read -> name -> propagate -> group loop and a
naming/confidence rubric.

**What "native graphify connections" means here.** Names, behaviours and links are written into graphify's own
relation vocabulary, so every graphify consumer sees them:

| Understanding | Graph representation |
|---|---|
| Functionally similar code | `semantically_similar_to` (INFERRED, score = confidence, per-feature breakdown as context), within and across binaries |
| Two functions communicating through a global | `shares_data_with` (writer -> reader, EXTRACTED) |
| Functions that operate on the same struct | both `references` the same `datatype` node (struct-typed params, locals, returns) |
| Renamed variables | `variable` nodes with `contains` from the function and `references` to their type |
| A behaviour (feature/subsystem) | a `concept` node; members `implements` it; a hyperedge groups them; `conceptually_related_to` nests sub-behaviours |
| An indirect call you resolved | `calls` (INFERRED) with your rationale |

All of it lives in per-binary annotation stores (`<out>/ghidra/annotations/<scope>.json`) and is
**re-applied to `graph.json` after every change and every re-ingest**, so re-analysing a binary resets
Ghidra's names but never your work. Provenance is recorded for every name (`analyst`, `ai`, `heuristic`,
`propagated`), with confidence and evidence. A weaker claim never displaces a stronger one, a name an analyst
set in Ghidra is protected unless `force`, and propagated names are never themselves propagation sources
(no runaway chains).

### Functional similarity

Matching has to survive recompilation, so it uses: the **mnemonic stream** (operands stripped, 4-gram
shingles, MinHash + band-LSH), normalised **pseudo-C statements** (variable names erased, constants and callee
names kept), the **API set**, large **constants**, and referenced **strings**; scored as a weighted mean of exact
Jaccard over the features both functions have. Boilerplate buckets (a shared prologue) are skipped rather than
enumerated. A score is "very probably the same routine", not proof.

### Speed: where the time actually goes

| Stage | Cost | Fix |
|---|---|---|
| Ghidra analysis | 40-80s for a small binary | Java; unavoidable, done once, project kept |
| Each live query (decompile, disasm, xrefs) | ~22s (JVM + project open) | **Warm Ghidra server**: one resident headless process over a token-authenticated loopback socket. 0.13s decompile, ~10ms xrefs/disasm, after a one-time ~40s start |
| Similarity at scale | Python/numpy: 11s at 20k functions and growing | **Rust engine** (`engine/`, rayon): below |

Measured on 8 cores (synthetic functions with planted near-duplicates; the Python fallback produces the same
pair sets, scores within 1e-4):

| functions | Python (numpy) | Rust (multithreaded) | speedup |
|---|---|---|---|
| 5,000 | 2.5s | 0.23s | 11x |
| 20,000 | 11.1s | 0.66s | 17x |
| 100,000 | not run (extrapolates to minutes) | 2.6s | - |

The engine is optional: without it the same code runs in Python. Build it with `graphify-ghidra build-engine`
(needs a Rust toolchain; `--offline` builds from a local cargo cache). It is found via `$GG_ENGINE`, the
package `bin/`, a dev build, or `PATH`.

### Where the data goes, and your existing graphify graph

Ghidra results default to **`./graphify-out-ghidra`**, not `./graphify-out`. In a project that already has a graphify
graph (of its source code, say) that folder is yours, and a binary analysis must not be merged into it by accident. So:

- `analyze` / `ingest` never write into a `graph.json` that holds no analysed binary unless you pass
  `--merge-into-existing`; `analyze` checks this **before** starting Ghidra, not after a long run.
- The same rule is mirrored in the Pi extension. An existing `./graphify-out` that already holds Ghidra data (older
  installs) is still used. `GRAPHIFY_GHIDRA_OUT` overrides everything.
- The native `graphify_*` tools keep reading your normal graph; point them at the Ghidra graph with `project_path`
  or `GRAPHIFY_GRAPH` if you want graphify's generic queries over it.

**Starting from nothing.** An agent in a project with no analysis calls `ghidra_status`, which says so and how to start;
`ghidra_analyze {binary: "<absolute path>"}` starts a detached job (`<out>/ghidra/job.json` + `job.log`; reported
`RUNNING` / `done` / `failed` / `died`). A 98 KB utility took about a minute and curl.exe (830 KB) under two; large DLLs
take far longer, and I have not timed one. The analysis is only needed once per binary: names, behaviours and links
persist and survive a re-analysis.

**Names stay in the graph.** They are not written back into the Ghidra database or into REA's session. REA's own docs say
its Windows Ghidra provider is read-only, so on Windows that path is closed regardless. If REA is your main tool, treat
graphify-ghidra as the persistent memory and naming layer beside it, not a replacement for REA's session.

### Install into Pi

```bash
uv tool install --editable .          # isolated env; does not touch an existing graphify install
graphify-ghidra install-pi            # dry run: shows exactly what will change
graphify-ghidra install-pi --apply    # backs up settings.json, runs `pi install`, records the command path
```

The same package also gives Pi **native `graphify_*` and `rea_*` tools** (no MCP adapter proxy), driven by a small
built-in MCP client that launches the servers from your existing `~/.pi/agent/mcp.json` / `~/.config/mcp/mcp.json`
entries and registers their real tools with their real schemas:

- `graphify_*`: all of `graphify-mcp`'s tools (`query_graph`, `get_node`, `get_neighbors`, `shortest_path`,
  `god_nodes`, `graph_stats`, ...) against `$GRAPHIFY_GRAPH`, else `<cwd>/graphify-out/graph.json`, else the graph in your
  graphify MCP entry. Read-only. `/graphify` shows which graph is in use.
- `rea_*`: REA has ~255 tools, too many for a model to see at once, so there is `rea_tools` (search the catalogue or fetch
  one tool's schema), `rea_call` (call any REA tool; output capped; tools that run, instrument or change a target ask for
  confirmation, and are refused when there is no UI), and 14 everyday read-only tools promoted to direct `rea_<tool>`
  tools (`open_binary`, `list_procedures`, `analyze_function`, `procedure_pseudo_code`, `xrefs`, ...). REA starts on first
  use and stays up for the session so an opened binary persists; the catalogue is cached so the direct tools exist at
  session start. `/rea` connects and reports the tool count.

Then, in a project, `graphify-ghidra analyze ./target.exe` and start Pi there. The extension keeps one
`graphify-ghidra tool-server` alive for the session (graph and Ghidra stay warm) and stops it on exit. `/ghidra`
shows coverage. Set `GRAPHIFY_GHIDRA_OUT` to use a different output folder. Only
mutating tools (`name`, `link`, `behavior`, `propagate`, `suggest apply`) write, and only into the Ghidra nodes of
the graph; a `graph.json` with no Ghidra data is left alone (tools report "no Ghidra data").

## `compact_context`: the agent compacts its own context, and is told

A Pi tool (not Ghidra-specific) that lets the agent choose to compact once its context is **at 80% or more**:

- **Gate:** below the threshold it refuses and reports usage; above it, it schedules compaction. `check_only` reports
  usage without acting; `focus` tells the summary what must survive. `PI_COMPACT_MIN_PERCENT` (1-100) overrides 80.
- **`check_context`:** a read-only tool that reports usage (tokens and %), whether compaction is allowed yet and how far
  off it is, and **when Pi will compact on its own**, estimated from `settings.json` the way Pi resolves it (per-model
  `provider/modelId` override, else `compaction.reserveTokens`, else 16,384; global and project merged). If Pi's automatic
  point falls below the agent's threshold it says so plainly: the agent will never get to choose.
- **Awareness:** the agent cannot see its own usage, so it gets a one-time warning message when it crosses the threshold
  (re-armed only after usage drops 10 points).
- **The `<context_budget>` tag:** a system-prompt section (a custom Pi section, so static text and cache-friendly) that
  frames all of this as budgeting time, not anxiety: use `check_context` sparingly and loosely, never economise or wrap up
  early, and compact only at a good time (a unit of work finished, progress saved outside the context, never mid-edit or
  mid-investigation), because a late compaction at a good time beats an early one at a bad time. The same wording is in
  both tools' descriptions, the 80% warning ("you do not have to compact immediately"), and a one-line note on every
  `check_context` result.
- **Timing:** Pi's `ctx.compact()` calls `abort()` on the running agent, so a tool calling it directly would kill the run
  that is executing it. The tool therefore records the request and ends the turn; compaction starts from `agent_settled`,
  when the agent is idle. An aborted run (Escape) drops the request rather than compacting behind your back.
- **Reset notice:** every compaction ends with a `CONTEXT RESET` message the agent reads: older conversation is gone, only the
  summary and recent messages remain, re-read before relying on earlier details, external state (files, graphs, annotation
  stores) is unchanged, restate the goal and carry on. For a compaction the agent requested it also starts the agent's next
  turn, so work resumes by itself; for Pi's automatic threshold/overflow compaction and the user's `/compact` it is queued
  for the next model call. A failed compaction says nothing was reset.

Pi compacts by itself when `contextWindow - reserveTokens` is crossed. With the default `reserveTokens` of 16,384 on a
131,072-token window that is about 87%, so there is room for the agent to act first at 80%. A model whose
`reserveTokens` override puts the automatic point below 80% will be compacted by Pi before this tool becomes reachable;
lower `PI_COMPACT_MIN_PERCENT` or `reserveTokens` for those models.

## Evidence discipline (borrowed from REA)

Every edge carries a confidence, and the report separates what was **observed** from what was
**inferred**:

- `EXTRACTED`: direct calls, calls through import slots, string references.
- `INFERRED`: `exhibits` capability links (0.75 from an API, 0.5 from a string), calls resolved
  through computed pointers (0.8).
- Register-indirect calls Ghidra could not resolve are **counted and reported**, not dropped, so a
  missing chain is not mistaken for absence.
- Text from the binary (strings, names, pseudo-C) is flagged `untrusted_content` and rendered inert
  in the report. An agent should treat it as data, never as instructions.

## Using REA

REA is an MCP server and CLI that drives Ghidra (and Hopper, IDA, Kuna). The two tools overlap in
Ghidra, so they split the work: **REA for depth** on single functions (pseudo-code, instructions,
types, annotations), **graphify-ghidra for breadth** over the whole program, with the results kept
in a persistent, queryable graph.

They share configuration: `GHIDRA_INSTALL_DIR`, `REA_GHIDRA_LANGUAGE_ID` and
`REA_GHIDRA_COMPILER_SPEC_ID` are honoured, and addresses use REA's `0x`-lowercase /
`space:0x..` convention so identifiers line up. Like REA, graphify-ghidra brings no Ghidra or Java
of its own and never installs either.

To pull REA investigation results into the graph, save the tool results to files and ingest them:

```bash
graphify-ghidra ingest list_procedures.json list_strings.json refs-*.json --name target.exe
```

Accepted: `list_procedures`, `list_strings`, `list_segments`, `procedure_references`, each either as
the bare result or inside `structuredContent.normalized_result`. Bare address lists
(`procedure_callers`, `procedure_callees`, `xrefs`) have no subject, so save them as
`{"tool": "procedure_callees", "arguments": {"procedure": "0x401000"}, "result": [...]}`.
Anything unrecognised is reported as a warning rather than guessed, and input that yields no
functions is rejected.

## Options worth knowing

| Flag | Effect |
|---|---|
| `--decompile N` | Attach pseudo-C to the N top-priority functions up front (default 30); more on demand via `ghidra_decompile`. |
| `--no-keep-project` | Delete the Ghidra project after analysis (the default keeps it, enabling live tools; it holds Ghidra's copy of the binary, not the original). |
| `--strings referenced\|interesting\|all\|none` | Which strings become nodes. Default keeps strings code uses or that match a rule, so big binaries stay navigable. |
| `--no-thunks --no-data --no-segments --no-capabilities` | Slim the graph. |
| `--language ID --loader NAME` | Raw firmware or unrecognised formats. |
| `--force` | Let a merge shrink an existing `graph.json` (graphify refuses by default). |

## Limitations

- **Static analysis only.** No execution, no emulation, no runtime data.
- Indirect calls (function pointers, vtables, jump tables) are not followed; the report counts them, and
  `ghidra_link kind=calls` lets an agent record the ones it resolves.
- Capability tagging and similarity are heuristics. Statically linked or obfuscated imports, and API resolution
  by hash, defeat the former; heavy obfuscation or very short functions (< 10 instructions) defeat the latter.
- Only strings Ghidra defined are visible. Packed, encrypted and stack-built strings are not.
- Pseudo-C is Ghidra's reconstruction (types and control flow can be wrong); the export truncates it to 1500
  characters per function, `ghidra_decompile` returns up to 12000 on demand.
- Names the agent assigns are claims with a confidence, not facts. `propagate` and `suggest` names are tagged
  by provenance so they can be audited.
- Every mutation re-reads and rewrites `graph.json`. That is a second or two on a few-thousand-function graph;
  on a 100k-function graph expect a few seconds per batch, which is why `ghidra_name` takes up to 80 names per call.
- `GraphifyGhidraExport.java` / `GraphifyGhidraQuery.java` are tested against **Ghidra 12.2 on Windows (x86-64
  PE)** only. Other versions, architectures and ELF/Mach-O targets are untested here.
- **The REA adapter has not been run against live REA output.** It is written against REA's Ghidra bridge source
  and docs and tested on payloads shaped from them. Report mismatches.
- **The Pi integration is verified up to the model**: Pi loads the package, registers all 14 tools with schemas it
  accepts, and `/ghidra` runs end to end through the installed tool-server. A model-driven session (a real LLM
  choosing and calling the tools) has not been run, so how well a given local model follows the naming protocol is
  untested.
- The warm Ghidra server holds the project open; opening the same project in the Ghidra GUI at the same time
  hits Ghidra's project lock. It exits by itself after 15 idle minutes, and on tool-server shutdown.
- If graphify's `build_merge` shrink guard refuses a write, the CLI exits non-zero and says why.

## Tests

```bash
pip install -e ".[dev]"
pytest                                           # ~210 tests, no Ghidra needed (Rust parity tests need the engine)
GRAPHIFY_GHIDRA_INTEGRATION=1 pytest -k real_ghidra   # runs real Ghidra on a stock system binary
```

## Not in scope (yet)

- Writing names or comments back into a Ghidra database (REA's annotation tools are the right path; the names live in
  graphify-out and can be exported from `ghidra/annotations/*.json`).
- Diffing two versions of a binary.
- Hopper, IDA and Kuna sources (REA supports them; the adapter only reads Ghidra-shaped results).
