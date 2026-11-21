"""Persistent analyst/AI annotations, re-applied to the graph on every change.

Reverse engineering a large program is mostly *accumulating understanding*:
this function parses the config, that one is a thin wrapper around ``recv``,
these twelve together implement the update check. Raw Ghidra output has none of
that, and a re-analysis would throw it away. This module keeps it:

``names``      address -> name (+ confidence, evidence, who, history)
``variables``  ``<fn address>:<old name>`` -> new name / type
``behaviors``  slug -> label, description, member addresses, parent behaviour
``links``      asserted relations between functions/data (similar, shares data, ...)
``examined``   address -> note: "looked at it, still unclear" (keeps the worklist moving)

One JSON file per binary (``<out>/ghidra/annotations/<scope>.json``). Every
mutation is followed by :func:`reapply`, which regenerates all annotation-derived
graph content from the stores, so the graph and the stores can never drift and a
re-ingest of the binary cannot lose a name.

Provenance is first-class: every name records who set it (``analyst`` / ``ai`` /
``heuristic`` / ``propagated``), with what confidence, and on what evidence. An
analyst's name is never silently overwritten by an AI one, and a low-confidence
guess never displaces a high-confidence name.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import canon_addr

__all__ = [
    "AnnotationStore", "NameResult", "validate_name", "load_stores", "reapply",
    "CONFIDENCES", "LINK_KINDS",
]

CONFIDENCES = ("low", "medium", "high")
_RANK = {c: i + 1 for i, c in enumerate(CONFIDENCES)}
_SCORE = {"low": 0.4, "medium": 0.65, "high": 0.85}
_AUTHOR_RANK = {"heuristic": 0, "propagated": 1, "ai": 2, "analyst": 3}

# How an asserted link kind maps onto graphify's own edge vocabulary.
LINK_KINDS: dict[str, tuple[str, str]] = {
    "similar":       ("semantically_similar_to", "functionally similar"),
    "related":       ("conceptually_related_to", "related behaviour"),
    "shares_data":   ("shares_data_with", "shares data"),
    "implements":    ("implements", "implements"),
    "calls":         ("calls", "calls (asserted; e.g. indirect call resolved by hand)"),
    "variant_of":    ("semantically_similar_to", "variant of"),
}

_AUTO_NAME = re.compile(r"^(?:FUN|DAT|LAB|SUB|PTR|UNK|thunk_FUN|param|local|sub|loc|dat|fun)_?[0-9a-fA-F]+$")
_NAME_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,95}$")
MAX_HISTORY = 5


def validate_name(raw: Any) -> tuple[str | None, str | None]:
    """Normalise a proposed name. Returns ``(name, note)``; ``name`` is None if unusable.

    Names come from a language model and end up in graph labels, reports and
    pseudo-code substitutions, so they are restricted to C-identifier characters.
    """
    if not isinstance(raw, str):
        return None, "name must be a string"
    name = raw.strip()
    if not name:
        return None, "name is empty"
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", name).strip("_")
    cleaned = re.sub(r"_+", "_", cleaned)
    if not cleaned:
        return None, f"{raw!r} has no usable characters"
    if cleaned[0].isdigit():
        cleaned = "_" + cleaned
    cleaned = cleaned[:96]
    if _AUTO_NAME.match(cleaned):
        return None, f"{cleaned!r} looks like an auto-generated name; choose a descriptive one"
    note = f"normalised to {cleaned!r}" if cleaned != name else None
    return cleaned, note


@dataclass
class NameResult:
    address: str
    status: str            # named | renamed | kept | protected | invalid | unchanged
    name: str | None = None
    message: str = ""

    def line(self) -> str:
        tail = f" ({self.message})" if self.message else ""
        return f"{self.address}: {self.status}{' -> ' + self.name if self.name else ''}{tail}"


@dataclass
class AnnotationStore:
    path: Path
    scope: str
    data: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ io
    @classmethod
    def open(cls, out_dir: str | Path, scope: str) -> "AnnotationStore":
        path = Path(out_dir) / "ghidra" / "annotations" / f"{scope}.json"
        data: dict[str, Any] = {}
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                # Never silently start from empty: that would erase the user's work on save.
                raise ValueError(f"{path} is corrupted ({exc}); fix or move it aside") from exc
        data.setdefault("version", 1)
        data["scope"] = scope
        for key in ("names", "variables", "behaviors", "examined"):
            data.setdefault(key, {})
        data.setdefault("links", [])
        return cls(path, scope, data)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".ann-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=1, ensure_ascii=False)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    # ---------------------------------------------------------------- names
    @property
    def names(self) -> dict[str, dict[str, Any]]:
        return self.data["names"]

    def set_name(
        self, address: str, name: Any, *, confidence: str = "medium", evidence: Any = None,
        rationale: str = "", by: str = "ai", force: bool = False, protected: bool = False,
    ) -> NameResult:
        addr = canon_addr(address)
        if addr is None:
            return NameResult(str(address), "invalid", message="not an address")
        clean, note = validate_name(name)
        if clean is None:
            return NameResult(addr, "invalid", message=note or "bad name")
        if confidence not in _RANK:
            confidence = "medium"
        by = by if by in _AUTHOR_RANK else "ai"
        existing = self.names.get(addr)

        if protected and not force and by != "analyst":
            return NameResult(addr, "protected", clean,
                              "already named by an analyst in Ghidra; pass force=true to override")
        if existing and not force:
            old_rank = (_AUTHOR_RANK.get(existing.get("by", "ai"), 2), _RANK.get(existing.get("confidence", "low"), 1))
            new_rank = (_AUTHOR_RANK[by], _RANK[confidence])
            if existing["name"] == clean:
                # Same name: only strengthen the record, never weaken it.
                if new_rank > old_rank:
                    existing.update(confidence=confidence, by=by, evidence=_evidence(evidence) or existing.get("evidence"),
                                    rationale=rationale or existing.get("rationale", ""), ts=_now())
                    return NameResult(addr, "renamed", clean, "confidence raised")
                return NameResult(addr, "unchanged", clean)
            if new_rank < old_rank:
                return NameResult(addr, "kept", existing["name"],
                                  f"existing {existing.get('by')}/{existing.get('confidence')} name outranks "
                                  f"{by}/{confidence}; pass force=true to override")
        record = {
            "name": clean, "confidence": confidence, "by": by, "ts": _now(),
            "evidence": _evidence(evidence), "rationale": (rationale or "")[:600],
        }
        if existing:
            hist = list(existing.get("history", []))
            hist.append({"name": existing["name"], "by": existing.get("by"), "confidence": existing.get("confidence")})
            record["history"] = hist[-MAX_HISTORY:]
        self.names[addr] = record
        self.data["examined"].pop(addr, None)   # naming it settles "examined"
        return NameResult(addr, "renamed" if existing else "named", clean, note or "")

    def clear_name(self, address: str) -> bool:
        addr = canon_addr(address)
        return bool(addr and self.names.pop(addr, None))

    # ----------------------------------------------------------- variables
    def set_variable(self, fn_address: str, old: str, new: Any, *, type_: str | None = None,
                     note: str = "", by: str = "ai") -> NameResult:
        addr = canon_addr(fn_address)
        if addr is None:
            return NameResult(str(fn_address), "invalid", message="not an address")
        clean, msg = validate_name(new)
        if clean is None:
            return NameResult(f"{addr}:{old}", "invalid", message=msg or "bad name")
        key = f"{addr}:{old}"
        existed = key in self.data["variables"]
        self.data["variables"][key] = {"function": addr, "old": old, "name": clean,
                                       "type": (type_ or "")[:80] or None, "note": note[:300], "by": by, "ts": _now()}
        return NameResult(key, "renamed" if existed else "named", clean)

    # -------------------------------------------------------------- examined
    def mark_examined(self, address: str, note: str = "") -> None:
        addr = canon_addr(address)
        if addr and addr not in self.names:
            self.data["examined"][addr] = {"note": note[:400], "ts": _now()}

    # ------------------------------------------------------------- behaviors
    def set_behavior(self, slug: str, *, label: str | None = None, description: str | None = None,
                     members: list[str] | None = None, add_members: list[str] | None = None,
                     remove_members: list[str] | None = None, parent: str | None = None,
                     confidence: str = "medium", evidence: Any = None) -> tuple[str, str]:
        slug_c = re.sub(r"[^a-z0-9_]+", "_", str(slug).lower()).strip("_")[:60]
        if not slug_c:
            return "", "behavior id must contain letters or digits"
        b = self.data["behaviors"].setdefault(slug_c, {"label": slug_c.replace("_", " "), "description": "",
                                                       "members": [], "parent": None, "confidence": "medium",
                                                       "evidence": []})
        if label:
            b["label"] = label.strip()[:120]
        if description is not None:
            b["description"] = description.strip()[:1000]
        if confidence in _RANK:
            b["confidence"] = confidence
        if evidence:
            b["evidence"] = _evidence(evidence)
        cur = list(b["members"])
        if members is not None:
            cur = []
        for a in (members or []) + (add_members or []):
            c = canon_addr(a)
            if c and c not in cur:
                cur.append(c)
        for a in remove_members or []:
            c = canon_addr(a)
            if c in cur:
                cur.remove(c)
        b["members"] = cur
        if parent is not None:
            p = re.sub(r"[^a-z0-9_]+", "_", parent.lower()).strip("_")
            if p == slug_c:
                return slug_c, "a behaviour cannot be its own parent"
            if p and p in self.data["behaviors"] and _ancestor(self.data["behaviors"], p, slug_c):
                return slug_c, f"{p!r} is already a sub-behaviour of {slug_c!r}; that would make a cycle"
            b["parent"] = p or None
        b["ts"] = _now()
        return slug_c, ""

    # ---------------------------------------------------------------- links
    def add_link(self, a: str, b: str, kind: str, *, confidence: str = "medium", rationale: str = "",
                 by: str = "ai") -> tuple[bool, str]:
        """``a``/``b`` are ``scope:0xaddr`` or bare ``0xaddr`` (this store's scope)."""
        if kind not in LINK_KINDS:
            return False, f"kind must be one of {sorted(LINK_KINDS)}"
        ea, eb = self._endpoint(a), self._endpoint(b)
        if not ea or not eb:
            return False, "endpoints must be addresses (optionally scope:address)"
        if ea == eb:
            return False, "a link needs two different endpoints"
        if confidence not in _RANK:
            confidence = "medium"
        for ln in self.data["links"]:
            if ln["a"] == ea and ln["b"] == eb and ln["kind"] == kind:
                ln.update(confidence=confidence, rationale=rationale[:400] or ln.get("rationale", ""), ts=_now())
                return True, "updated"
        self.data["links"].append({"a": ea, "b": eb, "kind": kind, "confidence": confidence,
                                   "rationale": rationale[:400], "by": by, "ts": _now()})
        return True, "added"

    def _endpoint(self, value: str) -> str | None:
        if not isinstance(value, str):
            return None
        if ":0x" in value and not value.startswith("0x"):
            scope, _, addr = value.rpartition(":")
            c = canon_addr(addr)
            return f"{scope}:{c}" if c and scope else None
        c = canon_addr(value)
        return f"{self.scope}:{c}" if c else None

    # ------------------------------------------------------------- coverage
    def counts(self) -> dict[str, int]:
        return {"names": len(self.names), "variables": len(self.data["variables"]),
                "behaviors": len(self.data["behaviors"]), "links": len(self.data["links"]),
                "examined": len(self.data["examined"])}


def _ancestor(behaviors: dict[str, Any], start: str, target: str) -> bool:
    seen: set[str] = set()
    cur: str | None = start
    while cur and cur not in seen:
        if cur == target:
            return True
        seen.add(cur)
        cur = (behaviors.get(cur) or {}).get("parent")
    return False


def _evidence(value: Any) -> list[str]:
    if value is None:
        return []
    items = value if isinstance(value, (list, tuple)) else [value]
    return [str(v)[:200] for v in items if str(v).strip()][:8]


def _now() -> int:
    return int(time.time())


def load_stores(out_dir: str | Path) -> dict[str, AnnotationStore]:
    d = Path(out_dir) / "ghidra" / "annotations"
    stores: dict[str, AnnotationStore] = {}
    if d.is_dir():
        for p in sorted(d.glob("*.json")):
            stores[p.stem] = AnnotationStore.open(out_dir, p.stem)
    return stores


# ============================================================ graph application

_ORIGIN = "annotation"


def reapply(graph: dict[str, Any], stores: dict[str, AnnotationStore]) -> dict[str, int]:
    """Regenerate every annotation-derived part of ``graph`` (a loaded graph.json dict).

    Idempotent: previous annotation output is removed first, so calling it after
    any store change (or after a re-ingest that reset the labels) converges to the
    same graph. Returns counts of what was applied.
    """
    nodes: list[dict[str, Any]] = graph.setdefault("nodes", [])
    links_key = "links" if "links" in graph or "edges" not in graph else "edges"
    links: list[dict[str, Any]] = graph.setdefault(links_key, [])
    hyper = graph.setdefault("hyperedges", [])

    # 1. drop previous output ------------------------------------------------
    removed_ids = {n["id"] for n in nodes if (n.get("metadata") or {}).get("origin") == _ORIGIN}
    nodes[:] = [n for n in nodes if n["id"] not in removed_ids]
    links[:] = [e for e in links if e.get("origin") != _ORIGIN
                and e.get("source") not in removed_ids and e.get("target") not in removed_ids]
    hyper[:] = [h for h in hyper if h.get("origin") != _ORIGIN]
    if isinstance(graph.get("graph"), dict):
        graph["graph"]["hyperedges"] = hyper

    by_id = {n["id"]: n for n in nodes}
    index: dict[tuple[str, str], str] = {}     # (scope, address) -> node id (functions, thunks, data)
    for n in nodes:
        m = n.get("metadata") or {}
        if m.get("ghidra_kind") in ("function", "thunk", "data") and m.get("scope") and m.get("address"):
            index[(m["scope"], m["address"])] = n["id"]

    # 2. restore auto labels, then apply names -----------------------------------
    for n in nodes:
        m = n.get("metadata") or {}
        if m.get("ai_name") or m.get("original_label"):
            n["label"] = m.get("original_label") or n["label"]
            for k in ("ai_name", "name_confidence", "name_evidence", "named_by", "name_rationale"):
                m.pop(k, None)
    used_labels = {(n.get("metadata") or {}).get("scope"): set() for n in nodes}
    for n in nodes:
        used_labels.setdefault((n.get("metadata") or {}).get("scope"), set()).add(n.get("label"))

    applied_names = 0
    for scope, store in stores.items():
        for addr, rec in store.names.items():
            nid = index.get((scope, addr))
            if not nid:
                continue
            n = by_id[nid]
            m = n.setdefault("metadata", {})
            m.setdefault("original_label", n["label"])
            label = rec["name"]
            taken = used_labels.setdefault(scope, set())
            if label in taken:
                label = f"{label} @{addr}"
            taken.add(label)
            n["label"] = label
            m.update(ai_name=True, name_confidence=rec["confidence"], named_by=rec.get("by", "ai"),
                     name_evidence=rec.get("evidence") or None, name_rationale=(rec.get("rationale") or None))
            applied_names += 1

    # 3. variables -------------------------------------------------------------
    applied_vars = 0
    type_nodes: set[str] = set()
    for scope, store in stores.items():
        for v in store.data["variables"].values():
            fid = index.get((scope, v["function"]))
            if not fid:
                continue
            fn = by_id[fid]
            vid = f"{fid}__var_{v['old']}"
            label = f"{fn['label'].split(' @')[0]}::{v['name']}"
            nodes.append(_node(vid, label, "variable", fn, scope=scope, address=v["function"], original=v["old"],
                               data_type=v.get("type"), note=v.get("note") or None, named_by=v.get("by")))
            by_id[vid] = nodes[-1]
            links.append(_edge(fid, vid, "contains", fn, context=f"variable {v['old']} -> {v['name']}"))
            if v.get("type"):
                tid = "ghidra_type_" + re.sub(r"[^a-z0-9]+", "_", v["type"].lower()).strip("_")
                if tid not in by_id:
                    nodes.append(_node(tid, v["type"], "datatype", fn, scope=None, address=None))
                    by_id[tid] = nodes[-1]
                    type_nodes.add(tid)
                links.append(_edge(vid, tid, "references", fn, context="variable type"))
            applied_vars += 1

    # 4. behaviors ----------------------------------------------------------------
    applied_beh = 0
    for scope, store in stores.items():
        for slug, b in store.data["behaviors"].items():
            bid = f"ghidra_{scope}_behavior_{slug}"
            any_node = next((by_id[index[(scope, a)]] for a in b["members"] if (scope, a) in index), None)
            src_file = (any_node or {}).get("source_file", "")
            nodes.append({"id": bid, "label": b["label"], "file_type": "concept", "source_file": src_file,
                          "source_location": None,
                          "metadata": {"ghidra_kind": "behavior", "origin": _ORIGIN, "scope": scope, "slug": slug,
                                       "description": b.get("description") or None, "confidence": b.get("confidence"),
                                       "member_count": len(b["members"]), "evidence": b.get("evidence") or None}})
            by_id[bid] = nodes[-1]
            member_ids = []
            for a in b["members"]:
                fid = index.get((scope, a))
                if fid:
                    member_ids.append(fid)
                    links.append(_edge(fid, bid, "implements", by_id[fid], confidence="INFERRED",
                                       score=_SCORE.get(b.get("confidence", "medium"), 0.65),
                                       context=f"member of behaviour '{b['label']}'"))
            if b.get("parent"):
                pid = f"ghidra_{scope}_behavior_{b['parent']}"
                if pid in by_id or b["parent"] in store.data["behaviors"]:
                    links.append({**_edge(bid, pid, "conceptually_related_to", by_id[bid], confidence="INFERRED",
                                          score=0.8, context="sub-behaviour of"), "source_file": src_file})
            if len(member_ids) >= 3:
                hyper.append({"id": f"{bid}_group", "label": b["label"], "nodes": member_ids, "relation": "implement",
                              "confidence": "INFERRED", "confidence_score": _SCORE.get(b.get("confidence", "medium"), 0.65),
                              "source_file": src_file, "origin": _ORIGIN})
            applied_beh += 1
    # parent links need both endpoints; drop any whose parent node never materialised
    ids = {n["id"] for n in nodes}
    links[:] = [e for e in links if e["source"] in ids and e["target"] in ids]

    # 5. asserted links ---------------------------------------------------------------
    applied_links = 0
    for store in stores.values():
        for ln in store.data["links"]:
            sa, _, aa = ln["a"].rpartition(":")
            sb, _, ab = ln["b"].rpartition(":")
            ia, ib = index.get((sa, aa)), index.get((sb, ab))
            if not ia or not ib:
                continue
            relation, phrase = LINK_KINDS[ln["kind"]]
            why = ln.get("rationale") or ""
            links.append(_edge(ia, ib, relation, by_id[ia], confidence="INFERRED",
                               score=_SCORE.get(ln.get("confidence", "medium"), 0.65),
                               context=f"{ln.get('by', 'ai')}: {phrase}" + (f" - {why}" if why else "")))
            applied_links += 1

    return {"names": applied_names, "variables": applied_vars, "behaviors": applied_beh, "links": applied_links}


def _node(nid: str, label: str, kind: str, near: dict[str, Any], **meta: Any) -> dict[str, Any]:
    return {"id": nid, "label": label, "file_type": "code" if kind == "variable" else "concept",
            "source_file": near.get("source_file", ""), "source_location": near.get("source_location"),
            "metadata": {"ghidra_kind": kind, "origin": _ORIGIN, **{k: v for k, v in meta.items() if v is not None}}}


def _edge(src: str, dst: str, relation: str, near: dict[str, Any], *, confidence: str = "EXTRACTED",
          score: float = 1.0, context: str = "") -> dict[str, Any]:
    e = {"source": src, "target": dst, "_src": src, "_tgt": dst, "relation": relation, "confidence": confidence,
         "confidence_score": score, "source_file": near.get("source_file", ""),
         "source_location": near.get("source_location"), "weight": 1.0, "origin": _ORIGIN}
    if context:
        e["context"] = context[:300]
    return e
