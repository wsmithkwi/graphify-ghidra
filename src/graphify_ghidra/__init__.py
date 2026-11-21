"""graphify-ghidra: Ghidra (and REA) support for graphify.

Public API::

    from graphify_ghidra import ingest_export, write_extraction, ProgramOptions
    extraction = ingest_export(json.load(open("program.ghidra.json")))
    write_extraction(extraction, "graphify-out")
"""

from __future__ import annotations

from .ingest import ingest_export
from .model import SCHEMA, canon_addr, empty_export, validate_export
from .program import Program, ProgramOptions

__all__ = [
    "SCHEMA", "Program", "ProgramOptions", "canon_addr", "empty_export",
    "ingest_export", "validate_export", "write_extraction",
]
__version__ = "0.1.0"


def write_extraction(*args, **kwargs):
    """Lazy wrapper: importing graph_io pulls in graphify's graph stack."""
    from .graph_io import write_extraction as _w
    return _w(*args, **kwargs)
