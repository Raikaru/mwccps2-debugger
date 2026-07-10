"""Host transport boundaries for MWCCPS2 debugger capture tooling.

These modules construct commands, launch processes, report host capabilities, and
compare capture artifacts.  They deliberately do not import or decode b210 memory
layouts; the GDB snapshot model remains the sole owner of that knowledge.
"""

from .capabilities import (
    CAPABILITY_SCHEMA_NAME,
    CAPABILITY_SCHEMA_VERSION,
    probe_capabilities,
    write_capabilities,
)
from .capture_compare import (
    CAPTURE_COMPARISON_SCHEMA_NAME,
    CAPTURE_COMPARISON_SCHEMA_VERSION,
    compare_capture_directories,
    normalize_capture_directory,
    write_comparison,
)
from .gdb import (
    GdbSnapshotRequest,
    Retrowin32GdbTransport,
    WindowsGdbTransport,
    create_gdb_transport,
)
from .process import TransportError

__all__ = [
    "CAPABILITY_SCHEMA_NAME",
    "CAPABILITY_SCHEMA_VERSION",
    "CAPTURE_COMPARISON_SCHEMA_NAME",
    "CAPTURE_COMPARISON_SCHEMA_VERSION",
    "GdbSnapshotRequest",
    "Retrowin32GdbTransport",
    "TransportError",
    "WindowsGdbTransport",
    "compare_capture_directories",
    "create_gdb_transport",
    "normalize_capture_directory",
    "probe_capabilities",
    "write_capabilities",
    "write_comparison",
]
