"""Import external control libraries (OSCAL catalogs, SCF CSV) as framework packs.

An imported library becomes a pack in the same shape as compliance/data/packs/*.yaml:
the catalog's controls are listed under ``titles`` and only the controls that can be
tied to a hub objective are listed under ``controls``. Because a pack only adds refs
to existing objectives, every CWE mapping reaches the imported framework with no code
changes. Imported text should be reviewed before use in an audit.
"""

from __future__ import annotations

from attestra.compliance.libraries.common import ImportedLibrary, install_pack, validate_pack, write_pack
from attestra.compliance.libraries.oscal import import_oscal_catalog
from attestra.compliance.libraries.scf import import_scf_csv

__all__ = [
    "ImportedLibrary",
    "import_oscal_catalog",
    "import_scf_csv",
    "install_pack",
    "validate_pack",
    "write_pack",
]
