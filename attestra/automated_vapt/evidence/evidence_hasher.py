"""SHA-256 evidence hashing and Elite execution manifests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

# @lat: [[architecture#Elite automated security testing#Evidence integrity]]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class ManifestEntry:
    evidence_id: str
    file_name: str
    hash: str
    creation_timestamp: str
    capture_method: str
    test_execution_id: int
    engagement_id: int


@dataclass
class EvidenceManifest:
    engagement_id: int
    test_execution_id: int
    entries: list[ManifestEntry] = field(default_factory=list)

    def add(
        self,
        *,
        evidence_id: str,
        file_name: str,
        data: bytes,
        capture_method: str,
    ) -> ManifestEntry:
        entry = ManifestEntry(
            evidence_id=evidence_id,
            file_name=file_name,
            hash=sha256_hex(data),
            creation_timestamp=datetime.now(UTC).isoformat(),
            capture_method=capture_method,
            test_execution_id=self.test_execution_id,
            engagement_id=self.engagement_id,
        )
        self.entries.append(entry)
        return entry

    def verify(self, evidence_id: str, data: bytes) -> bool:
        for e in self.entries:
            if e.evidence_id == evidence_id:
                return e.hash == sha256_hex(data)
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "test_execution_id": self.test_execution_id,
            "entries": [asdict(e) for e in self.entries],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)
