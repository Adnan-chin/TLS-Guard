"""JSON serialization for TLSGuard scan results."""

import json
from dataclasses import asdict
from datetime import date, datetime
from enum import Enum
from pathlib import Path

from tlsguard.models.report import ScanResult


def json_default(value):
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError(f"Unsupported JSON type: {type(value).__name__}")


def build_report(result: ScanResult) -> dict:
    return {
        "tool": {"name": "TLSGuard", "version": "0.1.0"},
        "target": {"host": result.host, "port": result.port},
        "security_score": asdict(result.security_score),
        "protocols": [asdict(protocol) for protocol in result.protocols],
        "certificate": asdict(result.certificate) if result.certificate else None,
        "certificate_error": result.certificate_error,
        "ciphers": [asdict(cipher) for cipher in result.ciphers],
        "findings": [asdict(finding) for finding in result.findings],
        "limitations": [
            "The certificate trust chain and hostname are not validated.",
            "Cipher-suite checks cover the explicit TLS 1.2 probe list only.",
            "A score is withheld when one or more required checks are incomplete.",
        ],
    }


def export_json(result: ScanResult, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            build_report(result),
            indent=2,
            ensure_ascii=False,
            default=json_default,
        ) + "\n",
        encoding="utf-8",
    )
