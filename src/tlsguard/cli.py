"""Command-line interface for TLSGuard."""

from __future__ import annotations

import argparse
import math
import ssl
import sys

from tlsguard.checks.certificate import certificate_status
from tlsguard.checks.ciphers import CipherStatus, classify_cipher
from tlsguard.checks.protocols import ProtocolStatus
from tlsguard.json_report import export_json
from tlsguard.models.finding import Severity
from tlsguard.scanner import TLSScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tlsguard",
        description="Audit a server's TLS configuration.",
        epilog=(
            "Example: python -m tlsguard scan example.com "
            "--port 443 --timeout 5 --json reports/scan.json"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="Scan a TLS-enabled server")
    scan_parser.add_argument("host", help="Hostname or IP address (no URL scheme)")
    scan_parser.add_argument("--port", type=int, default=443, help="TCP port (default: 443)")
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Socket timeout per connection after DNS lookup (default: 5)",
    )
    scan_parser.add_argument(
        "--json",
        dest="json_path",
        metavar="FILE",
        help="Export the scan report to a JSON file",
    )
    return parser


def print_header(host: str, port: int, timeout: float) -> None:
    print()
    print("TLSGuard")
    print("=" * 64)
    print(f"Python : {sys.version.split()[0]}")
    print(f"OpenSSL: {ssl.OPENSSL_VERSION}")
    print(f"Target : {host}:{port}")
    print(f"Timeout: {timeout:g} seconds per socket connection (DNS lookup excluded)")
    print()


def print_protocol_results(results) -> None:
    print("Protocol Support")
    print("-" * 64)
    for result in results:
        label = result.status.value.replace("_", " ").upper()
        marker = "+" if result.status is ProtocolStatus.SUPPORTED else "-"
        print(f"[{marker}] {result.protocol:<10} {label}")
        if result.negotiated_version:
            print(f"    Negotiated: {result.negotiated_version}")
        if result.error:
            print(f"    Details   : {result.error}")
    print()


def print_certificate_result(certificate, error: str | None = None) -> None:
    print("Certificate")
    print("-" * 64)
    if certificate is None:
        print("[!] Certificate metadata could not be collected.")
        if error:
            print(f"    Reason: {error}")
        print()
        return

    print(f"Date validity       : {certificate_status(certificate)}")
    print(f"Subject             : {certificate.subject}")
    print(f"Issuer              : {certificate.issuer}")
    print(f"Serial number       : {certificate.serial_number}")
    print(f"Valid from          : {certificate.not_valid_before.isoformat()}")
    print(f"Valid until         : {certificate.not_valid_after.isoformat()}")
    print(f"Days remaining      : {certificate.days_remaining:.2f}")
    print(f"Signature hash      : {certificate.signature_hash_algorithm or 'Unknown'}")
    print("DNS names (SAN)     :")
    if certificate.san_dns_names:
        for name in certificate.san_dns_names:
            print(f"    - {name}")
    else:
        print("    None")
    print("Trust chain/hostname: NOT CHECKED")
    print()


def print_cipher_results(results) -> None:
    print("TLS 1.2 Cipher Suites (configured probe list)")
    print("-" * 64)
    for result in results:
        label = result.status.value.replace("_", " ").upper()
        print(f"[{label:<13}] {result.name}")
        if result.status is CipherStatus.SUPPORTED:
            print(f"    Classification: {classify_cipher(result.name)}")
            if result.bits is not None:
                print(f"    Key strength  : {result.bits} bits")
        if result.error:
            print(f"    Details       : {result.error}")
    print()


def print_findings(findings, assessment_complete: bool = True) -> None:
    print("Security Findings")
    print("-" * 64)
    if not findings:
        if assessment_complete:
            print("[+] No security findings detected by completed checks.")
        else:
            print("[!] No findings could be confirmed; the assessment is incomplete.")
        print()
        return

    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    for finding in sorted(
        findings,
        key=lambda item: severity_order.get(item.severity, 99),
    ):
        print(f"[{finding.severity.value}] {finding.id} - {finding.title}")
        print(f"    Description    : {finding.description}")
        print(f"    Evidence       : {finding.evidence}")
        print(f"    Recommendation : {finding.recommendation}")
        print()


def run_scan(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
    json_path: str | None = None,
) -> int:
    print_header(host, port, timeout)
    try:
        result = TLSScanner(host=host, port=port, timeout=timeout).run()
    except KeyboardInterrupt:
        print("\nScan interrupted by the user.", file=sys.stderr)
        return 130
    except (ConnectionError, OSError, ssl.SSLError, ValueError, RuntimeError) as exc:
        print(f"[-] Scan failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    score = result.security_score
    if score.assessment_complete and score.score is not None:
        print(f"Security score: {score.score}/100")
        print(f"Risk level    : {score.risk_level}")
    else:
        print("Security score: NOT AVAILABLE (assessment incomplete)")
        print("Risk level    : INCOMPLETE")
        print("Some checks could not be completed; do not interpret this as a clean result.")
    print()

    print_protocol_results(result.protocols)
    print_certificate_result(result.certificate, result.certificate_error)
    print_cipher_results(result.ciphers)
    print_findings(result.findings, assessment_complete=score.assessment_complete)

    if json_path:
        try:
            export_json(result, json_path)
            print(f"JSON report saved to: {json_path}")
        except (OSError, TypeError, ValueError) as exc:
            print(f"[-] Could not export JSON report: {exc}", file=sys.stderr)
            return 1

    return 0 if score.assessment_complete else 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        if not args.host or args.host != args.host.strip():
            parser.error("host must be a non-empty hostname or IP address")
        if "://" in args.host or any(char in args.host for char in "/?#"):
            parser.error("provide a hostname or IP address, not a URL")
        if not 1 <= args.port <= 65535:
            parser.error("--port must be between 1 and 65535")
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            parser.error("--timeout must be a finite number greater than 0")
        return run_scan(
            host=args.host,
            port=args.port,
            timeout=args.timeout,
            json_path=args.json_path,
        )

    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
