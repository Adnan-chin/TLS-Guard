import pytest

from tlsguard.cli import main


def test_cli_forwards_timeout_and_json_path(monkeypatch):
    received = {}

    def fake_run_scan(**kwargs):
        received.update(kwargs)
        return 0

    monkeypatch.setattr("tlsguard.cli.run_scan", fake_run_scan)
    code = main([
        "scan",
        "example.test",
        "--port",
        "8443",
        "--timeout",
        "2.5",
        "--json",
        "reports/scan.json",
    ])
    assert code == 0
    assert received == {
        "host": "example.test",
        "port": 8443,
        "timeout": 2.5,
        "json_path": "reports/scan.json",
    }


def test_cli_rejects_url_instead_of_hostname():
    with pytest.raises(SystemExit) as exc:
        main(["scan", "https://example.test"])
    assert exc.value.code == 2


def test_cli_rejects_non_positive_timeout():
    with pytest.raises(SystemExit) as exc:
        main(["scan", "example.test", "--timeout", "0"])
    assert exc.value.code == 2


def test_incomplete_scan_returns_nonzero_and_explains_missing_findings(monkeypatch, capsys):
    from types import SimpleNamespace

    from tlsguard.cli import run_scan
    from tlsguard.scoring import SecurityScore

    class FakeScanner:
        def __init__(self, host, port, timeout):
            pass

        def run(self):
            return SimpleNamespace(
                security_score=SecurityScore(None, "INCOMPLETE", 0, False),
                protocols=[],
                certificate=None,
                certificate_error="connection refused",
                ciphers=[],
                findings=[],
            )

    monkeypatch.setattr("tlsguard.cli.TLSScanner", FakeScanner)
    assert run_scan("127.0.0.1", port=1, timeout=0.1) == 1
    output = capsys.readouterr().out
    assert "assessment is incomplete" in output
    assert "No findings could be confirmed" in output
