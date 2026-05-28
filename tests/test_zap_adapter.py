import httpx

from src.scanners.zap_adapter import ZapAdapter


def test_normalize_alert_high():
    adapter = ZapAdapter(poll_interval=0)

    finding = adapter._normalize_alert(
        {
            "pluginId": "10016",
            "name": "Web Browser XSS Protection Not Enabled",
            "risk": "High",
            "url": "http://localhost:8000",
            "evidence": "x" * 600,
            "description": "Header missing",
            "cweid": "693",
        }
    )

    assert finding["rule_id"] == "10016"
    assert finding["severity"] == "HIGH"
    assert finding["snippet"] == "x" * 500
    assert finding["tool"] == "zap"


def test_normalize_alert_info():
    adapter = ZapAdapter(poll_interval=0)

    finding = adapter._normalize_alert({"risk": "Informational"})

    assert finding["severity"] == "INFO"


def test_zap_unavailable_returns_empty():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = httpx.Client(
        base_url="http://localhost:8090",
        transport=httpx.MockTransport(handler),
    )
    adapter = ZapAdapter(client=client, poll_interval=0)

    assert adapter.scan("http://localhost:8000") == []
    assert adapter.returncode == 0

    client.close()


def test_invalid_target_url_returns_empty():
    adapter = ZapAdapter(poll_interval=0)

    assert adapter.scan("ftp://localhost:8000") == []
    assert adapter.returncode == 0
