import hashlib
import logging
import os
import time
import uuid
from urllib.parse import urlparse

import httpx

from src.api.models import Finding
from src.scanners.base import BaseScannerAdapter


LOGGER = logging.getLogger(__name__)

ZAP_BASE_URL = os.getenv("ZAP_BASE_URL", "http://localhost:8090")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")
POLL_INTERVAL = 5
SCAN_TIMEOUT = 300


class ZapAdapter(BaseScannerAdapter):
    tool_name = "zap"

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        client: httpx.Client | None = None,
        poll_interval: int = POLL_INTERVAL,
        scan_timeout: int = SCAN_TIMEOUT,
    ) -> None:
        self.base_url = (base_url or os.getenv("ZAP_BASE_URL", ZAP_BASE_URL)).rstrip("/")
        self.api_key = api_key if api_key is not None else os.getenv("ZAP_API_KEY", ZAP_API_KEY)
        self.client = client
        self.poll_interval = poll_interval
        self.scan_timeout = scan_timeout
        self.raw_output: dict = {"alerts": [], "errors": []}
        self.returncode: int | None = 0
        self.error: str | None = None

    def execute_scan(self, target_path: str) -> list[Finding]:
        return [self._to_finding(alert) for alert in self.scan(target_path)]

    def scan(self, target_url: str) -> list[dict]:
        if not self._is_valid_target_url(target_url):
            message = f"Invalid DAST target_url: {target_url}"
            LOGGER.warning(message)
            self.error = message
            self.raw_output = {"alerts": [], "errors": [message]}
            self.returncode = 0
            return []

        created_client = self.client is None
        client = self.client or httpx.Client(base_url=self.base_url, timeout=30.0)

        try:
            spider_id = self._start_spider(client, target_url)
            if not self._poll_status(client, "spider", spider_id):
                return []

            ascan_id = self._start_active_scan(client, target_url)
            if not self._poll_status(client, "ascan", ascan_id):
                return []

            alerts_payload = self._request_json(
                client,
                "/JSON/alert/view/alerts/",
                {
                    "apikey": self.api_key,
                    "baseurl": target_url,
                    "start": "0",
                    "count": "200",
                },
            )
            alerts = alerts_payload.get("alerts", [])
            if not isinstance(alerts, list):
                alerts = []

            self.raw_output = {
                "alerts": alerts,
                "errors": [],
                "metrics": {"total_findings": len(alerts)},
            }
            self.returncode = 1 if alerts else 0
            self.error = None
            return [self._normalize_alert(alert) for alert in alerts]
        except httpx.ConnectError as exc:
            message = f"OWASP ZAP is not available at {self.base_url}: {exc}"
            LOGGER.warning(message)
            self.raw_output = {"alerts": [], "errors": [message]}
            self.returncode = 0
            self.error = message
            return []
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            message = f"OWASP ZAP scan failed for {target_url}: {exc}"
            LOGGER.warning(message)
            self.raw_output = {"alerts": [], "errors": [message]}
            self.returncode = 0
            self.error = message
            return []
        except Exception as exc:
            message = f"Unexpected OWASP ZAP adapter failure for {target_url}: {exc}"
            LOGGER.warning(message)
            self.raw_output = {"alerts": [], "errors": [message]}
            self.returncode = 0
            self.error = message
            return []
        finally:
            if created_client:
                client.close()

    def _start_spider(self, client: httpx.Client, target_url: str) -> str:
        payload = self._request_json(
            client,
            "/JSON/spider/action/scan/",
            {"apikey": self.api_key, "url": target_url, "recurse": "true"},
        )
        return str(payload["scan"])

    def _start_active_scan(self, client: httpx.Client, target_url: str) -> str:
        payload = self._request_json(
            client,
            "/JSON/ascan/action/scan/",
            {"apikey": self.api_key, "url": target_url, "recurse": "true"},
        )
        return str(payload["scan"])

    def _poll_status(self, client: httpx.Client, scanner: str, scan_id: str) -> bool:
        deadline = time.monotonic() + self.scan_timeout
        path = f"/JSON/{scanner}/view/status/"

        while time.monotonic() < deadline:
            payload = self._request_json(
                client,
                path,
                {"apikey": self.api_key, "scanId": scan_id},
            )
            status = int(payload.get("status", 0))
            if status >= 100:
                return True
            time.sleep(self.poll_interval)

        message = f"OWASP ZAP {scanner} scan timed out after {self.scan_timeout} seconds."
        LOGGER.warning(message)
        self.error = message
        self.raw_output = {"alerts": [], "errors": [message]}
        self.returncode = 0
        return False

    def _request_json(self, client: httpx.Client, path: str, params: dict[str, str]) -> dict:
        response = client.get(path, params=params)
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("ZAP returned a non-object JSON response")
        return payload

    def _normalize_alert(self, alert: dict) -> dict:
        risk_map = {
            "High": "HIGH",
            "Medium": "MEDIUM",
            "Low": "LOW",
            "Informational": "INFO",
        }
        return {
            "rule_id": alert.get("pluginId", "ZAP-UNKNOWN"),
            "title": alert.get("name", ""),
            "severity": risk_map.get(alert.get("risk", ""), "LOW"),
            "file_path": alert.get("url", ""),
            "line_start": 0,
            "line_end": 0,
            "snippet": (alert.get("evidence", "") or "")[:500],
            "description": alert.get("description", ""),
            "cwe": alert.get("cweid", ""),
            "tool": "zap",
        }

    def _to_finding(self, alert: dict) -> Finding:
        fingerprint_source = "|".join(
            [
                str(alert.get("rule_id", "")),
                str(alert.get("file_path", "")),
                str(alert.get("title", "")),
                str(alert.get("description", "")),
                str(alert.get("snippet", "")),
            ]
        )
        return Finding(
            scan_id=uuid.UUID(int=0),
            tool="zap",
            rule_id=str(alert.get("rule_id", "")),
            title=str(alert.get("title", "")),
            description=str(alert.get("description", "")),
            severity=str(alert.get("severity", "LOW")),
            confidence="UNKNOWN",
            file_path=str(alert.get("file_path", "")),
            line_start=int(alert.get("line_start") or 0),
            line_end=int(alert.get("line_end") or 0),
            code_snippet=str(alert.get("snippet") or ""),
            status="open",
            fingerprint=hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest(),
        )

    def _is_valid_target_url(self, target_url: str) -> bool:
        parsed = urlparse((target_url or "").strip())
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
