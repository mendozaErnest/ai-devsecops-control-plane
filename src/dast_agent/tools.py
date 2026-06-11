"""Thin wrappers over the OWASP ZAP REST API for use inside the agentic loop.

Every public function follows two strict rules:
1. Returns a dict — never raises. Callers downstream interpret an empty/error result.
2. Reads `ZAP_BASE_URL` / `ZAP_API_KEY` from the process env on each call so the
   adapter responds to runtime config changes.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Optional

import httpx


LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0
POLL_INTERVAL = 5
SCAN_TIMEOUT = 180


def _zap_base_url() -> str:
    return os.getenv("ZAP_BASE_URL", "http://localhost:8090").rstrip("/")


def _zap_api_key() -> str:
    return os.getenv("ZAP_API_KEY", "")


def _client(timeout: float = DEFAULT_TIMEOUT) -> httpx.Client:
    return httpx.Client(base_url=_zap_base_url(), timeout=timeout)


def _request_json(
    client: httpx.Client, path: str, params: Optional[dict] = None
) -> Optional[dict]:
    try:
        response = client.get(path, params=params or {})
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict):
            return payload
    except (httpx.HTTPError, ValueError) as exc:
        LOGGER.warning("ZAP request to %s failed: %s", path, exc)
    return None


def _poll_until_done(
    client: httpx.Client, view_path: str, scan_id: str, timeout: int = SCAN_TIMEOUT
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        payload = _request_json(
            client, view_path, {"apikey": _zap_api_key(), "scanId": scan_id}
        )
        if payload is None:
            return False
        try:
            if int(payload.get("status", 0)) >= 100:
                return True
        except (TypeError, ValueError):
            return False
        time.sleep(POLL_INTERVAL)
    return False


def _extract_zap_error(payload: Optional[dict], fallback: str) -> str:
    """Extract a human-readable error from a ZAP JSON error payload."""
    if not payload:
        return fallback
    code = payload.get("code") or payload.get("error")
    message = payload.get("message") or payload.get("description")
    if code and message:
        return f"{fallback}: {code} — {message}"
    if code:
        return f"{fallback}: {code}"
    if message:
        return f"{fallback}: {message}"
    return fallback


def target_reachable(target_url: str) -> dict:
    """Check whether ZAP can reach *target_url* before starting a scan.

    Returns: {"reachable": bool, "error": str | None}
    Uses ZAP's accessUrl action which fetches the URL through the proxy and
    reports connectivity without requiring an active scan to be running.
    """
    result: dict = {"reachable": False, "error": None}
    try:
        with _client() as client:
            payload = _request_json(
                client,
                "/JSON/core/action/accessUrl/",
                {"apikey": _zap_api_key(), "url": target_url},
            )
            if payload is not None and "Result" in payload:
                result["reachable"] = True
                return result
            # ZAP returned a response but accessUrl failed
            err_msg = _extract_zap_error(
                payload,
                f"ZAP cannot reach {target_url}",
            )
            result["error"] = (
                err_msg
                + " — if the target runs on the host, use http://host.docker.internal:<port>"
            )
    except httpx.ConnectError:
        result["error"] = (
            f"ZAP cannot reach {target_url} (connection refused)"
            " — if the target runs on the host, use http://host.docker.internal:<port>"
        )
    except httpx.HTTPError as exc:
        result["error"] = f"target_reachable: {exc}"
    return result


def spider_crawl(target_url: str, max_children: int = 50) -> dict:
    """Run a ZAP spider and return discovered routes + forms.

    Returns: {"routes": [...], "forms": [...], "error": str | None}
    Forms are inferred from URLs containing query strings — full form
    introspection requires ZAP's URL search which is exposed separately.
    """
    result: dict = {"routes": [], "forms": [], "error": None}

    try:
        with _client() as client:
            start = _request_json(
                client,
                "/JSON/spider/action/scan/",
                {
                    "apikey": _zap_api_key(),
                    "url": target_url,
                    "recurse": "true",
                    "maxChildren": str(max_children),
                },
            )
            if not start or "scan" not in start:
                result["error"] = _extract_zap_error(start, "ZAP spider failed to start")
                return result

            scan_id = str(start["scan"])
            if not _poll_until_done(client, "/JSON/spider/view/status/", scan_id):
                result["error"] = "ZAP spider timed out"
                return result

            results_payload = _request_json(
                client,
                "/JSON/spider/view/results/",
                {"apikey": _zap_api_key(), "scanId": scan_id},
            )
            if results_payload:
                routes = results_payload.get("results", [])
                if isinstance(routes, list):
                    result["routes"] = [str(r) for r in routes]
                    result["forms"] = [
                        {"url": r, "method": "GET", "params": _extract_params(r)}
                        for r in result["routes"]
                        if "?" in str(r)
                    ]
    except httpx.HTTPError as exc:
        LOGGER.warning("spider_crawl error: %s", exc)
        result["error"] = f"spider_crawl: {exc}"

    return result


def active_scan(target_url: str, scope_urls: Optional[list[str]] = None) -> dict:
    """Trigger a ZAP active scan and wait for completion.

    Returns: {"scan_id": str | None, "completed": bool, "error": str | None}
    The actual alerts are fetched separately via get_alerts().
    """
    result: dict = {"scan_id": None, "completed": False, "error": None}

    try:
        with _client() as client:
            start = _request_json(
                client,
                "/JSON/ascan/action/scan/",
                {
                    "apikey": _zap_api_key(),
                    "url": target_url,
                    "recurse": "true",
                },
            )
            if not start or "scan" not in start:
                result["error"] = _extract_zap_error(start, "ZAP active scan failed to start")
                return result

            scan_id = str(start["scan"])
            result["scan_id"] = scan_id
            result["completed"] = _poll_until_done(
                client, "/JSON/ascan/view/status/", scan_id
            )
    except httpx.HTTPError as exc:
        LOGGER.warning("active_scan error: %s", exc)
        result["error"] = f"active_scan: {exc}"

    return result


def get_alerts(base_url: str, max_alerts: int = 200) -> dict:
    """Read ZAP alerts filtered by base URL."""
    result: dict = {"alerts": [], "error": None}

    try:
        with _client() as client:
            payload = _request_json(
                client,
                "/JSON/alert/view/alerts/",
                {
                    "apikey": _zap_api_key(),
                    "baseurl": base_url,
                    "start": "0",
                    "count": str(max_alerts),
                },
            )
            if payload:
                alerts = payload.get("alerts", [])
                if isinstance(alerts, list):
                    result["alerts"] = alerts
    except httpx.HTTPError as exc:
        LOGGER.warning("get_alerts error: %s", exc)
        result["error"] = f"get_alerts: {exc}"

    return result


def verify_alert(alert: dict, target_url: str) -> dict:
    """Best-effort confirmation of a ZAP alert.

    Logic:
    - XSS: re-fetch the alert URL and check whether the payload appears in the body.
    - Missing security header: re-request the URL and check absence in response headers.
    - Anything else: trust ZAP's original evidence (confirmed=True).
    """
    alert_url = str(alert.get("url") or target_url)
    name = str(alert.get("name") or alert.get("alert") or "").lower()
    evidence = str(alert.get("evidence") or "")
    result: dict = {"confirmed": False, "evidence": "", "reasoning": ""}

    if not alert_url:
        result["reasoning"] = "missing alert URL"
        return result

    is_xss = "xss" in name or "cross site scripting" in name or "cross-site scripting" in name
    is_missing_header = (
        "header" in name and ("missing" in name or "not" in name or "absence" in name)
    )

    try:
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            response = client.get(alert_url)
            body = response.text

            if is_xss and evidence:
                if evidence in body:
                    result["confirmed"] = True
                    result["evidence"] = f"payload `{evidence[:80]}` reflected in response body"
                    result["reasoning"] = "payload present in response"
                else:
                    result["confirmed"] = False
                    result["reasoning"] = "payload not present in response (possible false positive)"
                return result

            if is_missing_header:
                header_name = _extract_header_name(name)
                if header_name and header_name.lower() not in {k.lower() for k in response.headers}:
                    result["confirmed"] = True
                    result["evidence"] = f"`{header_name}` header absent in live response"
                    result["reasoning"] = "header still missing on direct request"
                else:
                    result["confirmed"] = False
                    result["reasoning"] = "header present on direct request"
                return result

            result["confirmed"] = True
            result["evidence"] = evidence or "trusting ZAP evidence"
            result["reasoning"] = "no automatic verifier — accepting ZAP triage"
    except httpx.HTTPError as exc:
        LOGGER.warning("verify_alert error: %s", exc)
        result["confirmed"] = True
        result["evidence"] = evidence or "trusting ZAP evidence (verification failed)"
        result["reasoning"] = f"verification request error: {exc}"

    return result


def _extract_params(url: str) -> list[str]:
    if "?" not in url:
        return []
    query = url.split("?", 1)[1]
    return [pair.split("=", 1)[0] for pair in query.split("&") if pair]


_HEADER_KEYWORDS = {
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "x-xss-protection": "X-XSS-Protection",
}


def _extract_header_name(alert_name: str) -> Optional[str]:
    name_lower = alert_name.lower()
    for keyword, header in _HEADER_KEYWORDS.items():
        if keyword in name_lower or keyword.replace("-", " ") in name_lower:
            return header
    return None
