"""Prometheus custom metrics for AI DevSecOps Control Plane.

All counters/gauges/histograms are module-level singletons. Import and call
the helper functions from escaneo.py and main.py — the metrics module never
imports from them to avoid circular dependencies.
"""
try:
    from prometheus_client import Counter, Gauge, Histogram
    _PROMETHEUS_AVAILABLE = True
except ImportError:
    _PROMETHEUS_AVAILABLE = False

if _PROMETHEUS_AVAILABLE:
    findings_total = Counter(
        "findings_total",
        "Total findings persistidos",
        ["severity", "tool"],
    )

    remediations_generated_total = Counter(
        "remediations_generated_total",
        "Total remediaciones generadas",
        ["source"],  # ollama | db_cache | fallback
    )

    regressions_detected_total = Counter(
        "regressions_detected_total",
        "Total regresiones detectadas",
    )

    sla_breached_gauge = Gauge(
        "sla_breached_findings",
        "Findings con SLA vencido activos",
    )

    scan_duration_seconds = Histogram(
        "scan_duration_seconds",
        "Duración de escaneos",
        ["tool"],
    )

    remediation_latency_seconds = Histogram(
        "remediation_latency_seconds",
        "Latencia de generación de remediación",
        ["source"],
    )
else:
    # Stub objects when prometheus_client is not installed.
    # The main flow must never break if Prometheus is absent.
    class _Noop:
        def labels(self, **_kw):
            return self

        def inc(self, _amount=1):
            pass

        def set(self, _value):
            pass

        def observe(self, _value):
            pass

        def __call__(self, *_a, **_kw):
            return self

    findings_total = _Noop()
    remediations_generated_total = _Noop()
    regressions_detected_total = _Noop()
    sla_breached_gauge = _Noop()
    scan_duration_seconds = _Noop()
    remediation_latency_seconds = _Noop()


def record_finding(severity: str, tool: str) -> None:
    findings_total.labels(severity=severity.lower(), tool=tool).inc()


def record_regression() -> None:
    regressions_detected_total.inc()


def record_remediation(source: str, latency_seconds: float | None = None) -> None:
    """source: 'ollama' | 'db_cache' | 'fallback'"""
    remediations_generated_total.labels(source=source).inc()
    if latency_seconds is not None:
        remediation_latency_seconds.labels(source=source).observe(latency_seconds)


def record_scan_duration(tool: str, duration_seconds: float) -> None:
    scan_duration_seconds.labels(tool=tool).observe(duration_seconds)


def update_sla_breached_gauge(count: int) -> None:
    sla_breached_gauge.set(count)
