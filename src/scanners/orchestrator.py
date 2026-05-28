import logging
import os
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from src.api.models import Finding, ScanProfile
from src.scanners.escaneo import build_fingerprint

logger = logging.getLogger(__name__)


def get_scanner_adapter(technology: str, sast_tools: str = ""):
    from src.scanners.bandit_adapter import BanditAdapter
    from src.scanners.semgrep_adapter import SemgrepAdapter
    from src.scanners.escaneo import get_default_scanner_adapter, CombinedScannerAdapter

    norm_tech = technology.strip().lower()
    engine = sast_tools.strip().lower()

    if engine == "semgrep":
        if norm_tech in {"python", "django", "flask", "angular", "typescript", "java", "java-spring"}:
            return SemgrepAdapter(norm_tech)
        return get_default_scanner_adapter(norm_tech)

    if engine == "bandit":
        return BanditAdapter()

    if engine == "both":
        if norm_tech == "python":
            return CombinedScannerAdapter([BanditAdapter(), SemgrepAdapter("python")])
        if norm_tech in {"angular", "typescript", "java", "java-spring"}:
            return SemgrepAdapter(norm_tech)
        return get_default_scanner_adapter(norm_tech)

    return get_default_scanner_adapter(norm_tech)


@dataclass
class OrchestratorResult:
    findings: list
    errors: list
    tools_run: list = field(default_factory=list)
    scan_summary: dict = field(default_factory=dict)   # {tool_name: finding_count}
    warnings: list = field(default_factory=list)       # non-fatal notices (0 findings, tech mismatch)


class ScanOrchestrator:
    """
    Executes the runners enabled by a ScanProfile in parallel
    (ThreadPoolExecutor), then normalises and deduplicates findings
    by SHA-256 fingerprint.
    """

    def run(
        self,
        profile: ScanProfile,
        target_path: str,
        technology: str,
        project_id: uuid.UUID | None = None,
        target_url: str | None = None,
    ) -> OrchestratorResult:
        futures_map: dict = {}
        errors: list[str] = []
        warnings: list[str] = []
        tools_run: list[str] = []

        with ThreadPoolExecutor(max_workers=3) as executor:
            if profile.sast_enabled:
                futures_map[executor.submit(
                    self._run_sast, profile, target_path, technology
                )] = "sast"

            if profile.dast_enabled:
                futures_map[executor.submit(
                    self._run_dast, profile, target_url
                )] = "dast"

            if profile.quality_enabled and profile.quality_tool:
                futures_map[executor.submit(
                    self._run_quality, profile, target_path, technology
                )] = "quality"

            all_findings: list[Finding] = []
            for future in as_completed(futures_map):
                runner_name = futures_map[future]
                try:
                    runner_result = future.result()
                    # _run_quality returns (findings, notices); others return findings list
                    if isinstance(runner_result, tuple):
                        runner_findings, runner_notices = runner_result
                        warnings.extend(runner_notices)
                    else:
                        runner_findings = runner_result
                    all_findings.extend(runner_findings)
                    tools_run.append(runner_name)
                except Exception as exc:
                    logger.error("Runner %s failed: %s", runner_name, exc)
                    errors.append(f"{runner_name}: {exc}")

        deduplicated = self._deduplicate(all_findings)
        scan_summary: dict[str, int] = {}
        for f in all_findings:
            tool = getattr(f, "tool", None) or "unknown"
            scan_summary[tool] = scan_summary.get(tool, 0) + 1

        return OrchestratorResult(
            findings=deduplicated,
            errors=errors,
            tools_run=tools_run,
            scan_summary=scan_summary,
            warnings=warnings,
        )

    def _run_sast(
        self,
        profile: ScanProfile,
        target_path: str,
        technology: str,
    ) -> list[Finding]:
        from src.scanners.bandit_adapter import BanditAdapter
        from src.scanners.semgrep_adapter import SemgrepAdapter
        from src.scanners.escaneo import get_default_scanner_adapter, CombinedScannerAdapter

        sast_tools = (profile.sast_tools or "").strip().lower()
        norm_tech = technology.strip().lower()

        if sast_tools == "semgrep":
            adapter = (SemgrepAdapter(norm_tech)
                       if norm_tech in {"python", "django", "flask", "angular", "typescript", "java", "java-spring"}
                       else get_default_scanner_adapter(norm_tech))
        elif sast_tools == "bandit":
            adapter = BanditAdapter()
        elif sast_tools == "both":
            if norm_tech == "python":
                adapter = CombinedScannerAdapter([BanditAdapter(), SemgrepAdapter("python")])
            elif norm_tech in {"angular", "typescript", "java", "java-spring"}:
                adapter = SemgrepAdapter(norm_tech)
            else:
                adapter = get_default_scanner_adapter(norm_tech)
        else:
            adapter = get_default_scanner_adapter(norm_tech)

        if adapter is None:
            logger.warning("No SAST adapter for technology=%s sast_tools=%s", technology, profile.sast_tools)
            return []
        return adapter.execute_scan(target_path)

    def _run_dast(self, profile: ScanProfile, target_url: str | None) -> list[Finding]:
        from src.scanners.zap_adapter import ZapAdapter

        dast_tool = (profile.dast_tool or "zap").strip().lower()
        if dast_tool != "zap":
            logger.warning("No DAST adapter for tool=%s", profile.dast_tool)
            return []

        resolved_target_url = (target_url or os.getenv("DAST_DEFAULT_URL", "")).strip()
        if not resolved_target_url:
            logger.warning("DAST enabled but no target_url provided - skipping ZAP")
            return []

        adapter = ZapAdapter()
        findings = adapter.execute_scan(resolved_target_url)
        if adapter.error:
            raise RuntimeError(f"ZAP: {adapter.error}")
        return findings

    def _run_quality(
        self,
        profile: ScanProfile,
        target_path: str,
        technology: str,
    ) -> tuple[list[Finding], list[str]]:
        from src.scanners.eslint_adapter import EslintAdapter
        from src.scanners.pylint_adapter import PylintAdapter
        from src.scanners.sonarqube_adapter import SonarQubeAdapter

        norm_tech = technology.strip().lower()
        quality_tools = [
            t.strip().lower()
            for t in (profile.quality_tool or "").split(",")
            if t.strip()
        ]

        all_findings: list[Finding] = []
        tool_errors: list[str] = []
        notices: list[str] = []

        for quality_tool in quality_tools:
            adapter = self._build_quality_adapter(
                quality_tool, norm_tech, technology, notices
            )
            if adapter is None:
                continue

            findings = adapter.execute_scan(target_path)
            self._collect_quality_results(
                adapter, findings, quality_tool, all_findings, tool_errors, notices
            )

        if not all_findings and tool_errors:
            raise RuntimeError("; ".join(tool_errors))

        return all_findings, notices

    def _build_quality_adapter(
        self,
        quality_tool: str,
        norm_tech: str,
        technology: str,
        notices: list[str],
    ):
        from src.scanners.eslint_adapter import EslintAdapter
        from src.scanners.pylint_adapter import PylintAdapter
        from src.scanners.sonarqube_adapter import SonarQubeAdapter

        PYLINT_TECHS  = {"python", "django", "flask"}
        ESLINT_TECHS  = {"angular", "typescript", "react"}
        SONAR_TECHS   = {"python", "django", "flask", "angular", "typescript",
                         "java", "java-spring", "react"}

        if quality_tool == "pylint" and norm_tech in PYLINT_TECHS:
            return PylintAdapter()
        if quality_tool == "eslint" and norm_tech in ESLINT_TECHS:
            return EslintAdapter()
        if quality_tool == "sonarqube" and norm_tech in SONAR_TECHS:
            return SonarQubeAdapter()

        notices.append(f"{quality_tool}: tecnología '{technology}' no compatible — saltado")
        logger.warning(
            "No Quality adapter for technology=%s quality_tool=%s — skipping",
            technology, quality_tool,
        )
        return None

    def _collect_quality_results(
        self,
        adapter,
        findings: list[Finding],
        quality_tool: str,
        all_findings: list[Finding],
        tool_errors: list[str],
        notices: list[str],
    ) -> None:
        error = getattr(adapter, "error", None)
        if error:
            logger.warning("Quality runner %s reported: %s", adapter.tool_name, error)
            if not findings:
                tool_errors.append(error)
        if findings:
            all_findings.extend(findings)
        elif not error:
            notices.append(f"{quality_tool}: conectado, 0 hallazgos encontrados")

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen: dict[str, Finding] = {}
        for finding in findings:
            fp = finding.fingerprint or build_fingerprint(finding)
            if fp not in seen:
                if not finding.fingerprint:
                    finding.fingerprint = fp
                seen[fp] = finding
        return list(seen.values())
