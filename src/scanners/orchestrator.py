import logging
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
        if norm_tech in {"python", "angular", "typescript", "java"}:
            return SemgrepAdapter(norm_tech)
        return get_default_scanner_adapter(norm_tech)

    if engine == "bandit":
        return BanditAdapter()

    if engine == "both":
        if norm_tech == "python":
            return CombinedScannerAdapter([BanditAdapter(), SemgrepAdapter("python")])
        if norm_tech in {"angular", "typescript", "java"}:
            return SemgrepAdapter(norm_tech)
        return get_default_scanner_adapter(norm_tech)

    return get_default_scanner_adapter(norm_tech)


@dataclass
class OrchestratorResult:
    findings: list
    errors: list
    tools_run: list = field(default_factory=list)


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
    ) -> OrchestratorResult:
        futures_map: dict = {}
        errors: list[str] = []
        tools_run: list[str] = []

        with ThreadPoolExecutor(max_workers=3) as executor:
            if profile.sast_enabled:
                futures_map[executor.submit(
                    self._run_sast, profile, target_path, technology
                )] = "sast"

            if profile.dast_enabled and profile.dast_tool:
                futures_map[executor.submit(
                    self._run_dast, profile, target_path
                )] = "dast"

            if profile.quality_enabled and profile.quality_tool:
                futures_map[executor.submit(
                    self._run_quality, profile, target_path, technology
                )] = "quality"

            all_findings: list[Finding] = []
            for future in as_completed(futures_map):
                runner_name = futures_map[future]
                try:
                    runner_findings = future.result()
                    all_findings.extend(runner_findings)
                    tools_run.append(runner_name)
                except Exception as exc:
                    logger.error("Runner %s failed: %s", runner_name, exc)
                    errors.append(f"{runner_name}: {exc}")

        deduplicated = self._deduplicate(all_findings)
        return OrchestratorResult(
            findings=deduplicated,
            errors=errors,
            tools_run=tools_run,
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
                       if norm_tech in {"python", "angular", "typescript", "java"}
                       else get_default_scanner_adapter(norm_tech))
        elif sast_tools == "bandit":
            adapter = BanditAdapter()
        elif sast_tools == "both":
            if norm_tech == "python":
                adapter = CombinedScannerAdapter([BanditAdapter(), SemgrepAdapter("python")])
            elif norm_tech in {"angular", "typescript", "java"}:
                adapter = SemgrepAdapter(norm_tech)
            else:
                adapter = get_default_scanner_adapter(norm_tech)
        else:
            adapter = get_default_scanner_adapter(norm_tech)

        if adapter is None:
            logger.warning("No SAST adapter for technology=%s sast_tools=%s", technology, profile.sast_tools)
            return []
        return adapter.execute_scan(target_path)

    def _run_dast(self, profile: ScanProfile, target_path: str) -> list[Finding]:
        logger.info("DAST runner: tool=%s not yet implemented", profile.dast_tool)
        return []

    def _run_quality(
        self,
        profile: ScanProfile,
        target_path: str,
        technology: str,
    ) -> list[Finding]:
        from src.scanners.eslint_adapter import EslintAdapter
        from src.scanners.pylint_adapter import PylintAdapter

        quality_tool = (profile.quality_tool or "").strip().lower()
        norm_tech = technology.strip().lower()

        if quality_tool == "pylint" and norm_tech == "python":
            adapter = PylintAdapter()
        elif quality_tool == "eslint" and norm_tech in {"angular", "typescript"}:
            adapter = EslintAdapter()
        else:
            message = f"No Quality adapter for technology={technology} quality_tool={profile.quality_tool}"
            logger.warning(message)
            raise RuntimeError(message)

        findings = adapter.execute_scan(target_path)
        if getattr(adapter, "error", None):
            logger.warning("Quality runner %s reported: %s", adapter.tool_name, adapter.error)
            raise RuntimeError(adapter.error)

        return findings

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen: dict[str, Finding] = {}
        for finding in findings:
            fp = finding.fingerprint or build_fingerprint(finding)
            if fp not in seen:
                if not finding.fingerprint:
                    finding.fingerprint = fp
                seen[fp] = finding
        return list(seen.values())
