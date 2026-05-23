import logging
import os
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from src.api.models import Finding, ScanProfile
from src.scanners.escaneo import build_fingerprint, get_scanner_adapter

logger = logging.getLogger(__name__)


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
        # Honour profile.sast_tools by temporarily overriding SCANNER_ENGINE
        original = os.environ.get("SCANNER_ENGINE")
        os.environ["SCANNER_ENGINE"] = profile.sast_tools
        try:
            adapter = get_scanner_adapter(technology)
            if adapter is None:
                logger.warning("No SAST adapter for technology=%s", technology)
                return []
            return adapter.execute_scan(target_path)
        finally:
            if original is None:
                os.environ.pop("SCANNER_ENGINE", None)
            else:
                os.environ["SCANNER_ENGINE"] = original

    def _run_dast(self, profile: ScanProfile, target_path: str) -> list[Finding]:
        logger.info("DAST runner: tool=%s not yet implemented", profile.dast_tool)
        return []

    def _run_quality(
        self,
        profile: ScanProfile,
        target_path: str,
        technology: str,
    ) -> list[Finding]:
        logger.info("Quality runner: tool=%s not yet implemented", profile.quality_tool)
        return []

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen: dict[str, Finding] = {}
        for finding in findings:
            fp = finding.fingerprint or build_fingerprint(finding)
            if fp not in seen:
                if not finding.fingerprint:
                    finding.fingerprint = fp
                seen[fp] = finding
        return list(seen.values())
