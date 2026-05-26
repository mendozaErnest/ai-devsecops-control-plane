from pathlib import Path

from src.api import main as app_module


def test_resolve_finding_file_path_remaps_host_workspace_path(monkeypatch, tmp_path):
    project_root = tmp_path / "repo"
    workspace_file = project_root / "workspace" / "uploads" / "scan-1" / "source" / "src" / "app.py"
    workspace_file.parent.mkdir(parents=True)
    workspace_file.write_text("print('ok')\n", encoding="utf-8")

    host_path = "/home/user/AI-DevSecOps-Control-Plane/workspace/uploads/scan-1/source/src/app.py"

    monkeypatch.delenv("SCAN_ALLOWED_ROOTS", raising=False)
    monkeypatch.setattr(app_module, "PROJECT_ROOT", project_root)
    monkeypatch.setattr(app_module, "WORKSPACE_ROOT", project_root / "workspace" / "uploads")

    assert app_module.resolve_finding_file_path(host_path) == workspace_file.resolve()


def test_resolve_finding_file_path_handles_relative_repo_path(monkeypatch, tmp_path):
    project_root = tmp_path / "repo"
    source_file = project_root / "src" / "api" / "main.py"
    source_file.parent.mkdir(parents=True)
    source_file.write_text("app = object()\n", encoding="utf-8")

    monkeypatch.delenv("SCAN_ALLOWED_ROOTS", raising=False)
    monkeypatch.setattr(app_module, "PROJECT_ROOT", project_root)
    monkeypatch.setattr(app_module, "WORKSPACE_ROOT", project_root / "workspace" / "uploads")

    assert app_module.resolve_finding_file_path("src/api/main.py") == source_file.resolve()
