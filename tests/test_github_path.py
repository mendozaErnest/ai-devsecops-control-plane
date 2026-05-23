import logging

import pytest

from src.integrations.github_client import normalize_file_path_for_github


def test_normalize_repo_path():
    path = "/home/user/workspace/uploads/73c10e6f-1234-5678-abcd-123456789012/repo/src/api/main.py"
    assert normalize_file_path_for_github(path) == "src/api/main.py"


def test_normalize_source_path():
    path = "/home/user/workspace/uploads/73c10e6f-1234-5678-abcd-123456789012/source/src/api/main.py"
    assert normalize_file_path_for_github(path) == "src/api/main.py"


def test_normalize_already_relative():
    assert normalize_file_path_for_github("src/api/main.py") == "src/api/main.py"


def test_normalize_no_match_returns_original(caplog):
    with caplog.at_level(logging.WARNING, logger="src.integrations.github_client"):
        result = normalize_file_path_for_github("/etc/passwd")
    assert result == "/etc/passwd"
    assert any("normalize_file_path_for_github" in msg for msg in caplog.messages)
