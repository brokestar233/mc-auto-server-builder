from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from mc_auto_server_builder import cli


def test_main_check_config_success_outputs_json(tmp_path, monkeypatch, capsys):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"runtime": {"max_attempts": 2}}), encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        ["mcasb", "--check-config", "--config", str(config_path), "--json"],
    )

    cli.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["message"] == "配置校验通过"


def test_main_check_config_requires_config(monkeypatch):
    monkeypatch.setattr("sys.argv", ["mcasb", "--check-config"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2


def test_main_rejects_missing_source_without_check_config(monkeypatch):
    monkeypatch.setattr("sys.argv", ["mcasb"])

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 2


def test_main_build_path_invokes_builder_and_outputs_json(tmp_path, monkeypatch, capsys):
    source_path = tmp_path / "pack.zip"
    source_path.write_text("zip", encoding="utf-8")
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"runtime": {"max_attempts": 2}}), encoding="utf-8")

    captured: dict[str, object] = {}

    class FakeBuilder:
        def __init__(self, source: str, config: object, base_dir: str):
            captured["source"] = source
            captured["config"] = config
            captured["base_dir"] = base_dir

        def run(self) -> dict[str, object]:
            return {
                "success": True,
                "workdir": str(Path("/tmp/workdir")),
                "report": str(Path("/tmp/workdir") / "report.txt"),
                "package": str(Path("/tmp/workdir") / "server_pack.zip"),
            }

    monkeypatch.setattr(cli, "ServerBuilder", FakeBuilder)
    monkeypatch.setattr(
        "sys.argv",
        ["mcasb", str(source_path), "--config", str(config_path), "--base-dir", str(tmp_path), "--json"],
    )

    cli.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload["success"] is True
    assert captured["source"] == str(source_path)
    assert captured["base_dir"] == str(tmp_path)
    config = cast(Any, captured["config"])
    assert config.runtime.max_attempts == 2


def test_main_build_path_renders_human_summary_without_json(tmp_path, monkeypatch, capsys):
    source_path = tmp_path / "pack.zip"
    source_path.write_text("zip", encoding="utf-8")

    class FakeBuilder:
        def __init__(self, source: str, config: object, base_dir: str):
            self.source = source
            self.config = config
            self.base_dir = base_dir

        def run(self) -> dict[str, object]:
            return {
                "success": False,
                "workdir": str(tmp_path / "workdir_123"),
                "report": str(tmp_path / "workdir_123" / "report.txt"),
                "package": str(tmp_path / "workdir_123" / "server_pack.zip"),
            }

    monkeypatch.setattr(cli, "ServerBuilder", FakeBuilder)
    monkeypatch.setattr("sys.argv", ["mcasb", str(source_path), "--base-dir", str(tmp_path)])

    cli.main()

    out = capsys.readouterr().out
    compact_out = out.replace("\n", "")
    assert "构建完成" in out
    assert "成功状态: False" in out
    assert str(tmp_path / "workdir_123") in compact_out
    assert "report.txt" in compact_out


def test_main_proxy_override_updates_config(tmp_path, monkeypatch, capsys):
    source_path = tmp_path / "pack.zip"
    source_path.write_text("zip", encoding="utf-8")
    captured: dict[str, object] = {}

    class FakeBuilder:
        def __init__(self, source: str, config: object, base_dir: str):
            captured["source"] = source
            captured["config"] = config
            captured["base_dir"] = base_dir

        def run(self) -> dict[str, object]:
            return {
                "success": True,
                "workdir": str(tmp_path / "workdir"),
                "report": str(tmp_path / "workdir" / "report.txt"),
                "package": str(tmp_path / "workdir" / "server_pack.zip"),
            }

    monkeypatch.setattr(cli, "ServerBuilder", FakeBuilder)
    monkeypatch.setattr(
        "sys.argv",
        [
            "mcasb",
            str(source_path),
            "--proxy",
            "http://127.0.0.1:7890",
            "--no-proxy",
            "localhost,127.0.0.1",
            "--proxy-trust-env",
            "false",
            "--json",
        ],
    )

    cli.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload["success"] is True
    config = cast(Any, captured["config"])
    assert config.proxy.http == "http://127.0.0.1:7890"
    assert config.proxy.https == "http://127.0.0.1:7890"
    assert config.proxy.all == "http://127.0.0.1:7890"
    assert config.proxy.no_proxy == "localhost,127.0.0.1"
    assert config.proxy.trust_env is False
