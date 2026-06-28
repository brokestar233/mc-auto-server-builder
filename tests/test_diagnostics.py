from __future__ import annotations

import json
import zipfile
from pathlib import Path

from mc_auto_server_builder.diagnostics import (
    build_dependency_graph,
    inspect_crash_report,
    inspect_mod_metadata,
    verify_start_command_artifacts,
)


def _write_jar(path: Path, members: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in members.items():
            zf.writestr(name, content)


def test_inspect_mod_metadata_and_dependency_graph_detect_deleted_dependency(tmp_path):
    mods_dir = tmp_path / "mods"
    mods_dir.mkdir()
    _write_jar(
        mods_dir / "client-ui.jar",
        {
            "fabric.mod.json": json.dumps(
                {
                    "id": "client-ui",
                    "name": "Client UI",
                    "environment": "client",
                }
            )
        },
    )
    _write_jar(
        mods_dir / "server-addon.jar",
        {
            "fabric.mod.json": json.dumps(
                {
                    "id": "server-addon",
                    "name": "Server Addon",
                    "depends": {"client-ui": ">=1.0.0"},
                }
            )
        },
    )

    metadata = inspect_mod_metadata(mods_dir)
    graph = build_dependency_graph(metadata, ["client-ui.jar"])

    assert metadata["client_only_mods"] == ["client-ui.jar"]
    assert any(item["file_name"] == "server-addon.jar" for item in metadata["files"])
    assert graph["deleted_dependency_hits"][0]["file_name"] == "server-addon.jar"
    assert graph["deleted_dependency_hits"][0]["dependency_id"] == "client-ui"


def test_verify_start_command_artifacts_reports_missing_argsfile_reference(tmp_path):
    server_dir = tmp_path / "server"
    libs_dir = server_dir / "libraries"
    libs_dir.mkdir(parents=True)
    argsfile = libs_dir / "unix_args.txt"
    argsfile.write_text("-cp lib.jar -jar missing-server.jar", encoding="utf-8")

    result = verify_start_command_artifacts(server_dir, "argsfile", "libraries/unix_args.txt", server_jar_name="server.jar")

    assert result["target_exists"] is True
    assert "argsfile_references_missing_jar" in result["issues"]
    assert "missing-server.jar" in result["missing_references"]


def test_inspect_crash_report_extracts_key_signals():
    result = inspect_crash_report(
        "Caused by: java.lang.RuntimeException: boom\nMixin apply failed for mod examplemod",
        "examplemod requires clientlib but it is missing",
        "-- Mod loading issue for: examplemod --",
    )

    assert result["caused_by"][0] == "java.lang.RuntimeException: boom"
    assert "clientlib" in result["missing_dependency_hints"]
    assert "examplemod" in result["mentioned_mod_ids"]
