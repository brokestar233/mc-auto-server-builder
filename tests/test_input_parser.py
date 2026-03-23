from __future__ import annotations

import json
import zipfile
import pytest

from mc_auto_server_builder.input_parser import parse_manifest_from_zip, parse_pack_input


def test_parse_pack_input_local_zip(tmp_path):
    zip_path = tmp_path / "modpack.zip"
    with zipfile.ZipFile(zip_path, "w"):
        pass

    result = parse_pack_input(str(zip_path))

    assert result.input_type == "local_zip"
    assert result.source == str(zip_path.resolve())
    assert result.file_id is None


def test_parse_pack_input_curseforge_id_and_file_id():
    result = parse_pack_input("396246:7760973")

    assert result.input_type == "curseforge"
    assert result.source == "396246"
    assert result.file_id == "7760973"


def test_parse_pack_input_modrinth_version_url():
    result = parse_pack_input("https://modrinth.com/modpack/fabulously-optimized/version/abc12345")

    assert result.input_type == "modrinth"
    assert result.source == "fabulously-optimized"
    assert result.file_id == "abc12345"


def test_parse_manifest_from_zip_full_pack_uses_first_version_dir(tmp_path):
    zip_path = tmp_path / "full-pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            ".minecraft/versions/1.20.1-forge-47.2.0/1.20.1-forge-47.2.0.json",
            json.dumps(
                {
                    "id": "1.20.1-forge-47.2.0",
                    "clientVersion": "1.20.1",
                    "inheritsFrom": "1.20.1",
                    "libraries": [
                        {"name": "net.minecraftforge:forge:1.20.1-47.2.0"},
                    ],
                }
            ),
        )
        zf.writestr(".minecraft/versions/1.20.1-forge-47.2.0/mods/example.jar", "mod")
        zf.writestr(
            ".minecraft/versions/zzz-second/zzz-second.json",
            json.dumps({"id": "zzz-second", "libraries": []}),
        )

    manifest = parse_manifest_from_zip(zip_path)

    assert manifest.pack_name == "1.20.1-forge-47.2.0"
    assert manifest.mc_version == "1.20.1"
    assert manifest.loader == "forge"
    assert manifest.loader_version == "1.20.1-47.2.0"
    assert manifest.raw["pack_type"] == "full_pack"
    assert manifest.raw["full_pack"]["remove_files"] == [
        "1.20.1-forge-47.2.0.jar",
        "1.20.1-forge-47.2.0.json",
    ]


def test_parse_manifest_from_zip_raises_when_no_manifest_and_no_dot_minecraft(tmp_path):
    zip_path = tmp_path / "invalid-pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("overrides/config/example.txt", "value")

    with pytest.raises(ValueError, match=r"既不包含 manifest\.json / modrinth\.index\.json.*也不包含 \.minecraft 目录"):
        parse_manifest_from_zip(zip_path)
