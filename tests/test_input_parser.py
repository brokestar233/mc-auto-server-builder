from __future__ import annotations

import zipfile

from mc_auto_server_builder.input_parser import parse_pack_input


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

