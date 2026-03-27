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


def test_parse_pack_input_curseforge_slug_url_without_project_id():
    result = parse_pack_input("https://www.curseforge.com/minecraft/modpacks/all-the-mods-9/files/1234567")

    assert result.input_type == "curseforge"
    assert result.source == "all-the-mods-9"
    assert result.file_id == "1234567"


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


def test_parse_manifest_from_zip_detects_serverstarter_yaml(tmp_path):
    zip_path = tmp_path / "serverstarter-pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "server-setup-config.yaml",
            """
modpack:
  name: Fancy Server Pack
install:
  mcVersion: 1.20.1
  loaderVersion: 47.2.0
launch:
  javaArgs: -Xmx6G
""".strip(),
        )

    manifest = parse_manifest_from_zip(zip_path)

    assert manifest.pack_name == "Fancy Server Pack"
    assert manifest.mc_version == "1.20.1"
    assert manifest.loader == "forge"
    assert manifest.loader_version == "47.2.0"
    assert manifest.start_mode == "script"
    assert manifest.loader_candidates[0].confidence >= 0.9
    assert manifest.evidence[0].source_type in {"serverstarter", "variables", "script", "manifest"}


def test_parse_manifest_from_zip_detects_serverstarter_specver_and_additional_url(tmp_path):
    zip_path = tmp_path / "serverstarter-specver-pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "serverstarter.yaml",
            "\n".join(
                [
                    "_specver: 2",
                    "modpack:",
                    "  name: Neo Server Pack",
                    "install:",
                    "  mcVersion: 1.21.1",
                    "  loaderVersion: 21.1.1-beta",
                    "  modpackUrl: https://example.invalid/additional.zip",
                    "launch:",
                    "  javaArgs: -Xmx6G",
                    "# neoforge neoforge forge",
                ]
            ),
        )

    manifest = parse_manifest_from_zip(zip_path)

    assert manifest.pack_name == "Neo Server Pack"
    assert manifest.loader == "neoforge"
    assert manifest.mc_version == "1.21.1"
    assert manifest.loader_version == "21.1.1-beta"
    assert manifest.raw["additional_resource_urls"] == ["https://example.invalid/additional.zip"]


def test_parse_manifest_from_zip_detects_variables_and_args_script(tmp_path):
    zip_path = tmp_path / "variables-pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "variables.txt",
            "\n".join(
                [
                    "minecraft_version=1.20.1",
                    "modloader=forge",
                    "modloader_version=1.20.1-47.2.0",
                    "java_args=-Xmx8G",
                ]
            ),
        )
        zf.writestr(
            "start.sh",
            "java @libraries/net/minecraftforge/forge/1.20.1-47.2.0/unix_args.txt nogui",
        )

    manifest = parse_manifest_from_zip(zip_path)

    assert manifest.loader == "forge"
    assert manifest.mc_version == "1.20.1"
    assert manifest.loader_version == "1.20.1-47.2.0"
    assert manifest.build == "47.2.0"
    assert manifest.start_mode == "args_file"
    assert manifest.start_mode_candidates[0].value == "args_file"
    assert manifest.raw["recognition_pipeline"][0] == "explicit_metadata"
    assert "explicit_metadata" in manifest.raw["recognition_phase_hits"]
    assert "startup_script" in manifest.raw["recognition_phase_hits"]


def test_parse_manifest_from_zip_supports_colon_style_variables_txt(tmp_path):
    zip_path = tmp_path / "variables-colon-pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "variables.txt",
            "\n".join(
                [
                    "minecraft_version: 1.20.1",
                    "modloader: forge",
                    "modloader_version: 1.20.1-47.2.0",
                    "java_args: -Xmx8G",
                ]
            ),
        )

    manifest = parse_manifest_from_zip(zip_path)

    assert manifest.loader == "forge"
    assert manifest.mc_version == "1.20.1"
    assert manifest.loader_version == "1.20.1-47.2.0"
    assert manifest.start_mode == "script"


def test_parse_manifest_from_zip_variables_unknown_loader_does_not_emit_build_candidate(tmp_path):
    zip_path = tmp_path / "variables-unknown-loader.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "variables.txt",
            "\n".join(
                [
                    "minecraft_version=1.20.1",
                    "modloader=vanilla",
                    "modloader_version=1.20.1-47.2.0",
                ]
            ),
        )
        zf.writestr("start.sh", "java -jar fabric-server-launch.jar nogui")

    manifest = parse_manifest_from_zip(zip_path)

    assert manifest.mc_version == "1.20.1"
    assert manifest.loader in {"fabric", "unknown"}
    assert all(candidate.value for candidate in manifest.loader_candidates)
    assert manifest.build is None
    assert manifest.build_candidates == []


def test_parse_manifest_from_zip_records_multistage_pipeline_details(tmp_path):
    zip_path = tmp_path / "pipeline-pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("variables.txt", "minecraft_version=1.20.1\nmodloader=forge\nmodloader_version=1.20.1-47.2.0")
        zf.writestr("start.sh", "java @libraries/net/minecraftforge/forge/1.20.1-47.2.0/unix_args.txt nogui")
        zf.writestr("docs/readme.txt", "Forge server for Minecraft 1.20.1")

    manifest = parse_manifest_from_zip(zip_path)

    assert manifest.raw["recognition_pipeline"] == [
        "explicit_metadata",
        "startup_script",
        "file_pattern",
        "directory_feature",
        "text_heuristic",
        "runtime_feedback",
    ]
    assert "explicit_metadata" in manifest.raw["recognition_phase_hits"]
    assert "startup_script" in manifest.raw["recognition_phase_hits"]
    assert "text_heuristic" in manifest.raw["recognition_phase_hits"]
    assert any(item.startswith("variables:") for item in manifest.raw["recognition_phase_details"]["explicit_metadata"])


def test_parse_manifest_from_zip_detects_directory_and_text_heuristics(tmp_path):
    zip_path = tmp_path / "heuristic-pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("libraries/net/neoforged/neoforge/21.0.10/win_args.txt", "args")
        zf.writestr("docs/readme.txt", "This server uses NeoForge on Minecraft 1.21.1. NeoForge is required.")

    manifest = parse_manifest_from_zip(zip_path)

    assert manifest.loader == "neoforge"
    assert manifest.mc_version == "1.21.1"
    assert manifest.start_mode in {"args_file", "jar", "script"}
    assert any(candidate.value == "neoforge" for candidate in manifest.loader_candidates)


def test_parse_manifest_from_zip_resolves_variable_based_start_script(tmp_path):
    zip_path = tmp_path / "variable-script-pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "start.sh",
            "\n".join(
                [
                    'FORGE_PATH="libraries/net/minecraftforge/forge/1.20.1-47.2.0/unix_args.txt"',
                    'java @${FORGE_PATH} nogui',
                ]
            ),
        )

    manifest = parse_manifest_from_zip(zip_path)

    assert manifest.loader == "forge"
    assert manifest.mc_version == "1.20.1"
    assert manifest.loader_version == "1.20.1-47.2.0"
    assert manifest.build == "47.2.0"
    assert manifest.start_mode == "args_file"
    assert manifest.raw["script_variables"]["forge_path"] == "libraries/net/minecraftforge/forge/1.20.1-47.2.0/unix_args.txt"


def test_parse_manifest_from_zip_resolves_nested_script_variables(tmp_path):
    zip_path = tmp_path / "nested-variable-script-pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "start.sh",
            "\n".join(
                [
                    'MC_VERSION="1.20.1"',
                    'FORGE_VERSION="${MC_VERSION}-47.2.0"',
                    'FORGE_PATH="libraries/net/minecraftforge/forge/${FORGE_VERSION}/unix_args.txt"',
                    'java @${FORGE_PATH} nogui',
                ]
            ),
        )

    manifest = parse_manifest_from_zip(zip_path)

    assert manifest.loader == "forge"
    assert manifest.mc_version == "1.20.1"
    assert manifest.loader_version == "1.20.1-47.2.0"
    assert manifest.build == "47.2.0"
    assert manifest.start_mode == "args_file"


def test_parse_manifest_from_zip_empty_variable_match_falls_back_to_default_start_mode(tmp_path):
    zip_path = tmp_path / "empty-variable-script-pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            "start.sh",
            "\n".join(
                [
                    'FORGE_PATH="${MISSING_VAR}"',
                    'java @${FORGE_PATH} nogui',
                ]
            ),
        )
        zf.writestr("readme.txt", "Minecraft 1.20.1 server package")

    manifest = parse_manifest_from_zip(zip_path)

    assert manifest.mc_version == "1.20.1"
    assert manifest.loader == "unknown"
    assert manifest.start_mode == "script"
    assert manifest.loader_candidates == []


def test_parse_manifest_from_zip_marks_server_pack_hints(tmp_path):
    zip_path = tmp_path / "server-files-pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("docs/Server Files Guide.txt", "Use this server package with Forge 1.20.1")
        zf.writestr("forge-1.20.1-47.2.0.jar", "jar")

    manifest = parse_manifest_from_zip(zip_path)

    assert manifest.loader == "forge"
    assert manifest.raw["server_pack_hints"] == ["docs/Server Files Guide.txt"]


def test_parse_manifest_from_zip_full_pack_prefers_version_root_with_mods_and_config(tmp_path):
    zip_path = tmp_path / "multi-version-full-pack.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr(
            ".minecraft/versions/aaa-empty/aaa-empty.json",
            json.dumps({"id": "aaa-empty", "libraries": []}),
        )
        zf.writestr(
            ".minecraft/versions/1.20.1-forge-47.2.0/1.20.1-forge-47.2.0.json",
            json.dumps(
                {
                    "id": "1.20.1-forge-47.2.0",
                    "clientVersion": "1.20.1",
                    "inheritsFrom": "1.20.1",
                    "libraries": [{"name": "net.minecraftforge:forge:1.20.1-47.2.0"}],
                }
            ),
        )
        zf.writestr(".minecraft/versions/1.20.1-forge-47.2.0/mods/example.jar", "mod")
        zf.writestr(".minecraft/versions/1.20.1-forge-47.2.0/config/example.toml", "cfg")

    manifest = parse_manifest_from_zip(zip_path)

    assert manifest.pack_name == "1.20.1-forge-47.2.0"
    assert manifest.mc_version == "1.20.1"
    assert manifest.loader == "forge"
    assert manifest.raw["full_pack"]["candidate_versions"] == ["1.20.1-forge-47.2.0", "aaa-empty"]
