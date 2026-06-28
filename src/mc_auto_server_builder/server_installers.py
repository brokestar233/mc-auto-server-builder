from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from .util import extract_start_command_from_line

if TYPE_CHECKING:
    from .builder import ServerBuilder


def set_start_command(builder: ServerBuilder, mode: str, value: str, reason: str) -> None:
    normalized_mode = mode if mode in {"jar", "argsfile"} else "jar"
    normalized_value = value.strip().strip('"').strip("'")
    if not normalized_value:
        normalized_mode = "jar"
        normalized_value = builder.server_jar_name
    builder.start_command_mode = normalized_mode
    builder.start_command_value = normalized_value
    builder.operations.append(f"start_command_set:{normalized_mode}:{normalized_value}:{reason}")


def pick_installed_server_jar(
    builder: ServerBuilder,
    loader: str | None = None,
    mc_version: str | None = None,
    loader_version: str | None = None,
) -> str | None:
    candidates = [path for path in builder.workdirs.server.glob("*.jar") if path.is_file()]
    if not candidates:
        return None

    normalized_loader = str(loader or getattr(getattr(builder, "manifest", None), "loader", "") or "").strip().lower()
    normalized_mc_version = str(mc_version or getattr(getattr(builder, "manifest", None), "mc_version", "") or "").strip().lower()
    normalized_loader_version = str(
        loader_version or getattr(getattr(builder, "manifest", None), "loader_version", "") or ""
    ).strip().lower()

    def score(path: Path) -> tuple[int, int, int, str]:
        name = path.name
        lower = name.lower()
        value = 0

        if lower.endswith("-installer.jar") or lower == "forge-installer.jar" or lower == "neoforge-installer.jar":
            value -= 100

        if normalized_loader == "forge":
            if lower.startswith("forge-"):
                value += 40
            if lower.startswith("minecraft_server"):
                value -= 24
            if lower.startswith("neoforge-"):
                value -= 12
            if "fabric" in lower or "quilt" in lower:
                value -= 12
        elif normalized_loader == "neoforge":
            if lower.startswith("neoforge-"):
                value += 40
            if lower.startswith("forge-"):
                value += 8
            if lower.startswith("minecraft_server"):
                value -= 24
            if "fabric" in lower or "quilt" in lower:
                value -= 12
        elif normalized_loader == "fabric":
            if "fabric" in lower:
                value += 40
            if lower.startswith("minecraft_server"):
                value -= 16
        elif normalized_loader == "quilt":
            if "quilt" in lower:
                value += 40
            if lower.startswith("minecraft_server"):
                value -= 16
        else:
            if lower.startswith(("forge-", "neoforge-")) or "fabric" in lower or "quilt" in lower:
                value += 16

        if normalized_loader_version:
            if normalized_loader_version in lower:
                value += 20
            else:
                compact_loader_version = normalized_loader_version.split("-", 1)[-1]
                if compact_loader_version and compact_loader_version in lower:
                    value += 12

        if normalized_mc_version and normalized_mc_version in lower:
            value += 8

        if lower == "server.jar":
            value -= 10
        elif "server" in lower:
            value += 2

        return (value, len(name), -len(lower), lower)

    preferred = sorted(candidates, key=score, reverse=True)[0]
    builder.operations.append(f"start_command_pick_server_jar:{preferred.name}:{normalized_loader or 'unknown'}")
    return preferred.name


def parse_start_command_from_run_scripts(builder: ServerBuilder) -> bool:
    run_sh = builder.workdirs.server / "run.sh"
    run_bat = builder.workdirs.server / "run.bat"
    candidates = [run_bat, run_sh] if os.name == "nt" else [run_sh, run_bat]

    for script in candidates:
        if not script.exists() or not script.is_file():
            continue
        try:
            lines = script.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        for line in lines:
            parsed = extract_start_command_from_line(line)
            if not parsed:
                continue
            mode, value = parsed
            builder._set_start_command(mode, value, f"run_script:{script.name}")
            builder.operations.append(f"start_command_parse_run_scripts:hit:{script.name}:{mode}:{value}")
            return True

    builder.operations.append("start_command_parse_run_scripts:miss")
    return False


def apply_modern_loader_start_mode(builder: ServerBuilder) -> bool:
    candidates = [
        *builder.workdirs.server.glob("libraries/**/unix_args.txt"),
        *builder.workdirs.server.glob("libraries/**/win_args.txt"),
    ]
    if not candidates:
        return False

    manifest = getattr(builder, "manifest", None)
    loader = str(getattr(manifest, "loader", "") or "").lower()
    loader_version = str(getattr(manifest, "loader_version", "") or "")
    mc_version = str(getattr(manifest, "mc_version", "") or "")

    def score(item: Path) -> tuple[int, int, int, int, str]:
        posix = item.as_posix().lower()
        value = 0

        if loader == "neoforge":
            if "/net/neoforged/neoforge/" in posix:
                value += 12
            if "/net/minecraftforge/forge/" in posix:
                value -= 4
        elif loader == "forge":
            if "/net/minecraftforge/forge/" in posix:
                value += 12
            if "/net/neoforged/neoforge/" in posix:
                value -= 4
        else:
            if "/net/neoforged/neoforge/" in posix:
                value += 6
            if "/net/minecraftforge/forge/" in posix:
                value += 6

        if loader_version and loader_version.lower() in posix:
            value += 8
        elif mc_version and mc_version.lower() in posix:
            value += 4

        if item.name == "unix_args.txt":
            value += 2 if os.name != "nt" else 0
        elif item.name == "win_args.txt":
            value += 2 if os.name == "nt" else 0

        return (value, -len(item.parts), -len(item.as_posix()), 0, item.as_posix())

    preferred = sorted(candidates, key=score, reverse=True)[0]
    rel = preferred.relative_to(builder.workdirs.server).as_posix()
    builder._set_start_command("argsfile", rel, "modern_loader_args")
    return True


def recover_start_command_from_existing_server_artifacts(
    builder: ServerBuilder,
    loader: str | None = None,
    mc_version: str | None = None,
    loader_version: str | None = None,
    reason: str = "existing_server_artifacts",
) -> bool:
    if builder._parse_start_command_from_run_scripts():
        builder.operations.append(f"start_command_recovered:run_script:{reason}")
        return True
    if builder._apply_modern_loader_start_mode():
        builder.operations.append(f"start_command_recovered:argsfile:{reason}")
        return True

    picked = builder._pick_installed_server_jar(loader=loader, mc_version=mc_version, loader_version=loader_version)
    if picked:
        builder.server_jar_name = picked
        builder._set_start_command("jar", builder.server_jar_name, reason)
        builder.operations.append(f"start_command_recovered:jar:{picked}:{reason}")
        return True
    return False


def write_start_script(builder: ServerBuilder) -> None:
    script = builder._start_script_path()
    flags = " ".join(builder.extra_jvm_flags).strip()

    builder._parse_start_command_from_run_scripts()

    mode = builder.start_command_mode if builder.start_command_mode in {"jar", "argsfile"} else "jar"
    value = (builder.start_command_value or "").strip()
    if not value:
        mode = "jar"
        value = builder.server_jar_name

    jvm_parts = [f"-Xms{builder.jvm_xms}", f"-Xmx{builder.jvm_xmx}"]
    if flags:
        jvm_parts.append(flags)
    jvm_part = " ".join(jvm_parts)

    bat_value = value.replace('"', '""')
    sh_value = value.replace('"', r"\"")

    if os.name == "nt":
        if mode == "argsfile":
            exec_line = f'"%JAVA_BIN%" {jvm_part} @"{bat_value}" %* nogui\n'
        else:
            exec_line = f'"%JAVA_BIN%" {jvm_part} -jar "{bat_value}" %* nogui\n'
        content = (
            "@echo off\n"
            "setlocal\n"
            "\n"
            'set "SCRIPT_DIR=%~dp0"\n'
            'cd /d "%SCRIPT_DIR%"\n'
            "\n"
            'set "JAVA_BIN="\n'
            "\n"
            'if exist "%SCRIPT_DIR%java_bins\\bin\\java.exe" set "JAVA_BIN=%SCRIPT_DIR%java_bins\\bin\\java.exe"\n'
            'if not defined JAVA_BIN if exist "%SCRIPT_DIR%..\\java_bins\\bin\\java.exe" '
            'set "JAVA_BIN=%SCRIPT_DIR%..\\java_bins\\bin\\java.exe"\n'
            'if not defined JAVA_BIN if exist "%SCRIPT_DIR%..\\..\\.mcasb_cache\\java_bins\\bin\\java.exe" '
            'set "JAVA_BIN=%SCRIPT_DIR%..\\..\\.mcasb_cache\\java_bins\\bin\\java.exe"\n'
            "\n"
            "if not defined JAVA_BIN (\n"
            '  for /d %%D in ("%SCRIPT_DIR%java_bins\\jdk-*") do (\n'
            '    if exist "%%~fD\\bin\\java.exe" (\n'
            '      set "JAVA_BIN=%%~fD\\bin\\java.exe"\n'
            "      goto :java_found\n"
            "    )\n"
            "  )\n"
            ")\n"
            "\n"
            "if not defined JAVA_BIN (\n"
            '  for /d %%D in ("%SCRIPT_DIR%..\\java_bins\\jdk-*") do (\n'
            '    if exist "%%~fD\\bin\\java.exe" (\n'
            '      set "JAVA_BIN=%%~fD\\bin\\java.exe"\n'
            "      goto :java_found\n"
            "    )\n"
            "  )\n"
            ")\n"
            "\n"
            "if not defined JAVA_BIN (\n"
            '  for /d %%D in ("%SCRIPT_DIR%..\\..\\.mcasb_cache\\java_bins\\jdk-*") do (\n'
            '    if exist "%%~fD\\bin\\java.exe" (\n'
            '      set "JAVA_BIN=%%~fD\\bin\\java.exe"\n'
            "      goto :java_found\n"
            "    )\n"
            "  )\n"
            ")\n"
            "\n"
            ":java_found\n"
            'if not defined JAVA_BIN set "JAVA_BIN=java"\n'
            "\n"
            f"{exec_line}"
        )
    else:
        if mode == "argsfile":
            exec_line = f'exec "$JAVA_BIN" {jvm_part} @"{sh_value}" "$@" nogui\n'
        else:
            exec_line = f'exec "$JAVA_BIN" {jvm_part} -jar "{sh_value}" "$@" nogui\n'
        content = (
            "#!/usr/bin/env sh\n"
            "set -e\n"
            "\n"
            'SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
            'cd "$SCRIPT_DIR"\n'
            "\n"
            'JAVA_BIN=""\n'
            "\n"
            'if [ -x "$SCRIPT_DIR/java_bins/bin/java" ]; then\n'
            '  JAVA_BIN="$SCRIPT_DIR/java_bins/bin/java"\n'
            'elif [ -x "$SCRIPT_DIR/../java_bins/bin/java" ]; then\n'
            '  JAVA_BIN="$SCRIPT_DIR/../java_bins/bin/java"\n'
            'elif [ -x "$SCRIPT_DIR/../../.mcasb_cache/java_bins/bin/java" ]; then\n'
            '  JAVA_BIN="$SCRIPT_DIR/../../.mcasb_cache/java_bins/bin/java"\n'
            "else\n"
            '  for candidate in "$SCRIPT_DIR"/java_bins/jdk-*/bin/java '
            '"$SCRIPT_DIR"/../java_bins/jdk-*/bin/java '
            '"$SCRIPT_DIR"/../../.mcasb_cache/java_bins/jdk-*/bin/java; do\n'
            '    if [ -x "$candidate" ]; then\n'
            '      JAVA_BIN="$candidate"\n'
            "      break\n"
            "    fi\n"
            "  done\n"
            "fi\n"
            "\n"
            'if [ -z "$JAVA_BIN" ]; then\n'
            "  JAVA_BIN=java\n"
            "fi\n"
            "\n"
            f"{exec_line}"
        )
    script.write_text(content, encoding="utf-8")
    if os.name != "nt":
        script.chmod(0o755)
