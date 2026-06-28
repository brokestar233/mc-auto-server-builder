from __future__ import annotations

from mc_auto_server_builder.builder import ServerBuilder
from mc_auto_server_builder.models import PackManifest
from mc_auto_server_builder.workspace import create_cache_dirs, create_workdirs


def test_create_workdirs_uses_shared_cache_layout(tmp_path):
    cache_dirs = create_cache_dirs(tmp_path)
    workdirs = create_workdirs(tmp_path, cache_dirs=cache_dirs)

    assert workdirs.root.parent == tmp_path / "runs"
    assert workdirs.java_bins == tmp_path / ".mcasb_cache" / "java_bins"
    assert workdirs.db == workdirs.root / "db"
    assert workdirs.server.exists()
    assert cache_dirs.packs.exists()
    assert cache_dirs.manifests.exists()


def test_prepare_runtime_environment_resume_skips_server_prepare(tmp_path):
    cache_dirs = create_cache_dirs(tmp_path)
    resume_dir = tmp_path / "runs" / "workdir_resume"
    workdirs = create_workdirs(tmp_path, resume_dir=resume_dir, cache_dirs=cache_dirs)
    (workdirs.server / "mods").mkdir(parents=True)

    builder = ServerBuilder.__new__(ServerBuilder)
    builder.resume_requested = True
    builder.resume_state = {"prepared_server": True}
    builder.workdirs = workdirs
    builder.current_java_version = 21
    calls: list[str] = []

    builder._log = lambda *_args, **_kwargs: None
    builder._resolve_pack_and_manifest = lambda: setattr(
        builder, "manifest", PackManifest(pack_name="Pack", mc_version="1.20.1", loader="forge")
    )
    builder._prepare_server_files = lambda: calls.append("prepare_server_files")
    builder.apply_known_client_blacklist = lambda: calls.append("apply_known_client_blacklist")
    builder.backup_mods = lambda _tag: calls.append("backup_mods")
    builder._ensure_server_meta_files = lambda: calls.append("ensure_meta")
    builder._select_java_version_for_current_manifest = lambda: 21
    builder.switch_java_version = lambda version: calls.append(f"switch_java:{version}")
    builder._verify_start_command_artifacts = lambda: {"target_exists": True}
    builder._recover_start_command_from_existing_server_artifacts = lambda **_kwargs: calls.append("recover_start_command")
    builder._persist_resume_state = lambda **kwargs: calls.append(f"persist:{kwargs['prepared_server']}")

    ServerBuilder._prepare_runtime_environment(builder)

    assert "prepare_server_files" not in calls
    assert "apply_known_client_blacklist" not in calls
    assert "backup_mods" not in calls
    assert "ensure_meta" in calls
    assert "recover_start_command" not in calls
    assert "persist:True" in calls
