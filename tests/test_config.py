from __future__ import annotations

import json

from mc_auto_server_builder.config import AppConfig


def test_load_default_config_when_path_is_none():
    cfg = AppConfig.load(None)

    assert cfg.memory.xmx == "6G"
    assert cfg.runtime.max_attempts == 8
    assert cfg.ai.enabled is False


def test_load_config_normalizes_ai_stop_string(tmp_path):
    config_path = tmp_path / "config.json"
    payload = {
        "ai": {
            "enabled": True,
            "provider": "openai_compatible",
            "stop": "<END>",
        }
    }
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    cfg = AppConfig.load(config_path)

    assert cfg.ai.enabled is True
    assert cfg.ai.provider == "openai_compatible"
    assert cfg.ai.stop == ["<END>"]

