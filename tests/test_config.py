from __future__ import annotations

import json

import pytest

from mc_auto_server_builder.config import AppConfig, ConfigError


def test_load_default_config_when_path_is_none():
    cfg = AppConfig.load(None)

    assert cfg.memory.xmx == "6G"
    assert cfg.runtime.max_attempts == 20
    assert cfg.ai.enabled is False
    assert cfg.proxy.trust_env is True
    assert cfg.proxy.to_requests_proxies() is None


def test_load_config_normalizes_proxy_fields(tmp_path):
    config_path = tmp_path / "config.json"
    payload = {
        "proxy": {
            "http": " http://127.0.0.1:7890 ",
            "https": "https://127.0.0.1:7891",
            "all": "socks5://127.0.0.1:1080",
            "no_proxy": " localhost,127.0.0.1 ",
            "trust_env": "false",
        }
    }
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    cfg = AppConfig.load(config_path)

    assert cfg.proxy.http == "http://127.0.0.1:7890"
    assert cfg.proxy.https == "https://127.0.0.1:7891"
    assert cfg.proxy.all == "socks5://127.0.0.1:1080"
    assert cfg.proxy.no_proxy == "localhost,127.0.0.1"
    assert cfg.proxy.trust_env is False
    assert cfg.proxy.to_requests_proxies() == {
        "http": "http://127.0.0.1:7890",
        "https": "https://127.0.0.1:7891",
        "all": "socks5://127.0.0.1:1080",
        "no_proxy": "localhost,127.0.0.1",
    }


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


def test_load_default_runtime_max_attempts_is_twenty():
    cfg = AppConfig.load(None)

    assert cfg.runtime.max_attempts == 20


def test_load_config_normalizes_bool_number_and_list_fields(tmp_path):
    config_path = tmp_path / "config.json"
    payload = {
        "runtime": {"keep_running": "true", "max_attempts": "3"},
        "ai": {"stream": "false", "retry_backoff_sec": "2.5", "stop": "<END>"},
        "extra_jvm_flags": "-Dfoo=bar",
        "graalvm_external_packages": [" pkg.a ", "pkg.b"],
    }
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    cfg = AppConfig.load(config_path)

    assert cfg.runtime.keep_running is True
    assert cfg.runtime.max_attempts == 3
    assert cfg.ai.stream is False
    assert cfg.ai.retry_backoff_sec == 2.5
    assert cfg.extra_jvm_flags == ["-Dfoo=bar"]
    assert cfg.graalvm_external_packages == ["pkg.a", "pkg.b"]


def test_load_config_rejects_invalid_json(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text("{invalid", encoding="utf-8")

    with pytest.raises(ConfigError, match="不是合法 JSON"):
        AppConfig.load(config_path)


def test_load_config_rejects_unknown_fields(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"runtime": {"unknown": 1}}), encoding="utf-8")

    with pytest.raises(ConfigError, match="未知字段"):
        AppConfig.load(config_path)


def test_load_config_rejects_invalid_bool_value(tmp_path):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"ai": {"enabled": "not-bool"}}), encoding="utf-8")

    with pytest.raises(ConfigError, match="ai.enabled"):
        AppConfig.load(config_path)
