from __future__ import annotations

from mc_auto_server_builder.builder import ServerBuilder


def test_detect_command_probe_ready_accepts_player_count_line():
    ready, source = ServerBuilder._detect_command_probe_ready(
        None,
        "There are 0 of a max of 20 players online:",
    )

    assert ready is True
    assert source == "cmd_probe_list_response"


def test_detect_command_probe_ready_ignores_case():
    ready, source = ServerBuilder._detect_command_probe_ready(
        None,
        "THERE ARE 0 OF A MAX OF 20 PLAYERS ONLINE:",
    )

    assert ready is True
    assert source == "cmd_probe_list_response"

def test_detect_command_probe_ready_rejects_unrelated_output():
    ready, source = ServerBuilder._detect_command_probe_ready(
        None,
        "Done (12.345s)! For help, type \"help\"",
    )

    assert ready is False
    assert source == ""
