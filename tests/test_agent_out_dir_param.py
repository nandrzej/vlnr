from unittest.mock import MagicMock, patch

from vlnr.agent import AgentLoop


def test_agent_loop_constructor_stores_out_dir() -> None:
    client = MagicMock()
    loop = AgentLoop(client, out_dir="custom/dir")
    assert loop.out_dir == "custom/dir"


def test_agent_loop_out_dir_default_is_out() -> None:
    client = MagicMock()
    loop = AgentLoop(client)
    assert loop.out_dir == "out"


def test_dispatch_scan_package_uses_self_out_dir() -> None:
    client = MagicMock()
    loop = AgentLoop(client, out_dir="custom/dir")
    action = MagicMock()
    action.action = "scan_package"
    action.package_name = "demo"
    state = MagicMock()

    with patch("vlnr.agent.process_package") as mock_process:
        mock_process.return_value = None
        loop.dispatch_action(action, state)

    mock_process.assert_called_once()
    _, kwargs = mock_process.call_args
    assert kwargs["out_dir"] == "custom/dir"
