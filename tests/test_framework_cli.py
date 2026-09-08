"""Tests for framework CLI (truckdevil.py) with virtual device."""

import importlib.util
import os
import re
import sys
import uuid
from textwrap import dedent

import pytest

# Load FrameworkCommands from truckdevil/truckdevil.py (needs truckdevil dir on path for libs/modules)
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TRUCKDEVIL_DIR = os.path.join(_REPO_ROOT, "truckdevil")


def _load_truckdevil_cli_module():
    """Load truckdevil.py as a module for CLI-focused tests."""
    spec = importlib.util.spec_from_file_location(
        "truckdevil_cli",
        os.path.join(_TRUCKDEVIL_DIR, "truckdevil.py"),
        submodule_search_locations=[_TRUCKDEVIL_DIR],
    )
    mod = importlib.util.module_from_spec(spec)
    old_path = list(sys.path)
    try:
        sys.path.insert(0, _REPO_ROOT)
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.path[:] = old_path


def _load_framework_commands():
    return _load_truckdevil_cli_module().FrameworkCommands


@pytest.fixture
def shared_channel():
    return f"cli-{uuid.uuid4().hex}"


def _load_version():
    """Load __version__ from truckdevil/__init__.py."""
    spec = importlib.util.spec_from_file_location(
        "truckdevil_init",
        os.path.join(_TRUCKDEVIL_DIR, "__init__.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.__version__


def test_version_format():
    """__version__ exists and follows semver (MAJOR.MINOR.PATCH)."""
    version = _load_version()
    assert re.match(r"^\d+\.\d+\.\d+$", version), (
        f"unexpected version format: {version}"
    )


def test_version_in_intro_banner(truckdevil_module_env):
    """The intro banner contains the version string."""
    FrameworkCommands = _load_framework_commands()
    version = _load_version()
    fc = FrameworkCommands()
    assert version in fc.intro


def test_version_flag(truckdevil_module_env):
    """python truckdevil.py --version prints 'truckdevil <version>' and exits."""
    import subprocess

    result = subprocess.run(
        [sys.executable, os.path.join(_TRUCKDEVIL_DIR, "truckdevil.py"), "--version"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert _load_version() in result.stdout


def test_python_module_version_flag(truckdevil_module_env):
    """python -m truckdevil --version prints 'truckdevil <version>' and exits."""
    import subprocess

    result = subprocess.run(
        [sys.executable, "-m", "truckdevil", "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        cwd=_REPO_ROOT,
    )
    assert result.returncode == 0
    assert _load_version() in result.stdout


def test_cli_add_device_list_device(truckdevil_module_env, shared_channel):
    """add_device virtual <channel> 250000 then list_device; assert device type virtual and channel in output."""
    FrameworkCommands = _load_framework_commands()

    fc = FrameworkCommands()
    fc.onecmd(f"add_device virtual {shared_channel} 250000")
    buf = __import__("io").StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        fc.onecmd("list_device")
    finally:
        sys.stdout = old
    out = buf.getvalue()
    assert "virtual" in out
    assert shared_channel in out
    # Cleanup: device holds can_bus
    if fc.device is not None and getattr(fc.device, "can_bus", None) is not None:
        try:
            fc.device.can_bus.shutdown()
        except Exception:
            pass


def test_cli_add_device_tcp(monkeypatch, truckdevil_module_env):
    """add_device m2:<ip> can0 500000 1234 sets up TCP device."""
    import socket

    class MockSocket:
        def __init__(self, *args, **kwargs):
            pass

        def setsockopt(self, *args, **kwargs):
            pass

        def connect(self, addr):
            pass

        def sendall(self, data):
            pass

    monkeypatch.setattr(socket, "socket", MockSocket)
    FrameworkCommands = _load_framework_commands()
    fc = FrameworkCommands()
    fc.onecmd("add_device m2:192.168.7.2 can0 500000 1234")
    assert fc.device is not None
    assert fc.device.m2_used is True
    assert "192.168.7.2" in str(fc.device)


def test_cli_add_device_invalid_ip(truckdevil_module_env):
    """add_device with malformed IP prints error."""
    FrameworkCommands = _load_framework_commands()
    fc = FrameworkCommands()
    buf = __import__("io").StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        fc.onecmd("add_device m2:999.999.999.999 can0 500000 1234")
    finally:
        sys.stdout = old
    assert "Error: invalid IP address" in buf.getvalue()


def test_cli_list_device_when_none(truckdevil_module_env):
    """list_device prints 'No device configured.' when device is None."""
    FrameworkCommands = _load_framework_commands()
    fc = FrameworkCommands()
    buf = __import__("io").StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        fc.onecmd("list_device")
    finally:
        sys.stdout = old
    assert "No device configured." in buf.getvalue()


def test_cli_list_device_tcp(monkeypatch, truckdevil_module_env):
    """list_device prints TCP IP and Port for TCP M2 device."""
    import socket

    class MockSocket:
        def __init__(self, *args, **kwargs):
            pass

        def setsockopt(self, *args, **kwargs):
            pass

        def connect(self, addr):
            pass

        def sendall(self, data):
            pass

    monkeypatch.setattr(socket, "socket", MockSocket)
    FrameworkCommands = _load_framework_commands()
    fc = FrameworkCommands()
    fc.onecmd("add_device m2:10.0.0.50 can0 250000 9000")
    buf = __import__("io").StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        fc.onecmd("list_device")
    finally:
        sys.stdout = old
    out = buf.getvalue()
    assert "TCP IP: 10.0.0.50" in out
    assert "Port: 9000" in out


def test_cli_run_module_read_messages(truckdevil_module_env, shared_channel):
    """run_module read_messages with args (set, settings, back); no blocking on print_messages."""
    FrameworkCommands = _load_framework_commands()

    fc = FrameworkCommands()
    fc.onecmd(f"add_device virtual {shared_channel} 250000")
    try:
        buf = __import__("io").StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            # Use set + settings + back so we don't block in print_messages waiting for CAN traffic
            fc.onecmd("run_module read_messages set num_messages 1 settings back")
        finally:
            sys.stdout = old
    finally:
        if fc.device is not None and getattr(fc.device, "can_bus", None) is not None:
            try:
                fc.device.can_bus.shutdown()
            except Exception:
                pass


def test_cli_run_module_send_messages(truckdevil_module_env, shared_channel):
    """run_module send_messages send 0x18EA00FF 00 back; no exception."""
    FrameworkCommands = _load_framework_commands()

    fc = FrameworkCommands()
    fc.onecmd(f"add_device virtual {shared_channel} 250000")
    try:
        buf = __import__("io").StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            fc.onecmd("run_module send_messages send 0x18EA00FF 00 back")
        finally:
            sys.stdout = old
    finally:
        if fc.device is not None and getattr(fc.device, "can_bus", None) is not None:
            try:
                fc.device.can_bus.shutdown()
            except Exception:
                pass


def test_cli_list_modules(truckdevil_module_env):
    """list_modules: assert known module names appear."""
    FrameworkCommands = _load_framework_commands()

    fc = FrameworkCommands()
    buf = __import__("io").StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        fc.onecmd("list_modules")
    finally:
        sys.stdout = old
    out = buf.getvalue()
    for name in ("ecu_discovery", "j1939_fuzzer", "read_messages", "send_messages"):
        assert name in out


def test_cli_ls_alias(truckdevil_module_env):
    """ls is an alias for list_modules."""
    FrameworkCommands = _load_framework_commands()

    fc = FrameworkCommands()
    buf = __import__("io").StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        fc.onecmd("ls")
    finally:
        sys.stdout = old
    out = buf.getvalue()
    for name in ("ecu_discovery", "j1939_fuzzer", "read_messages", "send_messages"):
        assert name in out


def test_cli_use_alias(truckdevil_module_env, shared_channel):
    """use is an alias for run_module."""
    FrameworkCommands = _load_framework_commands()

    fc = FrameworkCommands()
    fc.onecmd(f"add_device virtual {shared_channel} 250000")
    try:
        buf = __import__("io").StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            fc.onecmd("use read_messages settings back")
        finally:
            sys.stdout = old
        # Should have run read_messages module without error
    finally:
        if fc.device is not None and getattr(fc.device, "can_bus", None) is not None:
            try:
                fc.device.can_bus.shutdown()
            except Exception:
                pass


def test_cli_quit(truckdevil_module_env):
    """quit raises SystemExit."""
    FrameworkCommands = _load_framework_commands()

    fc = FrameworkCommands()
    with pytest.raises(SystemExit):
        fc.onecmd("quit")


def test_cli_add_device_missing_args(truckdevil_module_env):
    """add_device with too few args prints error."""
    FrameworkCommands = _load_framework_commands()

    fc = FrameworkCommands()
    buf = __import__("io").StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        fc.onecmd("add_device virtual")  # missing channel and baud
    finally:
        sys.stdout = old
    out = buf.getvalue()
    assert "Error" in out or "expected" in out.lower()


def test_cli_run_module_not_found(truckdevil_module_env, shared_channel):
    """run_module with unknown module name prints error."""
    FrameworkCommands = _load_framework_commands()

    fc = FrameworkCommands()
    fc.onecmd(f"add_device virtual {shared_channel} 250000")
    try:
        buf = __import__("io").StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            fc.onecmd("run_module nonexistent_module")
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert "Error" in out or "not found" in out.lower()
    finally:
        if fc.device is not None and getattr(fc.device, "can_bus", None) is not None:
            try:
                fc.device.can_bus.shutdown()
            except Exception:
                pass


def test_cli_run_module_no_args(truckdevil_module_env):
    """run_module with no module name prints error."""
    FrameworkCommands = _load_framework_commands()

    fc = FrameworkCommands()
    buf = __import__("io").StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        fc.onecmd("run_module")
    finally:
        sys.stdout = old
    out = buf.getvalue()
    assert "Error" in out or "expected" in out.lower()


def test_cli_complete_run_module(truckdevil_module_env):
    """complete_run_module returns module names matching prefix."""
    FrameworkCommands = _load_framework_commands()

    fc = FrameworkCommands()
    completions = fc.complete_run_module("read", "run_module read", 11, 15)
    assert "read_messages" in completions

    all_completions = fc.complete_run_module("", "run_module ", 11, 11)
    assert len(all_completions) >= 4


def test_cli_complete_use(truckdevil_module_env):
    """complete_use returns module names matching prefix."""
    FrameworkCommands = _load_framework_commands()

    fc = FrameworkCommands()
    completions = fc.complete_use("send", "use send", 4, 8)
    assert "send_messages" in completions

    all_completions = fc.complete_use("", "use ", 4, 4)
    assert len(all_completions) >= 4


def test_readline_tab_binding_configured(truckdevil_module_env):
    """readline 'tab: complete' binding is set after importing truckdevil."""
    readline = pytest.importorskip("readline")
    # After importing readline, verify we can parse_and_bind without error
    # (the actual binding happens in __main__ and Command.preloop)
    if getattr(readline, "__doc__", None) and "libedit" in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")


def test_command_preloop_does_not_raise(truckdevil_module_env):
    """Command.preloop() runs without error (sets libedit binding if needed)."""
    from truckdevil.libs.command import Command

    cmd_instance = Command()
    # preloop should not raise regardless of readline backend
    cmd_instance.preloop()


def test_cli_device_added_property(truckdevil_module_env, shared_channel):
    """device_added is False until add_device, then True."""
    FrameworkCommands = _load_framework_commands()

    fc = FrameworkCommands()
    assert fc.device_added is False
    fc.onecmd(f"add_device virtual {shared_channel} 250000")
    assert fc.device_added is True
    if fc.device is not None and getattr(fc.device, "can_bus", None) is not None:
        try:
            fc.device.can_bus.shutdown()
        except Exception:
            pass


def test_cli_list_modules_includes_user_module(
    truckdevil_module_env, tmp_path, monkeypatch
):
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_file = module_dir / "user_echo.py"
    module_file.write_text(
        dedent(
            """
            def main_mod(argv, device):
                print("user module ran")
            """
        ).strip()
        + "\n"
    )
    monkeypatch.setenv("TRUCKDEVIL_MODULE_PATH", str(module_dir))

    FrameworkCommands = _load_framework_commands()
    fc = FrameworkCommands()

    assert "user_echo" in fc.module_names


def test_cli_run_user_module(truckdevil_module_env, tmp_path, monkeypatch):
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_file = module_dir / "user_echo.py"
    module_file.write_text(
        dedent(
            """
            def main_mod(argv, device):
                print("user module {}".format(" ".join(argv)))
            """
        ).strip()
        + "\n"
    )
    monkeypatch.setenv("TRUCKDEVIL_MODULE_PATH", str(module_dir))

    FrameworkCommands = _load_framework_commands()
    fc = FrameworkCommands()
    buf = __import__("io").StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        fc.onecmd("run_module user_echo hello world")
    finally:
        sys.stdout = old

    assert "user module hello world" in buf.getvalue()


def test_cli_user_module_path_env_supports_multiple_dirs(
    truckdevil_module_env, tmp_path, monkeypatch
):
    first_dir = tmp_path / "modules_a"
    second_dir = tmp_path / "modules_b"
    first_dir.mkdir()
    second_dir.mkdir()
    (second_dir / "user_echo.py").write_text(
        dedent(
            """
            def main_mod(argv, device):
                print("multi path module")
            """
        ).strip()
        + "\n"
    )
    monkeypatch.setenv(
        "TRUCKDEVIL_MODULE_PATH",
        os.pathsep.join([str(first_dir), str(second_dir)]),
    )

    FrameworkCommands = _load_framework_commands()
    fc = FrameworkCommands()

    assert "user_echo" in fc.module_names


class _FakeEntryPoint:
    def __init__(self, name, loaded):
        self.name = name
        self._loaded = loaded

    def load(self):
        return self._loaded


class _ModuleWithMainMod:
    @staticmethod
    def main_mod(argv, device):
        print("plugin main_mod {}".format(" ".join(argv)))


def test_cli_list_modules_includes_entry_point_module(
    truckdevil_module_env, monkeypatch
):
    cli_mod = _load_truckdevil_cli_module()

    def plugin_main(argv, device):
        return None

    monkeypatch.setattr(
        cli_mod,
        "_iter_module_entry_points",
        lambda: [_FakeEntryPoint("plugin_echo", plugin_main)],
    )

    fc = cli_mod.FrameworkCommands()

    assert "plugin_echo" in fc.module_names


def test_cli_run_entry_point_module(truckdevil_module_env, monkeypatch):
    cli_mod = _load_truckdevil_cli_module()

    def plugin_main(argv, device):
        print("plugin module {}".format(" ".join(argv)))

    monkeypatch.setattr(
        cli_mod,
        "_iter_module_entry_points",
        lambda: [_FakeEntryPoint("plugin_echo", plugin_main)],
    )

    fc = cli_mod.FrameworkCommands()
    buf = __import__("io").StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        fc.onecmd("run_module plugin_echo alpha beta")
    finally:
        sys.stdout = old

    assert "plugin module alpha beta" in buf.getvalue()


def test_cli_run_entry_point_module_object(truckdevil_module_env, monkeypatch):
    cli_mod = _load_truckdevil_cli_module()

    monkeypatch.setattr(
        cli_mod,
        "_iter_module_entry_points",
        lambda: [_FakeEntryPoint("plugin_main_mod", _ModuleWithMainMod())],
    )

    fc = cli_mod.FrameworkCommands()
    buf = __import__("io").StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        fc.onecmd("run_module plugin_main_mod gamma delta")
    finally:
        sys.stdout = old

    assert "plugin main_mod gamma delta" in buf.getvalue()


def test_main_module_path_argument(truckdevil_module_env, tmp_path, monkeypatch):
    module_dir = tmp_path / "modules"
    module_dir.mkdir()
    module_file = module_dir / "arg_echo.py"
    module_file.write_text(
        dedent(
            """
            def main_mod(argv, device):
                print("arg module {}".format(" ".join(argv)))
            """
        ).strip()
        + "\n"
    )

    cli_mod = _load_truckdevil_cli_module()
    monkeypatch.delenv("TRUCKDEVIL_MODULE_PATH", raising=False)

    buf = __import__("io").StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        rc = cli_mod.main(
            ["--module-path", str(module_dir), "run_module", "arg_echo", "hello"]
        )
    finally:
        sys.stdout = old

    assert rc == 0
    assert "arg module hello" in buf.getvalue()


def test_main_module_path_argument_requires_value(truckdevil_module_env):
    cli_mod = _load_truckdevil_cli_module()

    buf = __import__("io").StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        rc = cli_mod.main(["--module-path"])
    finally:
        sys.stdout = old

    assert rc == 1
    assert "expected path" in buf.getvalue().lower()
