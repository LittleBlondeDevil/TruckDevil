"""Tests for framework CLI (truckdevil.py) with virtual device."""
import importlib.util
import os
import re
import sys
import uuid

import pytest

# Load FrameworkCommands from truckdevil/truckdevil.py (needs truckdevil dir on path for libs/modules)
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TRUCKDEVIL_DIR = os.path.join(_REPO_ROOT, "truckdevil")


def _load_framework_commands():
    """Load FrameworkCommands from truckdevil.py with truckdevil dir on path."""
    spec = importlib.util.spec_from_file_location(
        "truckdevil_cli",
        os.path.join(_TRUCKDEVIL_DIR, "truckdevil.py"),
        submodule_search_locations=[_TRUCKDEVIL_DIR],
    )
    mod = importlib.util.module_from_spec(spec)
    old_path = list(sys.path)
    try:
        sys.path.insert(0, _TRUCKDEVIL_DIR)
        spec.loader.exec_module(mod)
        return mod.FrameworkCommands
    finally:
        sys.path[:] = old_path


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
    assert re.match(r"^\d+\.\d+\.\d+$", version), f"unexpected version format: {version}"


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
        capture_output=True, text=True, timeout=10,
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
