"""Tests for j1939_fuzzer module with virtual device."""
import sys
import threading
import time
import uuid
from unittest.mock import patch

import pytest


@pytest.fixture
def shared_channel():
    return f"fuzz-{uuid.uuid4().hex}"


def _inject_fuzzer_messages(channel, count=5, delay=0.03):
    """Inject CAN messages on channel for baseline (run in thread)."""
    from libs.device import Device
    from j1939.j1939 import J1939Interface, J1939Message
    dev = Device("virtual", None, channel, 250000)
    try:
        iface = J1939Interface(dev)
        for i in range(count):
            iface.send_message(J1939Message(0x18EA00FF, "0011223344556677"))
            time.sleep(delay)
    finally:
        if getattr(dev, "can_bus", None) is not None:
            try:
                dev.can_bus.shutdown()
            except Exception:
                pass


def test_fuzzer_record_baseline(truckdevil_module_env, shared_channel):
    """record_baseline with virtual bus; inject messages; patch time.sleep; assert baseline or show_baseline runs."""
    from libs.device import Device
    import modules.j1939_fuzzer as j1939_fuzzer

    device = Device("virtual", None, shared_channel, 250000)
    try:
        t = threading.Thread(target=_inject_fuzzer_messages, args=(shared_channel, 5))
        t.start()
        time.sleep(0.05)
        with patch("modules.j1939_fuzzer.time.sleep"):
            buf = __import__("io").StringIO()
            old = sys.stdout
            try:
                sys.stdout = buf
                # baseline_time must be >= 10 per setting constraint
                j1939_fuzzer.main_mod(
                    ["set", "baseline_time", "10", "record_baseline", "show_baseline", "back"],
                    device,
                )
            finally:
                sys.stdout = old
        t.join(timeout=2)
        out = buf.getvalue()
        assert "Baselining" in out or "baseline" in out.lower()
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_fuzzer_generate_test_cases_mode1(truckdevil_module_env, shared_channel):
    """generate_test_cases with mode 1 (generational, no baseline required); assert test_cases populated or no crash."""
    from libs.device import Device
    import modules.j1939_fuzzer as j1939_fuzzer

    device = Device("virtual", None, shared_channel, 250000)
    try:
        buf = __import__("io").StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            j1939_fuzzer.main_mod(
                ["set", "mode", "1", "set", "num_messages", "3", "generate_test_cases", "back"],
                device,
            )
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert "Creating" in out or "messages" in out.lower() or "test" in out.lower()
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_fuzzer_start_fuzzer_small_run(truckdevil_module_env, shared_channel):
    """record_baseline, generate_test_cases, start_fuzzer with num_messages=2, message_frequency=0.01; patch sleep."""
    from libs.device import Device
    import modules.j1939_fuzzer as j1939_fuzzer

    device = Device("virtual", None, shared_channel, 250000)
    try:
        # First get a baseline with messages
        t = threading.Thread(target=_inject_fuzzer_messages, args=(shared_channel, 3))
        t.start()
        time.sleep(0.05)
        with patch("modules.j1939_fuzzer.time.sleep"):
            j1939_fuzzer.main_mod(
                [
                    "set", "baseline_time", "10",
                    "record_baseline",
                    "set", "num_messages", "2",
                    "set", "message_frequency", "0.01",
                    "generate_test_cases",
                    "start_fuzzer",
                    "back",
                ],
                device,
            )
        t.join(timeout=2)
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_fuzzer_settings_set(truckdevil_module_env, shared_channel):
    """set num_messages 5, message_frequency 0.01; run record_baseline + generate; confirm settings applied."""
    from libs.device import Device
    import modules.j1939_fuzzer as j1939_fuzzer

    device = Device("virtual", None, shared_channel, 250000)
    try:
        t = threading.Thread(target=_inject_fuzzer_messages, args=(shared_channel, 2))
        t.start()
        time.sleep(0.05)
        with patch("modules.j1939_fuzzer.time.sleep"):
            buf = __import__("io").StringIO()
            old = sys.stdout
            try:
                sys.stdout = buf
                j1939_fuzzer.main_mod(
                    [
                        "set", "num_messages", "5",
                        "set", "message_frequency", "0.01",
                        "set", "baseline_time", "10",
                        "record_baseline",
                        "generate_test_cases",
                        "settings",
                        "back",
                    ],
                    device,
                )
            finally:
                sys.stdout = old
            out = buf.getvalue()
            assert "5" in out and "0.01" in out
        t.join(timeout=2)
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_fuzzer_save_load_smoke(truckdevil_module_env, shared_channel, tmp_path):
    """Save fuzz_settings to temp file, load; smoke test."""
    from libs.device import Device
    import modules.j1939_fuzzer as j1939_fuzzer

    device = Device("virtual", None, shared_channel, 250000)
    f = tmp_path / "fuzz_settings.dill"
    try:
        buf = __import__("io").StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            j1939_fuzzer.main_mod(
                ["set", "num_messages", "2", "save", "fuzz_settings", str(f), "back"],
                device,
            )
            j1939_fuzzer.main_mod(["load", "fuzz_settings", str(f), "settings", "back"], device)
        finally:
            sys.stdout = old
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_fuzzer_target_cli(truckdevil_module_env, shared_channel):
    """do_target: add, list, modify, remove, clear via CLI commands."""
    from libs.device import Device
    import modules.j1939_fuzzer as j1939_fuzzer

    device = Device("virtual", None, shared_channel, 250000)
    try:
        buf = __import__("io").StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            j1939_fuzzer.main_mod([
                "target", "add", "11", "60928", "0xAABB",
                "target", "add", "22",
                "target", "list",
                "target", "modify", "11", "100", "CCDD",
                "target", "remove", "22",
                "target", "list",
                "target", "clear",
                "target", "list",
                "back",
            ], device)
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert "11" in out
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass
