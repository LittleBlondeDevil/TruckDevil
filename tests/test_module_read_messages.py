"""Tests for read_messages module with virtual device."""
import sys
import threading
import time
import uuid

import can
import pytest


@pytest.fixture
def shared_channel():
    return f"read-{uuid.uuid4().hex}"


def _inject_messages(channel, count, delay=0.05):
    """Inject count CAN messages on channel (run in thread)."""
    from libs.device import Device
    dev = Device("virtual", None, channel, 250000)
    try:
        for i in range(count):
            msg = can.Message(
                arbitration_id=0x18EA00FF,
                data=[i, 1, 2, 3, 4, 5, 6, 7],
                is_extended_id=True,
            )
            dev.send(msg)
            time.sleep(delay)
    finally:
        if getattr(dev, "can_bus", None) is not None:
            try:
                dev.can_bus.shutdown()
            except Exception:
                pass


def test_read_messages_set_num_messages_print_messages(truckdevil_module_env, shared_channel):
    """main_mod set num_messages 3 print_messages with 3 messages injected; no crash, output reflects messages."""
    from libs.device import Device
    import modules.read_messages as read_messages

    device = Device("virtual", None, shared_channel, 250000)
    try:
        # Start injector thread: 3 messages
        t = threading.Thread(target=_inject_messages, args=(shared_channel, 3))
        t.start()
        time.sleep(0.05)
        # Run module: set num_messages 3 then print_messages (capture stdout)
        import io
        old_stdout = sys.stdout
        buf = io.StringIO()
        try:
            sys.stdout = buf
            read_messages.main_mod(["set", "num_messages", "3", "print_messages", "back"], device)
        finally:
            sys.stdout = old_stdout
        t.join(timeout=2)
        out = buf.getvalue()
        assert "18EA00FF" in out or "18ea00ff" in out.lower()
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_read_messages_set_unset_settings(truckdevil_module_env, shared_channel):
    """set / unset / settings: drive via main_mod and assert no crash."""
    from libs.device import Device
    import modules.read_messages as read_messages

    device = Device("virtual", None, shared_channel, 250000)
    try:
        import io
        buf = io.StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            read_messages.main_mod(["set", "num_messages", "5", "settings", "unset", "num_messages", "settings", "back"], device)
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert "num_messages" in out
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_read_messages_save_load_roundtrip(truckdevil_module_env, shared_channel, tmp_path):
    """save settings to temp file, load; assert no crash."""
    from libs.device import Device
    import modules.read_messages as read_messages

    device = Device("virtual", None, shared_channel, 250000)
    f = tmp_path / "read_settings.dill"
    try:
        read_messages.main_mod(["set", "num_messages", "2", "save", str(f), "back"], device)
        read_messages.main_mod(["load", str(f), "settings", "back"], device)
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass
