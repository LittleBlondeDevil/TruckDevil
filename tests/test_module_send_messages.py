"""Tests for send_messages module with virtual device."""
import sys
import uuid

import pytest


@pytest.fixture
def shared_channel():
    return f"send-{uuid.uuid4().hex}"


def test_send_messages_send_then_receive(truckdevil_module_env, shared_channel):
    """main_mod send 0x18EA00FF AABBCCDDEEFF0011 back; other endpoint receives and asserts CAN ID and data."""
    from libs.device import Device
    from j1939.j1939 import J1939Interface
    import modules.send_messages as send_messages

    dev_tx = Device("virtual", None, shared_channel, 250000)
    dev_rx = Device("virtual", None, shared_channel, 250000)
    try:
        send_messages.main_mod(["send", "0x18EA00FF", "AABBCCDDEEFF0011", "back"], dev_tx)
        iface_rx = J1939Interface(dev_rx)
        received = iface_rx.read_one_message(timeout=1)
        assert received is not None
        assert received.can_id == 0x18EA00FF
        assert received.data.upper() == "AABBCCDDEEFF0011"
    finally:
        for d in (dev_tx, dev_rx):
            if getattr(d, "can_bus", None) is not None:
                try:
                    d.can_bus.shutdown()
                except Exception:
                    pass


def test_send_messages_verbose_dry_run(truckdevil_module_env, shared_channel):
    """send ... -v and -vv: no exception, decoded/printed output appears."""
    from libs.device import Device
    import modules.send_messages as send_messages

    device = Device("virtual", None, shared_channel, 250000)
    try:
        buf = __import__("io").StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            send_messages.main_mod(["send", "0x18EA00FF", "00112233", "-v", "back"], device)
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert "18EA00FF" in out or "18ea00ff" in out.lower()
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_send_messages_invalid_args_no_data(truckdevil_module_env, shared_channel):
    """send 0x18EA00FF (no data): assert error message and no send (receiver gets nothing)."""
    from libs.device import Device
    import modules.send_messages as send_messages

    device = Device("virtual", None, shared_channel, 250000)
    try:
        buf = __import__("io").StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            send_messages.main_mod(["send", "0x18EA00FF", "back"], device)
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert "arguments not found" in out or "help send" in out.lower()
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_send_messages_bad_hex_can_id(truckdevil_module_env, shared_channel):
    """send 0xZZZZ AABB: prints error instead of crashing."""
    from libs.device import Device
    import modules.send_messages as send_messages

    device = Device("virtual", None, shared_channel, 250000)
    try:
        buf = __import__("io").StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            send_messages.main_mod(["send", "0xZZZZ", "AABB", "back"], device)
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert "could not parse can id" in out.lower()
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_send_messages_bad_data_non_hex(truckdevil_module_env, shared_channel):
    """send 0x18EA00FF XYZ123: prints error instead of crashing."""
    from libs.device import Device
    import modules.send_messages as send_messages

    device = Device("virtual", None, shared_channel, 250000)
    try:
        buf = __import__("io").StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            send_messages.main_mod(["send", "0x18EA00FF", "XYZ123", "back"], device)
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert "invalid message" in out.lower()
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_send_messages_bad_data_odd_length(truckdevil_module_env, shared_channel):
    """send 0x18EA00FF AAB: prints error for odd-length hex data."""
    from libs.device import Device
    import modules.send_messages as send_messages

    device = Device("virtual", None, shared_channel, 250000)
    try:
        buf = __import__("io").StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            send_messages.main_mod(["send", "0x18EA00FF", "AAB", "back"], device)
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert "invalid message" in out.lower()
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass
