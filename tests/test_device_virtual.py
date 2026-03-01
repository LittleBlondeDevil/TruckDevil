"""Tests for Device using python-can virtual interface (no hardware)."""
import can
import pytest

from truckdevil.libs.device import Device


def test_virtual_device_creation():
    """Create Device with virtual interface; m2_used is False, can_bus is set."""
    device = Device("virtual", None, "test", 250000)
    try:
        assert device.m2_used is False
        assert device.can_bus is not None
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_virtual_device_send_receive(virtual_channel):
    """Send on one virtual bus, receive on another on same channel."""
    dev_tx = Device("virtual", None, virtual_channel, 250000)
    dev_rx = Device("virtual", None, virtual_channel, 250000)
    try:
        msg = can.Message(
            arbitration_id=0x18EA00FF,
            data=[0, 1, 2, 3, 4, 5, 6, 7],
            is_extended_id=True,
        )
        dev_tx.send(msg)
        received = dev_rx.read(timeout=0.5)
        assert received is not None
        assert received.arbitration_id == 0x18EA00FF
        assert list(received.data) == [0, 1, 2, 3, 4, 5, 6, 7]
    finally:
        for d in (dev_tx, dev_rx):
            if getattr(d, "can_bus", None) is not None:
                try:
                    d.can_bus.shutdown()
                except Exception:
                    pass


def test_virtual_device_read_timeout_returns_none(virtual_device):
    """read() with no message and short timeout returns None."""
    result = virtual_device.read(timeout=0.01)
    assert result is None


def test_virtual_device_str():
    """__str__ includes device type and channel; no serial port for virtual."""
    device = Device("virtual", None, "vcan99", 250000)
    try:
        s = str(device)
        assert "virtual" in s
        assert "vcan99" in s
        assert "Serial Port" not in s or "None" in s
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_m2_requires_serial_port():
    """Device('m2', None, ...) raises ValueError (serial port required)."""
    with pytest.raises(ValueError, match="serial port"):
        Device("m2", None, "can0", 250000)
