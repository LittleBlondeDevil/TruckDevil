"""Tests for Device using python-can virtual interface (no hardware)."""
import can
import pytest
from unittest.mock import Mock, call, patch

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


def test_virtual_device_send_retry_on_can_operation_error(virtual_device):
    """send() sleeps with backoff delay before retrying when can.CanOperationError occurs."""
    msg = can.Message(
        arbitration_id=0x18EA00FF,
        data=[1, 2, 3, 4],
        is_extended_id=True,
    )
    mock_parent = Mock()
    mock_sleep = mock_parent.sleep
    mock_send = mock_parent.send
    mock_send.side_effect = [can.CanOperationError("tx buffer full"), None]

    with patch("truckdevil.libs.device.time.sleep", mock_sleep), \
         patch.object(virtual_device.can_bus, "send", mock_send):
        virtual_device.send(msg)

    assert mock_send.call_count == 2
    mock_send.assert_called_with(msg)
    # Verify delay is applied before retrying: sleep(0.0) -> failed send -> backoff sleep(0.001) -> successful send
    assert mock_parent.mock_calls == [
        call.sleep(0.0),
        call.send(msg),
        call.sleep(0.001),
        call.send(msg),
    ]


def test_virtual_device_send_multiple_retries_exponential_backoff(virtual_device):
    """send() increases backoff delay on successive can.CanOperationError failures."""
    msg = can.Message(
        arbitration_id=0x18EA00FF,
        data=[1, 2, 3, 4],
        is_extended_id=True,
    )
    mock_parent = Mock()
    mock_sleep = mock_parent.sleep
    mock_send = mock_parent.send
    mock_send.side_effect = [
        can.CanOperationError("error 1"),
        can.CanOperationError("error 2"),
        None,
    ]

    with patch("truckdevil.libs.device.time.sleep", mock_sleep), \
         patch.object(virtual_device.can_bus, "send", mock_send):
        virtual_device.send(msg)

    assert mock_send.call_count == 3
    assert mock_parent.mock_calls == [
        call.sleep(0.0),
        call.send(msg),
        call.sleep(0.001),
        call.send(msg),
        call.sleep(0.01),
        call.send(msg),
    ]


def test_virtual_device_send_unexpected_exception_aborts(virtual_device):
    """send() aborts and does not retry when a non-CanOperationError exception occurs."""
    msg = can.Message(
        arbitration_id=0x18EA00FF,
        data=[1, 2, 3, 4],
        is_extended_id=True,
    )
    with patch("truckdevil.libs.device.time.sleep") as mock_sleep, \
         patch.object(virtual_device.can_bus, "send", side_effect=RuntimeError("unexpected")) as mock_send:
        virtual_device.send(msg)

        assert mock_send.call_count == 1
        assert mock_sleep.call_args_list == [call(0.0)]


def test_virtual_device_send_backoff_capped_at_max_backoff(virtual_device):
    """send() caps backoff sleep delay at max_backoff."""
    msg = can.Message(
        arbitration_id=0x18EA00FF,
        data=[1, 2, 3, 4],
        is_extended_id=True,
    )
    mock_parent = Mock()
    mock_sleep = mock_parent.sleep
    mock_send = mock_parent.send
    mock_send.side_effect = [
        can.CanOperationError("err 1"),
        can.CanOperationError("err 2"),
        can.CanOperationError("err 3"),
        can.CanOperationError("err 4"),
        None,
    ]

    with patch("truckdevil.libs.device.time.sleep", mock_sleep), \
         patch.object(virtual_device.can_bus, "send", mock_send):
        virtual_device.send(msg, max_backoff=0.05)

    assert mock_send.call_count == 5
    assert mock_parent.mock_calls == [
        call.sleep(0.0),
        call.send(msg),
        call.sleep(0.001),
        call.send(msg),
        call.sleep(0.01),
        call.send(msg),
        call.sleep(0.05),
        call.send(msg),
        call.sleep(0.05),
        call.send(msg),
    ]


def test_virtual_device_send_max_retries_exceeded_aborts(virtual_device):
    """send() aborts when consecutive can.CanOperationError failures exceed max_retries."""
    msg = can.Message(
        arbitration_id=0x18EA00FF,
        data=[1, 2, 3, 4],
        is_extended_id=True,
    )
    mock_parent = Mock()
    mock_sleep = mock_parent.sleep
    mock_send = mock_parent.send
    mock_send.side_effect = can.CanOperationError("persistent bus error")

    with patch("truckdevil.libs.device.time.sleep", mock_sleep), \
         patch.object(virtual_device.can_bus, "send", mock_send):
        virtual_device.send(msg, max_retries=2)

    assert mock_send.call_count == 3
    assert mock_parent.mock_calls == [
        call.sleep(0.0),
        call.send(msg),
        call.sleep(0.001),
        call.send(msg),
        call.sleep(0.01),
        call.send(msg),
    ]


