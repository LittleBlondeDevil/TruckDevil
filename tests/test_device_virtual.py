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


def test_m2_tcp_requires_port():
    """Device('m2', None, ..., tcp_ip='127.0.0.1') raises ValueError if port missing."""
    with pytest.raises(ValueError, match="port must be specified"):
        Device("m2", None, "can0", 250000, tcp_ip="127.0.0.1")


def test_m2_tcp_connection_and_read_write(monkeypatch):
    """Test M2 device communication over TCP with a mock socket."""
    import socket

    sent_data = []

    class MockSocket:
        def __init__(self, *args, **kwargs):
            self.timeout = None

        def setsockopt(self, *args, **kwargs):
            pass

        def connect(self, addr):
            pass

        def settimeout(self, timeout):
            self.timeout = timeout

        def sendall(self, data):
            sent_data.append(data)

        def recv(self, n):
            return b""

    monkeypatch.setattr(socket, "socket", MockSocket)

    dev = Device("m2", port=1234, channel="can0", can_baud=250000, tcp_ip="192.168.1.10")
    assert dev.m2_used is True
    assert "TCP IP: 192.168.1.10" in str(dev)
    assert "Port: 1234" in str(dev)
    assert b"#0250000can0" in sent_data

    msg = can.Message(arbitration_id=0x18EA00FF, data=[1, 2, 3], is_extended_id=True)
    dev.send(msg)
    assert any(b"$18ea00ff03010203*" in s for s in sent_data)

    dev.flush_m2()
    assert dev._acknowledged_flush is False


def test_m2_tcp_port_alias_and_serial_port_kwarg(monkeypatch):
    """Device supports both port= and serial_port= kwargs for TCP."""
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
    dev1 = Device("m2", serial_port=5555, channel="can0", can_baud=250000, tcp_ip="10.0.0.1")
    assert dev1._port == 5555
    assert "Port: 5555" in str(dev1)

    dev2 = Device("m2", port=6666, channel="can1", can_baud=500000, tcp_ip="10.0.0.2")
    assert dev2._port == 6666
    assert dev2._channel == "can1"


def test_m2_tcp_read_message_and_timeout(monkeypatch):
    """Test reading formatted M2 frames and timeouts over TCP."""
    import socket

    data_stream = bytearray(b"$18EA00FF04AABBCCDD*")
    eof_sent = False

    class MockSocket:
        def __init__(self, *args, **kwargs):
            self.timeout = None

        def setsockopt(self, *args, **kwargs):
            pass

        def connect(self, addr):
            pass

        def settimeout(self, timeout):
            self.timeout = timeout

        def sendall(self, data):
            pass

        def recv(self, n):
            nonlocal eof_sent
            if data_stream:
                chunk = data_stream[:n]
                del data_stream[:n]
                return bytes(chunk)
            if not eof_sent:
                eof_sent = True
                return b""
            raise socket.timeout("timed out")

    monkeypatch.setattr(socket, "socket", MockSocket)
    dev = Device("m2", port=1234, channel="can0", can_baud=250000, tcp_ip="192.168.1.10")

    # Read message that was queued
    msg = dev.read(timeout=0.1)
    assert msg is not None
    assert msg.arbitration_id == 0x18EA00FF
    assert msg.dlc == 4
    assert list(msg.data) == [0xAA, 0xBB, 0xCC, 0xDD]

    # Next recv returns empty byte b"", indicating EOF / disconnect -> returns None
    assert dev.read(timeout=0.1) is None

    # Next recv raises socket.timeout -> returns None (does not loop forever)
    assert dev.read(timeout=0.1) is None


def test_m2_tcp_flush_drains_socket(monkeypatch):
    """flush_m2 drains any pending bytes from the TCP socket."""
    import socket

    drained = []

    class MockSocket:
        def __init__(self, *args, **kwargs):
            self._timeout = 0.5
            self._data = [b"stale_data_1", b"stale_data_2"]

        def setsockopt(self, *args, **kwargs):
            pass

        def connect(self, addr):
            pass

        def gettimeout(self):
            return self._timeout

        def settimeout(self, timeout):
            self._timeout = timeout

        def sendall(self, data):
            pass

        def recv(self, n):
            if self._data:
                chunk = self._data.pop(0)
                drained.append(chunk)
                return chunk
            raise socket.timeout("empty")

    monkeypatch.setattr(socket, "socket", MockSocket)
    dev = Device("m2", port=1234, channel="can0", can_baud=250000, tcp_ip="192.168.1.10")
    dev.flush_m2()
    assert drained == [b"stale_data_1", b"stale_data_2"]
    assert dev._acknowledged_flush is False
