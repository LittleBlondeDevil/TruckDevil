"""Tests for tcp/truckdevil-tcp bridge utility functions and arguments."""

import os
import sys
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader

import can

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TCP_SCRIPT = os.path.join(_REPO_ROOT, "tcp", "truckdevil-tcp")


def _load_tcp_module():
    loader = SourceFileLoader("truckdevil_tcp", _TCP_SCRIPT)
    spec = spec_from_loader("truckdevil_tcp", loader)
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_tcp_encode_extended_frame():
    """encode() formats extended CAN ID as 8 hex digits, 2-digit DLC, and uppercase data."""
    tcp_mod = _load_tcp_module()
    msg = can.Message(
        arbitration_id=0x18EA00FF,
        data=[0x01, 0x02, 0x03, 0x04],
        is_extended_id=True,
    )
    encoded = tcp_mod.encode(msg)
    assert encoded == "$18EA00FF0401020304*"


def test_tcp_encode_standard_frame():
    """encode() formats standard CAN ID with 8 hex digits to match M2 wire expectations."""
    tcp_mod = _load_tcp_module()
    msg = can.Message(
        arbitration_id=0x123,
        data=[0xAA, 0xBB],
        is_extended_id=False,
    )
    encoded = tcp_mod.encode(msg)
    assert encoded == "$0000012302AABB*"


def test_tcp_decode_extended_frame():
    """decode() parses >=10 char M2 string into extended python-can Message."""
    tcp_mod = _load_tcp_module()
    msg = tcp_mod.decode("18EA00FF0401020304")
    assert msg is not None
    assert msg.is_extended_id is True
    assert msg.arbitration_id == 0x18EA00FF
    assert msg.dlc == 4
    assert list(msg.data) == [1, 2, 3, 4]


def test_tcp_decode_standard_frame():
    """decode() parses <10 char M2 string into standard python-can Message."""
    tcp_mod = _load_tcp_module()
    msg = tcp_mod.decode("12302AABB")
    assert msg is not None
    assert msg.is_extended_id is False
    assert msg.arbitration_id == 0x123
    assert msg.dlc == 2
    assert list(msg.data) == [0xAA, 0xBB]


def test_tcp_decode_invalid_frames():
    """decode() returns None on malformed inputs."""
    tcp_mod = _load_tcp_module()
    # Too short (< 5 chars)
    assert tcp_mod.decode("12") is None
    # Invalid hex ID
    assert tcp_mod.decode("ZZZ02AABB") is None
    # Standard ID > 0x7FF
    assert tcp_mod.decode("80002AABB") is None
    # Extended ID > 0x1FFFFFFF (29-bit CAN max)
    assert tcp_mod.decode("2000000002AABB") is None
    assert tcp_mod.decode("FFFFFFFF02AABB") is None
    # Invalid DLC
    assert tcp_mod.decode("12309010203040506070809") is None
    # Data length mismatch
    assert tcp_mod.decode("12302AA") is None
    # Invalid hex data
    assert tcp_mod.decode("12302ZZ") is None


def test_tcp_iface_whitelist_pattern():
    """IFACE_PATTERN allows can0/can1/vcan0 but disallows dangerous interfaces."""
    tcp_mod = _load_tcp_module()
    assert tcp_mod.IFACE_PATTERN.match("can0")
    assert tcp_mod.IFACE_PATTERN.match("can1")
    assert tcp_mod.IFACE_PATTERN.match("vcan0")
    assert tcp_mod.IFACE_PATTERN.match("vcan99")
    assert not tcp_mod.IFACE_PATTERN.match("eth0")
    assert not tcp_mod.IFACE_PATTERN.match("lo")
    assert not tcp_mod.IFACE_PATTERN.match("wlan0")
    assert not tcp_mod.IFACE_PATTERN.match(";rm -rf /")


def test_tcp_parse_args(monkeypatch):
    """parse_args() correctly parses IP, port, and verbosity flags."""
    tcp_mod = _load_tcp_module()
    monkeypatch.setattr(sys, "argv", ["truckdevil-tcp", "127.0.0.1", "1234", "-v"])
    args = tcp_mod.parse_args()
    assert args.bind_ip == "127.0.0.1"
    assert args.tcp_port == 1234
    assert args.verbose == 1


def test_tcp_can_setup(monkeypatch):
    """can_setup runs ip link commands."""
    tcp_mod = _load_tcp_module()
    commands = []

    def mock_call(cmd):
        commands.append(cmd)
        return 0

    monkeypatch.setattr(tcp_mod.subprocess, "call", mock_call)
    assert tcp_mod.can_setup("vcan0", 500000) is True
    assert len(commands) == 2
    assert commands[0] == ["ip", "link", "set", "vcan0", "down"]
    assert commands[1] == ["ip", "link", "set", "vcan0", "up", "type", "can", "bitrate", "500000"]
