"""
Pytest fixtures for TruckDevil test suite.
Uses python-can virtual interface so no hardware is required.
"""
import os
import sys
import uuid

import pytest

# Ensure repo root is on path so truckdevil package can be imported
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TRUCKDEVIL_DIR = os.path.join(_REPO_ROOT, "truckdevil")
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)


@pytest.fixture
def virtual_channel():
    """Unique channel name per test to avoid cross-test leakage."""
    return f"test-{uuid.uuid4().hex}"


@pytest.fixture
def virtual_device(virtual_channel):
    """Create a Device using python-can virtual interface. No hardware required."""
    from truckdevil.libs.device import Device

    device = Device(
        device_type="virtual",
        serial_port=None,
        channel=virtual_channel,
        can_baud=250000,
    )
    yield device
    if hasattr(device, "can_bus") and device.can_bus is not None:
        try:
            device.can_bus.shutdown()
        except Exception:
            pass


@pytest.fixture
def j1939_cwd():
    """
    Change CWD to truckdevil package dir so J1939Interface can find
    resources/json_files/. Restores original CWD after test.
    """
    old_cwd = os.getcwd()
    try:
        os.chdir(_TRUCKDEVIL_DIR)
        yield _TRUCKDEVIL_DIR
    finally:
        os.chdir(old_cwd)


@pytest.fixture
def virtual_device_shared_channel():
    """Virtual device with a fixed channel for tests that need two endpoints on same bus."""
    channel = f"shared-{uuid.uuid4().hex}"
    from truckdevil.libs.device import Device

    device = Device(
        device_type="virtual",
        serial_port=None,
        channel=channel,
        can_baud=250000,
    )
    yield device, channel
    if hasattr(device, "can_bus") and device.can_bus is not None:
        try:
            device.can_bus.shutdown()
        except Exception:
            pass


@pytest.fixture
def j1939_interface(virtual_device, j1939_cwd):
    """J1939Interface backed by a virtual device. Sets CWD so JSON resources load."""
    from truckdevil.j1939.j1939 import J1939Interface

    yield J1939Interface(virtual_device)


@pytest.fixture
def truckdevil_module_env(j1939_cwd):
    """
    CWD is truckdevil dir and truckdevil is at front of sys.path so that
    'import modules.read_messages' and 'from libs.device import Device' work
    (as when running python truckdevil.py from inside truckdevil/).
    """
    old_path = list(sys.path)
    try:
        if _TRUCKDEVIL_DIR not in sys.path:
            sys.path.insert(0, _TRUCKDEVIL_DIR)
        yield
    finally:
        sys.path[:] = old_path
