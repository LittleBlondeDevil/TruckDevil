"""Tests for ecu_discovery module with virtual device."""
import io
import sys
import threading
import uuid
from unittest.mock import patch

import pytest


@pytest.fixture
def shared_channel():
    return f"ecu-{uuid.uuid4().hex}"


def test_ecu_discovery_view_ecus_no_ecus(truckdevil_module_env, shared_channel):
    """view_ecus with no ECUs: assert 'no ecu information stored' (or equivalent)."""
    from libs.device import Device
    import modules.ecu_discovery as ecu_discovery

    device = Device("virtual", None, shared_channel, 250000)
    try:
        buf = __import__("io").StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            ecu_discovery.main_mod(["view_ecus", "back"], device)
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert "no ecu information stored" in out or "passive_scan" in out.lower()
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_ecu_discovery_passive_scan_no_crash(truckdevil_module_env, shared_channel):
    """passive_scan with virtual bus; patch time.sleep to avoid 10s wait; assert no crash."""
    from libs.device import Device
    import modules.ecu_discovery as ecu_discovery

    device = Device("virtual", None, shared_channel, 250000)
    try:
        with patch("modules.ecu_discovery.time.sleep"):
            buf = __import__("io").StringIO()
            old = sys.stdout
            try:
                sys.stdout = buf
                ecu_discovery.main_mod(["passive_scan", "back"], device)
            finally:
                sys.stdout = old
        assert "scanning" in buf.getvalue().lower() or "complete" in buf.getvalue().lower()
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_ecu_discovery_active_scan_inject_response(truckdevil_module_env, shared_channel):
    """active_scan: inject Address Claimed response on virtual bus; assert at least one ECU or flow completes."""
    import threading
    import time
    from libs.device import Device
    from j1939.j1939 import J1939Interface, J1939Message
    import modules.ecu_discovery as ecu_discovery

    dev_main = Device("virtual", None, shared_channel, 250000)
    dev_inject = Device("virtual", None, shared_channel, 250000)
    try:
        def inject_address_claimed():
            time.sleep(0.2)
            # Address Claimed PGN 0x18EExxxx, response has PDU format 0xEE
            msg = J1939Message(0x18EE00F9, "0000000000000100")  # src 0xF9
            iface = J1939Interface(dev_inject)
            iface.send_message(msg)

        t = threading.Thread(target=inject_address_claimed)
        t.start()
        with patch("modules.ecu_discovery.time.sleep"):
            buf = __import__("io").StringIO()
            old = sys.stdout
            try:
                sys.stdout = buf
                ecu_discovery.main_mod(["active_scan", "back"], dev_main)
            finally:
                sys.stdout = old
        t.join(timeout=2)
        out = buf.getvalue()
        assert "scanning" in out.lower() or "complete" in out.lower()
    finally:
        for d in (dev_main, dev_inject):
            if getattr(d, "can_bus", None) is not None:
                try:
                    d.can_bus.shutdown()
                except Exception:
                    pass


def test_ecu_discovery_save_load(truckdevil_module_env, shared_channel, tmp_path):
    """save ECU list to temp file, load; assert no crash."""
    from libs.device import Device
    from j1939.j1939 import J1939Interface, J1939Message
    import modules.ecu_discovery as ecu_discovery

    device = Device("virtual", None, shared_channel, 250000)
    f = tmp_path / "ecus.dill"
    try:
        # Add one ECU via active_scan with injected response (quick)
        def inject():
            import time
            time.sleep(0.15)
            iface = J1939Interface(Device("virtual", None, shared_channel, 250000))
            try:
                iface.send_message(J1939Message(0x18EE00F9, "0000000000000100"))
            finally:
                if iface.device.can_bus:
                    try:
                        iface.device.can_bus.shutdown()
                    except Exception:
                        pass

        t = threading.Thread(target=inject)
        t.start()
        with patch("modules.ecu_discovery.time.sleep"):
            ecu_discovery.main_mod(["active_scan", "save", str(f), "back"], device)
        t.join(timeout=2)
        ecu_discovery.main_mod(["load", str(f), "view_ecus", "back"], device)
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_ecu_discovery_find_boot_msg_smoke(truckdevil_module_env, shared_channel):
    """find_boot_msg: smoke test; mock input to 'q' to quit immediately; assert no crash."""
    from libs.device import Device
    import modules.ecu_discovery as ecu_discovery

    device = Device("virtual", None, shared_channel, 250000)
    try:
        with patch("builtins.input", side_effect=["q"]):
            buf = __import__("io").StringIO()
            old = sys.stdout
            try:
                sys.stdout = buf
                ecu_discovery.main_mod(["find_boot_msg", "11", "back"], device)
            finally:
                sys.stdout = old
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_ecu_discovery_request_pgn_smoke(truckdevil_module_env, shared_channel):
    """request_pgn: smoke test with address and PGN; no real responder; assert no crash."""
    from libs.device import Device
    import modules.ecu_discovery as ecu_discovery

    device = Device("virtual", None, shared_channel, 250000)
    try:
        with patch("modules.ecu_discovery.time.sleep"):
            buf = __import__("io").StringIO()
            old = sys.stdout
            try:
                sys.stdout = buf
                ecu_discovery.main_mod(["request_pgn", "11", "64965", "back"], device)
            finally:
                sys.stdout = old
        out = buf.getvalue()
        assert "requesting" in out.lower() or "did not" in out.lower() or "back" in out
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


# --- ECUDiscovery class unit tests ---


def test_input_to_int_decimal(truckdevil_module_env):
    from modules.ecu_discovery import input_to_int
    assert input_to_int("11") == 11
    assert input_to_int("0") == 0
    assert input_to_int("255") == 255


def test_input_to_int_hex(truckdevil_module_env):
    from modules.ecu_discovery import input_to_int
    assert input_to_int("0x0B") == 11
    assert input_to_int("0xFF") == 255
    assert input_to_int("0x00") == 0


def test_ecu_discovery_class_add_and_get(truckdevil_module_env):
    from modules.ecu_discovery import ECUDiscovery
    from libs.ecu import ECU

    ed = ECUDiscovery()
    assert ed.known_ecus == []
    assert ed.get_all_addresses() == []
    assert ed.get_ecu_by_address(11) is None

    ecu1 = ECU(11)
    result = ed.add_known_ecu(ecu1)
    assert result is ecu1
    assert ed.get_all_addresses() == [11]
    assert ed.get_ecu_by_address(11) is ecu1

    ecu2 = ECU(249)
    ed.add_known_ecu(ecu2)
    assert len(ed.known_ecus) == 2
    assert set(ed.get_all_addresses()) == {11, 249}


def test_ecu_discovery_class_add_duplicate(truckdevil_module_env):
    from modules.ecu_discovery import ECUDiscovery
    from libs.ecu import ECU

    ed = ECUDiscovery()
    ecu1 = ECU(11)
    ed.add_known_ecu(ecu1)
    ecu_dup = ECU(11)
    result = ed.add_known_ecu(ecu_dup)
    assert result is ecu1  # returns existing, not the new one
    assert len(ed.known_ecus) == 1


def test_ecu_discovery_find_proprietary_smoke(truckdevil_module_env, shared_channel):
    """find_proprietary: hits a bug in do_find_proprietary when no messages match --
    e is None and the code tries e.prop_messages. This documents the existing bug."""
    from libs.device import Device
    import modules.ecu_discovery as ecu_discovery

    device = Device("virtual", None, shared_channel, 250000)
    try:
        with patch("modules.ecu_discovery.time.sleep"):
            # Known bug: AttributeError when no proprietary messages found for unknown ECU
            with pytest.raises(AttributeError, match="prop_messages"):
                ecu_discovery.main_mod(["find_proprietary", "11", "back"], device)
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_ecu_discovery_find_uds_smoke(truckdevil_module_env, shared_channel):
    """find_uds: smoke test with patched sleep; no crash."""
    from libs.device import Device
    import modules.ecu_discovery as ecu_discovery

    device = Device("virtual", None, shared_channel, 250000)
    try:
        with patch("modules.ecu_discovery.time.sleep"):
            buf = io.StringIO()
            old = sys.stdout
            try:
                sys.stdout = buf
                ecu_discovery.main_mod(["find_uds", "11", "back"], device)
            finally:
                sys.stdout = old
        out = buf.getvalue()
        assert "Scanning" in out or "tester" in out.lower() or "did not respond" in out.lower()
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass


def test_ecu_discovery_missing_args(truckdevil_module_env, shared_channel):
    """Commands with missing arguments print help/error without crashing."""
    from libs.device import Device
    import modules.ecu_discovery as ecu_discovery

    device = Device("virtual", None, shared_channel, 250000)
    try:
        buf = io.StringIO()
        old = sys.stdout
        try:
            sys.stdout = buf
            ecu_discovery.main_mod([
                "find_boot_msg",  # no address
                "find_proprietary",  # no address
                "find_uds",  # no address
                "request_pgn",  # no address/pgn
                "back",
            ], device)
        finally:
            sys.stdout = old
        out = buf.getvalue()
        assert "expected" in out.lower()
    finally:
        if device.can_bus is not None:
            try:
                device.can_bus.shutdown()
            except Exception:
                pass
