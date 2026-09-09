import threading
import time

import can

import truckdevil.modules.ecu_discovery as ecu_discovery

def simulate_ecu(channel):
    bus = can.interface.Bus(channel, interface='virtual')
    try:
        while True:
            msg = bus.recv(1)
            if msg:
                # Check if it is a UDS request (PGN DAxx)
                if (msg.arbitration_id >> 16) & 0xFF == 0xDA:
                    data = msg.data
                    # Standard Tester Present or DSC
                    if len(data) >= 2 and (data[1] == 0x3E or data[1] == 0x10):
                        src = (msg.arbitration_id >> 8) & 0xFF
                        dst = msg.arbitration_id & 0xFF
                        resp_id = 0x18DA0000 | (dst << 8) | src
                        # Positive response is SID + 0x40
                        resp_msg = can.Message(
                            arbitration_id=resp_id, data=[0x02, data[1] + 0x40, 0x00], is_extended_id=True
                        )
                        bus.send(resp_msg)
    except Exception:
        pass
    finally:
        bus.shutdown()

def test_find_uds_success(virtual_device_shared_channel, capsys):
    device, channel = virtual_device_shared_channel

    # Start ECU simulation in background
    ecu_thread = threading.Thread(target=simulate_ecu, args=(channel,), daemon=True)
    ecu_thread.start()

    time.sleep(1)  # Wait for simulation to start

    # Use DiscoveryCommands to run find_uds
    cmd = ecu_discovery.DiscoveryCommands(device)

    # We'll use dst=0x11
    # Note: DiscoveryCommands init already created J1939Interface(device) as self.devil

    cmd.do_find_uds("dst=0x11")
    out = capsys.readouterr().out
    # Check if the simulated ECU was discovered
    assert "Discovered" in out
    assert "Target" in out
    assert "Fmt" in out
    # Suggested Send/Recv IDs
    # 18DA11F1 (from F1 to 11)
    assert "S: 0x18DA11F1" in out
    # 18DAF111 (from 11 to F1)
    assert "R: 0x18DAF111" in out


def simulate_ecu_nr(channel):
    bus = can.interface.Bus(channel, interface='virtual')
    try:
        while True:
            msg = bus.recv(1)
            if msg:
                # Check if it is a UDS request (PGN DAxx)
                if (msg.arbitration_id >> 16) & 0xFF == 0xDA:
                    data = msg.data
                    # Standard Tester Present or DSC
                    if len(data) >= 2 and (data[1] == 0x3E or data[1] == 0x10):
                        src = (msg.arbitration_id >> 8) & 0xFF
                        dst = msg.arbitration_id & 0xFF
                        resp_id = 0x18DA0000 | (dst << 8) | src
                        # Negative response is 7F SID NRC
                        # PCI 03
                        resp_msg = can.Message(
                            arbitration_id=resp_id, data=[0x03, 0x7F, data[1], 0x11], is_extended_id=True
                        )
                        bus.send(resp_msg)
    except Exception:
        pass
    finally:
        bus.shutdown()

def test_find_uds_nr_success(virtual_device_shared_channel, capsys):
    device, channel = virtual_device_shared_channel

    # Start ECU simulation in background
    ecu_thread = threading.Thread(target=simulate_ecu_nr, args=(channel,), daemon=True)
    ecu_thread.start()

    time.sleep(1)  # Wait for simulation to start

    cmd = ecu_discovery.DiscoveryCommands(device)
    cmd.do_find_uds("dst=0x12")  # Use different address
    out = capsys.readouterr().out
    assert "Discovered" in out
    assert "Target" in out
    # 18DA12F1 (from F1 to 12)
    assert "S: 0x18DA12F1" in out
    # 18DAF112 (from 12 to F1)
    assert "R: 0x18DAF112" in out
