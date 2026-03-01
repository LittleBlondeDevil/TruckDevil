"""Unit tests for ECU class (no device)."""
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "truckdevil"))

from truckdevil.libs.ecu import ECU
from truckdevil.j1939.j1939 import J1939Message


def test_ecu_creation():
    ecu = ECU(0x0B)
    assert ecu.address == 0x0B
    assert ecu.name is None
    assert ecu.address_claimed_response is None
    assert ecu.prop_messages == []


def test_ecu_str_no_name():
    ecu = ECU(11)
    s = str(ecu)
    assert "11" in s
    assert "unknown" in s


def test_ecu_address_claimed_response_valid():
    ecu = ECU(0xF9)
    # PDU format 0xEE, src_addr 0xF9, 8 bytes (16 hex chars)
    msg = J1939Message(0x18EEFFF9, "0000000000000100")
    ecu.address_claimed_response = msg
    assert ecu.address_claimed_response is msg
    assert ecu.name == "0000000000000100"


def test_ecu_address_claimed_response_wrong_pdu_format():
    ecu = ECU(0xF9)
    msg = J1939Message(0x18EA00F9, "0000000000000100")  # PDU format 0xEA, not 0xEE
    with pytest.raises(ValueError, match="PDU Format 0xEE"):
        ecu.address_claimed_response = msg


def test_ecu_address_claimed_response_wrong_src_addr():
    ecu = ECU(0x0B)
    msg = J1939Message(0x18EEFFF9, "0000000000000100")  # src 0xF9 != 0x0B
    with pytest.raises(ValueError, match="does not match"):
        ecu.address_claimed_response = msg


def test_ecu_address_claimed_response_wrong_data_length():
    ecu = ECU(0xF9)
    msg = J1939Message(0x18EEFFF9, "00000000")  # 4 bytes, need 8
    with pytest.raises(ValueError, match="8 bytes"):
        ecu.address_claimed_response = msg


def test_ecu_str_with_name():
    ecu = ECU(0xF9)
    msg = J1939Message(0x18EEFFF9, "AABBCCDD11223344")
    ecu.address_claimed_response = msg
    s = str(ecu)
    assert "AABBCCDD11223344" in s
    assert "249" in s  # 0xF9 = 249


def test_ecu_add_prop_message_unique():
    ecu = ECU(0x0B)
    msg1 = J1939Message(0x18EF000B, "AABBCCDD")
    msg2 = J1939Message(0x18EF000B, "11223344")  # same can_id, different data
    ecu.add_prop_message(msg1)
    ecu.add_prop_message(msg2)
    assert len(ecu.prop_messages) == 2


def test_ecu_add_prop_message_duplicate_ignored():
    ecu = ECU(0x0B)
    msg1 = J1939Message(0x18EF000B, "AABBCCDD")
    msg2 = J1939Message(0x18EF000B, "AABBCCDD")  # identical
    ecu.add_prop_message(msg1)
    ecu.add_prop_message(msg2)
    assert len(ecu.prop_messages) == 1
