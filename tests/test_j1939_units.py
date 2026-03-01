"""Unit tests for J1939 helpers and J1939Message (no device)."""
import pytest

from truckdevil.j1939.j1939 import J1939Message, j1939_fields_to_can_id


def test_j1939_fields_to_can_id():
    """j1939_fields_to_can_id builds expected 29-bit CAN ID."""
    # priority=6, reserved=0, data_page=0, pdu_format=0xEA, pdu_specific=0, src_addr=0xFF -> 0x18EA00FF
    can_id = j1939_fields_to_can_id(6, 0, 0, 0xEA, 0, 0xFF)
    assert can_id == 0x18EA00FF
    assert can_id <= 0x1FFFFFFF


@pytest.mark.parametrize(
    "priority,reserved,data_page,pdu_format,pdu_specific,src_addr,expected",
    [
        (0, 0, 0, 0, 0, 0, 0),
        (7, 1, 1, 0xFF, 0xFF, 0xFF, 0x1FFFFFFF),
        (3, 0, 0, 0xEC, 0x00, 0x0B, 0x0CEC000B),
    ],
)
def test_j1939_fields_to_can_id_param(priority, reserved, data_page, pdu_format, pdu_specific, src_addr, expected):
    """Parametrized 29-bit CAN ID from fields."""
    assert j1939_fields_to_can_id(priority, reserved, data_page, pdu_format, pdu_specific, src_addr) == expected


def test_j1939_message_creation_and_properties():
    """J1939Message(can_id, data) exposes priority, pdu_format, pdu_specific, src_addr, pgn, data."""
    msg = J1939Message(0x18EA00FF, "AABBCCDDEEFF0011")
    assert msg.priority == 6
    assert msg.pdu_format == 0xEA
    assert msg.pdu_specific == 0x00
    assert msg.src_addr == 0xFF
    assert msg.pgn == 0xEA00
    assert msg.data.upper() == "AABBCCDDEEFF0011"
    assert msg.can_id == 0x18EA00FF


def test_j1939_message_dst_addr_destination_specific():
    """dst_addr is pdu_specific when PDU format < 0xF0."""
    # can_id with pdu_format=0xEC, pdu_specific=0x0B (destination address)
    msg = J1939Message(0x00EC0B00, "00")
    assert msg.pdu_format < 0xF0
    assert msg.dst_addr == 0x0B


def test_j1939_message_dst_addr_broadcast():
    """dst_addr is 0xFF when PDU format >= 0xF0 (broadcast)."""
    # can_id with pdu_format=0xF0 (broadcast range)
    msg = J1939Message(0x18F000FF, "00")
    assert msg.pdu_format >= 0xF0
    assert msg.dst_addr == 0xFF


def test_j1939_message_invalid_can_id_raises():
    """J1939Message with can_id out of range raises ValueError."""
    with pytest.raises(ValueError, match="invalid CAN ID"):
        J1939Message(0x20000000, "00")
    with pytest.raises(ValueError, match="invalid CAN ID"):
        J1939Message(-1, "00")


def test_j1939_message_invalid_data_raises():
    """J1939Message with non-hex data raises ValueError."""
    with pytest.raises(ValueError, match="hexadecimal"):
        J1939Message(0x18EA00FF, "GG")
    with pytest.raises(ValueError, match="even number"):
        J1939Message(0x18EA00FF, "A")


# --- J1939Message property setter tests ---


def test_j1939_message_set_priority():
    msg = J1939Message(0x18EA00FF, "00")
    assert msg.priority == 6
    msg.priority = 3
    assert msg.priority == 3
    # Other fields preserved
    assert msg.pdu_format == 0xEA
    assert msg.src_addr == 0xFF


def test_j1939_message_set_priority_invalid():
    msg = J1939Message(0x18EA00FF, "00")
    with pytest.raises(ValueError):
        msg.priority = 8
    with pytest.raises(ValueError):
        msg.priority = -1


def test_j1939_message_set_reserved_bit():
    msg = J1939Message(0x18EA00FF, "00")
    assert msg.reserved_bit == 0
    msg.reserved_bit = 1
    assert msg.reserved_bit == 1
    with pytest.raises(ValueError):
        msg.reserved_bit = 2


def test_j1939_message_set_data_page_bit():
    msg = J1939Message(0x18EA00FF, "00")
    assert msg.data_page_bit == 0
    msg.data_page_bit = 1
    assert msg.data_page_bit == 1
    with pytest.raises(ValueError):
        msg.data_page_bit = 2


def test_j1939_message_set_pdu_format():
    msg = J1939Message(0x18EA00FF, "00")
    msg.pdu_format = 0xF0
    assert msg.pdu_format == 0xF0
    assert msg.priority == 6
    assert msg.src_addr == 0xFF
    with pytest.raises(ValueError):
        msg.pdu_format = 256
    with pytest.raises(ValueError):
        msg.pdu_format = -1


def test_j1939_message_set_pdu_specific():
    msg = J1939Message(0x18EA00FF, "00")
    msg.pdu_specific = 0x0B
    assert msg.pdu_specific == 0x0B
    with pytest.raises(ValueError):
        msg.pdu_specific = 256


def test_j1939_message_set_src_addr():
    msg = J1939Message(0x18EA00FF, "00")
    msg.src_addr = 0x0B
    assert msg.src_addr == 0x0B
    assert msg.priority == 6
    with pytest.raises(ValueError):
        msg.src_addr = 256
    with pytest.raises(ValueError):
        msg.src_addr = -1


def test_j1939_message_set_can_id():
    msg = J1939Message(0x18EA00FF, "00")
    msg.can_id = 0x0CEC000B
    assert msg.can_id == 0x0CEC000B
    assert msg.priority == 3
    assert msg.pdu_format == 0xEC
    with pytest.raises(ValueError):
        msg.can_id = 0x20000000
    with pytest.raises(ValueError):
        msg.can_id = -1


def test_j1939_message_set_data():
    msg = J1939Message(0x18EA00FF, "00")
    msg.data = "AABBCCDD"
    assert msg.data == "AABBCCDD"
    with pytest.raises(ValueError, match="hexadecimal"):
        msg.data = "ZZZZ"
    with pytest.raises(ValueError, match="even number"):
        msg.data = "AAB"


def test_j1939_message_set_timestamp():
    msg = J1939Message(0x18EA00FF, "00")
    assert msg.timestamp == 0
    msg.timestamp = 100.5
    assert msg.timestamp == 100.5
    with pytest.raises(ValueError):
        msg.timestamp = -1


def test_j1939_message_set_total_bytes():
    msg = J1939Message(0x18EA00FF, "AABBCCDD")
    assert msg.total_bytes == 4
    msg.total_bytes = 100
    assert msg.total_bytes == 100


def test_j1939_message_pgn_destination_specific_vs_broadcast():
    """PGN calculation differs for pdu_format < 0xF0 vs >= 0xF0."""
    # Destination-specific: PGN masks out pdu_specific
    msg = J1939Message(0x00EC0B00, "00")
    assert msg.pgn == 0xEC00  # pdu_specific not included

    # Broadcast: PGN includes pdu_specific as group extension
    msg2 = J1939Message(0x18FEF000, "00")
    assert msg2.pgn == 0xFEF0


def test_j1939_message_str():
    msg = J1939Message(0x18EA00FF, "AABBCCDD")
    msg.timestamp = 1.0
    s = str(msg)
    assert "18EA00FF" in s
    assert "AABBCCDD" in s
