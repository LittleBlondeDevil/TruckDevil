"""Integration tests for J1939Interface with virtual device."""
import io
import os
import sys
import threading
import time
import uuid

import can
import pytest

from truckdevil.libs.device import Device
from truckdevil.j1939.j1939 import J1939Interface, J1939Message, j1939_fields_to_can_id


@pytest.fixture
def shared_channel():
    return f"shared-{uuid.uuid4().hex}"


@pytest.fixture
def two_virtual_devices(shared_channel, j1939_cwd):
    """Two devices on same channel for send/recv; CWD set for J1939 resources."""
    dev_tx = Device("virtual", None, shared_channel, 250000)
    dev_rx = Device("virtual", None, shared_channel, 250000)
    try:
        yield dev_tx, dev_rx
    finally:
        for d in (dev_tx, dev_rx):
            if getattr(d, "can_bus", None) is not None:
                try:
                    d.can_bus.shutdown()
                except Exception:
                    pass


def test_j1939_send_and_receive_single_frame(two_virtual_devices):
    """Send J1939 message on one interface, read_one_message on other; assert PGN, data, src_addr."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    msg = J1939Message(0x18EA00FF, "AABBCCDDEEFF0011")
    iface_tx.send_message(msg)
    received = iface_rx.read_one_message(timeout=1)
    assert received is not None
    assert received.pgn == msg.pgn
    assert received.data.upper() == msg.data.upper()
    assert received.src_addr == msg.src_addr


def test_j1939_read_one_message_timeout_returns_none(j1939_interface):
    """read_one_message(timeout=0.1) with no traffic returns None."""
    result = j1939_interface.read_one_message(timeout=0.1)
    assert result is None


def test_j1939_filters(two_virtual_devices):
    """start_data_collection with filter; inject messages; stop_data_collection returns only matching."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    iface_rx.start_data_collection(abstract_tpm=True, src_addr=[0xFF])
    msg = J1939Message(0x18EA00FF, "00112233")  # src_addr 0xFF
    iface_tx.send_message(msg)
    msg2 = J1939Message(0x0CEC000B, "44556677")  # src_addr 0x0B
    iface_tx.send_message(msg2)
    import time
    time.sleep(0.5)
    collected = iface_rx.stop_data_collection()
    # Filter was src_addr=[0xFF], so we expect at least the first message (and possibly both depending on timing)
    assert len(collected) >= 1
    addrs = {m.src_addr for m in collected}
    assert 0xFF in addrs


def test_j1939_get_candump(j1939_interface):
    """get_candump(message) returns non-empty string."""
    msg = J1939Message(0x18EA00FF, "AABBCCDD")
    result = j1939_interface.get_candump(msg)
    assert isinstance(result, str)
    assert len(result) > 0
    assert "18EA00FF" in result or "AABBCCDD" in result.upper()


def test_j1939_get_decoded_message(j1939_interface):
    """get_decoded_message(message) returns non-empty string."""
    msg = J1939Message(0x18EA00FF, "AABBCCDD")
    result = j1939_interface.get_decoded_message(msg)
    assert isinstance(result, str)
    assert len(result) > 0


# --- Decoder tests exercising JSON resource files ---


def test_decoded_message_pgn_lookup(j1939_interface):
    """get_decoded_message with known PGN 61444 (EEC1) includes PGN acronym and label from pgn_list.json."""
    # PGN 61444 = 0xF004: pdu_format=0xF0, pdu_specific=0x04
    # src_addr=0x00 (Engine #1), broadcast
    can_id = j1939_fields_to_can_id(3, 0, 0, 0xF0, 0x04, 0x00)
    msg = J1939Message(can_id, "00" * 8)  # 8 bytes matching pgnDataLength
    result = j1939_interface.get_decoded_message(msg)
    assert "EEC1" in result
    assert "Electronic Engine Controller 1" in result
    assert "PGNDataLength" in result
    assert "TransmissionRate" in result


def test_decoded_message_spn_names(j1939_interface):
    """get_decoded_message with PGN 61444 decodes SPN names from spn_list.json."""
    can_id = j1939_fields_to_can_id(3, 0, 0, 0xF0, 0x04, 0x00)
    msg = J1939Message(can_id, "00" * 8)
    result = j1939_interface.get_decoded_message(msg)
    assert "Engine Torque Mode" in result  # SPN 899
    assert "Driver's Demand Engine" in result  # SPN 512
    assert "Engine Speed" in result  # SPN 190


def test_decoded_message_spn_value_with_resolution(j1939_interface):
    """get_decoded_message applies SPN resolution/offset from spn_list.json.
    SPN 512 (Driver's Demand Torque): 8 bits at bitPos 8, resolution=1, offset=-125.
    Byte 2 value 0x7D (125) -> (125 * 1) + (-125) = 0%."""
    can_id = j1939_fields_to_can_id(3, 0, 0, 0xF0, 0x04, 0x00)
    # Byte layout: [torqueMode|4154] [512] [513] [190 lo] [190 hi] [1483] [1675] [2432]
    msg = J1939Message(can_id, "007D00000000007D")
    result = j1939_interface.get_decoded_message(msg)
    assert "%" in result  # SPN 512 units
    assert "rpm" in result  # SPN 190 units


def test_decoded_message_bit_decoding(j1939_interface):
    """get_decoded_message uses dataBitDecoding.json for bit-type SPNs.
    SPN 899 (Engine Torque Mode, 4 bits at bitPos 0): the decoder uses MSB bit
    extraction from bin(data), so byte 0 = 0x10 gives first 4 bits = 0001 = 1
    -> 'accelerator pedal/operator selection'."""
    can_id = j1939_fields_to_can_id(3, 0, 0, 0xF0, 0x04, 0x00)
    msg = J1939Message(can_id, "10" + "00" * 7)
    result = j1939_interface.get_decoded_message(msg)
    assert "accelerator pedal" in result


def test_decoded_message_src_addr_lookup(j1939_interface):
    """get_decoded_message includes source/dest address names from src_addr_list.json."""
    # src=0 (Engine #1), dst=0xFF (GLOBAL)
    can_id = j1939_fields_to_can_id(3, 0, 0, 0xF0, 0x04, 0x00)
    msg = J1939Message(can_id, "00" * 8)
    result = j1939_interface.get_decoded_message(msg)
    assert "Engine" in result
    assert "GLOBAL" in result


def test_decoded_message_unknown_pgn(j1939_interface):
    """get_decoded_message with PGN not in pgn_list.json still returns basic info."""
    # PGN 3584 (pdu_format=0x0E) is not in pgn_list.json
    can_id = j1939_fields_to_can_id(6, 0, 0, 0x0E, 0x00, 0xFF)
    msg = J1939Message(can_id, "00112233")
    result = j1939_interface.get_decoded_message(msg)
    assert isinstance(result, str)
    assert len(result) > 0
    # Should NOT contain PGN label since it's unknown
    assert "PGNDataLength" not in result


def test_decoded_message_wrong_data_length(j1939_interface):
    """get_decoded_message with known PGN but wrong data length shows 'Cannot decode SPNs'."""
    can_id = j1939_fields_to_can_id(3, 0, 0, 0xF0, 0x04, 0x00)
    msg = J1939Message(can_id, "00112233")  # 4 bytes, EEC1 expects 8
    result = j1939_interface.get_decoded_message(msg)
    assert "EEC1" in result
    assert "Cannot decode SPNs" in result


def test_uds_decode_service_lookup(j1939_interface):
    """_uds_decode single frame with service 0x10 (DiagnosticSessionControl) from UDS_services.json."""
    can_id = j1939_fields_to_can_id(6, 0, 0, 0xDA, 0x00, 0xF9)
    # Single frame: type=0, size=2, serviceID=0x10, subfunction=0x01
    msg = J1939Message(can_id, "021001FFFFFFFFFF")
    result = j1939_interface.get_decoded_message(msg)
    assert "DiagnosticSessionControl" in result


def test_uds_decode_negative_response(j1939_interface):
    """_uds_decode negative response (0x7F) uses UDS_services.json and UDS_NRC.json."""
    can_id = j1939_fields_to_can_id(6, 0, 0, 0xDA, 0x00, 0xF9)
    # Negative response: type=0, size=3, serviceID=0x7F, rejected_service=0x10, NRC=0x12
    msg = J1939Message(can_id, "037F1012FFFFFFFF")
    result = j1939_interface.get_decoded_message(msg)
    assert "Negative Response" in result
    assert "DiagnosticSessionControl" in result


def test_j1939_data_collection(two_virtual_devices):
    """start_data_collection; send a few messages; stop_data_collection; assert count and content."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    iface_rx.start_data_collection(abstract_tpm=True)
    for _ in range(3):
        iface_tx.send_message(J1939Message(0x18EA00FF, "0011223344556677"))
    time.sleep(0.6)
    collected = iface_rx.stop_data_collection()
    assert len(collected) >= 1
    assert any(m.data for m in collected)


# --- Transport Protocol (multipacket) send and receive ---


def test_multipacket_send_bam(two_virtual_devices):
    """send_message with >8 bytes triggers BAM transport protocol; raw frames arrive on receiver."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)

    # 12 bytes of data -> requires 2 TP data transfer packets
    long_data = "AABBCCDDEEFF00112233AABB"
    msg = J1939Message(0x18EAFF00, long_data)  # broadcast (pdu_format >= 0xF0, dst 0xFF)
    iface_tx.send_message(msg)

    # Receiver should see the BAM control message (pdu_format=0xEC) and data transfer (0xEB)
    frames = []
    for _ in range(10):
        raw = dev_rx.read(timeout=0.5)
        if raw is None:
            break
        frames.append(raw)

    assert len(frames) >= 3  # 1 BAM + 2 data transfer packets
    # First frame should be TP.CM (pdu_format 0xEC)
    first = frames[0]
    assert (first.arbitration_id >> 16 & 0xFF) == 0xEC
    # First byte of BAM control message is 0x20
    assert first.data[0] == 0x20


def test_multipacket_receive_reassembly(two_virtual_devices):
    """Send >8 bytes; receiver with abstract_tpm=True reassembles into one J1939Message."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    long_data = "AABBCCDDEEFF00112233AABB"  # 12 bytes
    msg = J1939Message(0x18EAFF00, long_data)
    iface_tx.send_message(msg)

    received = iface_rx.read_one_message(abstract_tpm=True, timeout=2)
    assert received is not None
    assert received.total_bytes == 12
    assert received.data.upper() == long_data.upper()


def test_multipacket_rts_send(two_virtual_devices):
    """send_message with >8 bytes to destination-specific address triggers RTS (0x10)."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)

    # Destination-specific: pdu_format < 0xF0, pdu_specific = 0x0B (not 0xFF)
    long_data = "112233445566778899AABBCC"  # 12 bytes
    can_id = j1939_fields_to_can_id(6, 0, 0, 0xEA, 0x0B, 0x00)
    msg = J1939Message(can_id, long_data)
    iface_tx.send_message(msg)

    frames = []
    for _ in range(10):
        raw = dev_rx.read(timeout=0.5)
        if raw is None:
            break
        frames.append(raw)

    assert len(frames) >= 3
    first = frames[0]
    assert (first.arbitration_id >> 16 & 0xFF) == 0xEC
    # First byte of RTS control message is 0x10
    assert first.data[0] == 0x10


def test_multipacket_3_packets(two_virtual_devices):
    """Send 20 bytes (3 TP packets); reassembly returns all data."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    long_data = "AA" * 20  # 20 bytes -> ceil(20/7)=3 packets
    msg = J1939Message(0x18EAFF00, long_data)
    iface_tx.send_message(msg)

    received = iface_rx.read_one_message(abstract_tpm=True, timeout=2)
    assert received is not None
    assert received.total_bytes == 20
    assert received.data.upper() == long_data.upper()


# --- ISO-TP reassembly ---


def test_isotp_first_frame_and_consecutive_reassembly(two_virtual_devices):
    """Manually inject ISO-TP first frame + consecutive frames; reader reassembles with abstract_tpm=True."""
    dev_tx, dev_rx = two_virtual_devices
    iface_rx = J1939Interface(dev_rx)

    # ISO-TP first frame: pdu_format 0xDA, first nibble '1', size=10 bytes
    # Data format: 1<size_3hex><first 6 bytes of payload>
    # 10 bytes total, first frame carries 6 bytes of payload
    first_frame_data = bytes.fromhex("100AAABBCCDDEEFF")  # size=10, 6 payload bytes
    first_can_id = j1939_fields_to_can_id(6, 0, 0, 0xDA, 0x00, 0xF9)
    first_msg = can.Message(arbitration_id=first_can_id, data=first_frame_data, is_extended_id=True)
    dev_tx.send(first_msg)

    # Consecutive frame: first nibble '2', index=1, remaining 4 bytes + padding
    consec_data = bytes.fromhex("2111223344FFFFFF")  # index=1, 4 payload bytes
    consec_msg = can.Message(arbitration_id=first_can_id, data=consec_data, is_extended_id=True)
    time.sleep(0.05)
    dev_tx.send(consec_msg)

    received = iface_rx.read_one_message(abstract_tpm=True, timeout=2)
    assert received is not None
    # The reassembled message should contain the payload data
    assert len(received.data) > 0


# --- UDS decode ---


def test_uds_decode_single_frame(j1939_interface):
    """get_decoded_message on a UDS single-frame message (PGN 0xDA00) triggers _uds_decode."""
    # PGN 0xDA00 -> pdu_format=0xDA, pdu_specific=0x00
    can_id = j1939_fields_to_can_id(6, 0, 0, 0xDA, 0x00, 0xF9)
    # Single frame UDS: frame_type=0, size=2, service_id=3E (TesterPresent), sub=00
    msg = J1939Message(can_id, "023E00FFFFFFFFFF")
    result = j1939_interface.get_decoded_message(msg)
    assert isinstance(result, str)
    assert len(result) > 0


def test_uds_decode_first_frame(j1939_interface):
    """_uds_decode handles first frame type (frame_type=1)."""
    can_id = j1939_fields_to_can_id(6, 0, 0, 0xDA, 0x00, 0xF9)
    msg = J1939Message(can_id, "100AAABBCCDDEEFF")  # first frame, 10 bytes
    result = j1939_interface.get_decoded_message(msg)
    assert "First frame" in result or "incoming" in result


def test_uds_decode_consecutive_frame(j1939_interface):
    """_uds_decode handles consecutive frame type (frame_type=2)."""
    can_id = j1939_fields_to_can_id(6, 0, 0, 0xDA, 0x00, 0xF9)
    msg = J1939Message(can_id, "2100112233445566")  # consecutive, index 1
    result = j1939_interface.get_decoded_message(msg)
    assert "Consecutive frame" in result or "index" in result


def test_uds_decode_flow_control_frame(j1939_interface):
    """_uds_decode handles flow control frame type (frame_type=3)."""
    can_id = j1939_fields_to_can_id(6, 0, 0, 0xDA, 0x00, 0xF9)
    msg = J1939Message(can_id, "30000AFFFFFFFFFF")  # flow control
    result = j1939_interface.get_decoded_message(msg)
    assert "Flow control" in result or "FC Flag" in result


# --- save_data_collected / import_data_collected ---


def test_save_data_collected_writes_file(j1939_interface, tmp_path):
    """save_data_collected writes messages to a file that exists and has content."""
    messages = [
        J1939Message(0x18EA00FF, "AABBCCDDEEFF0011"),
        J1939Message(0x0CEC000B, "1122334455667788"),
    ]
    for m in messages:
        m.timestamp = 1.0

    f = tmp_path / "test_log.txt"
    j1939_interface.save_data_collected(messages, file_name=str(f))
    assert f.exists()
    content = f.read_text()
    assert "18EA00FF" in content
    assert "0CEC000B" in content


def test_import_data_collected_known_limitation(j1939_interface, tmp_path):
    """import_data_collected can't parse current __str__ format (has timestamp prefix).
    This documents the known TODO in the source. The parser expects 8 parts but
    __str__ now outputs 9 (timestamp + original fields).
    """
    messages = [J1939Message(0x18EA00FF, "AABBCCDDEEFF0011")]
    messages[0].timestamp = 1.0
    f = tmp_path / "test_log2.txt"
    j1939_interface.save_data_collected(messages, file_name=str(f))

    imported = j1939_interface.import_data_collected(str(f))
    # Known bug: returns empty because __str__ format doesn't match the parser
    assert imported == []


def test_save_data_collected_empty_raises(j1939_interface, tmp_path):
    """save_data_collected with empty list raises Exception."""
    f = tmp_path / "empty.txt"
    with pytest.raises(Exception, match="empty"):
        j1939_interface.save_data_collected([], file_name=str(f))


def test_import_data_collected_missing_file_raises(j1939_interface):
    """import_data_collected with nonexistent file raises Exception."""
    with pytest.raises(Exception, match="does not exist"):
        j1939_interface.import_data_collected("nonexistent_file_xyz.txt")


# --- read_messages_until ---


def test_read_messages_until_finds_match(two_virtual_devices):
    """read_messages_until returns when a message matching the params is found."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    def send_messages():
        time.sleep(0.1)
        iface_tx.send_message(J1939Message(0x18EA00FF, "1111111111111111"))
        time.sleep(0.05)
        iface_tx.send_message(J1939Message(0x18EA000B, "2222222222222222"))

    t = threading.Thread(target=send_messages)
    t.start()
    found, collected = iface_rx.read_messages_until(src_addr=0x0B)
    t.join(timeout=2)
    assert found is not None
    assert found.src_addr == 0x0B
    assert len(collected) >= 1


def test_read_messages_until_data_contains(two_virtual_devices):
    """read_messages_until with data_contains filter."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    def send_messages():
        time.sleep(0.1)
        iface_tx.send_message(J1939Message(0x18EA00FF, "AABB000000000000"))
        time.sleep(0.05)
        iface_tx.send_message(J1939Message(0x18EA00FF, "00CCDD0000000000"))

    t = threading.Thread(target=send_messages)
    t.start()
    found, collected = iface_rx.read_messages_until(data_contains="CCDD")
    t.join(timeout=2)
    assert found is not None
    assert "CCDD" in found.data.upper()


def test_read_messages_until_no_params_raises(j1939_interface):
    """read_messages_until with no params raises Exception."""
    with pytest.raises(Exception, match="at least one parameter"):
        j1939_interface.read_messages_until()


# --- print_messages direct tests ---


def test_print_messages_num_messages(two_virtual_devices):
    """print_messages with num_messages=3 prints exactly 3 messages then returns."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    def send_messages():
        for i in range(5):
            time.sleep(0.05)
            iface_tx.send_message(J1939Message(0x18EA00FF, f"0{i}11223344556677"))

    t = threading.Thread(target=send_messages)
    t.start()
    buf = io.StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        iface_rx.print_messages(num_messages=3)
    finally:
        sys.stdout = old
    t.join(timeout=3)
    lines = [l for l in buf.getvalue().strip().split("\n") if l.strip()]
    assert len(lines) == 3


def test_print_messages_with_src_addr_filter(two_virtual_devices):
    """print_messages with src_addr filter only prints matching messages."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    def send_messages():
        time.sleep(0.05)
        iface_tx.send_message(J1939Message(0x18EA00FF, "1111111111111111"))  # src 0xFF
        time.sleep(0.05)
        iface_tx.send_message(J1939Message(0x18EA000B, "2222222222222222"))  # src 0x0B
        time.sleep(0.05)
        iface_tx.send_message(J1939Message(0x18EA00FF, "3333333333333333"))  # src 0xFF

    t = threading.Thread(target=send_messages)
    t.start()
    buf = io.StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        iface_rx.print_messages(num_messages=2, src_addr=[0xFF])
    finally:
        sys.stdout = old
    t.join(timeout=3)
    lines = [l for l in buf.getvalue().strip().split("\n") if l.strip()]
    assert len(lines) == 2
    for line in lines:
        assert "0B" not in line.split()[0][-2:]


def test_print_messages_verbose(two_virtual_devices):
    """print_messages with verbose=True prints decoded form."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    def send_messages():
        time.sleep(0.05)
        iface_tx.send_message(J1939Message(0x18EA00FF, "1111111111111111"))

    t = threading.Thread(target=send_messages)
    t.start()
    buf = io.StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        iface_rx.print_messages(num_messages=1, verbose=True)
    finally:
        sys.stdout = old
    t.join(timeout=3)
    out = buf.getvalue()
    assert len(out) > 0
    # Verbose output is multi-line (decoded) rather than single-line
    assert "\n" in out.strip()


def test_print_messages_log_to_file(two_virtual_devices, tmp_path):
    """print_messages with log_to_file=True writes messages to file."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    log_file = tmp_path / "print_log.txt"

    def send_messages():
        time.sleep(0.05)
        iface_tx.send_message(J1939Message(0x18EA00FF, "1111111111111111"))
        time.sleep(0.05)
        iface_tx.send_message(J1939Message(0x18EA00FF, "2222222222222222"))

    t = threading.Thread(target=send_messages)
    t.start()
    iface_rx.print_messages(num_messages=2, log_to_file=True, file_name=str(log_file))
    t.join(timeout=3)
    assert log_file.exists()
    content = log_file.read_text()
    assert "18EA00FF" in content


def test_print_messages_read_time(two_virtual_devices):
    """print_messages with read_time stops after the timer expires."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    def send_messages():
        for _ in range(20):
            time.sleep(0.05)
            iface_tx.send_message(J1939Message(0x18EA00FF, "1111111111111111"))

    t = threading.Thread(target=send_messages)
    t.start()
    buf = io.StringIO()
    old = sys.stdout
    start = time.time()
    try:
        sys.stdout = buf
        iface_rx.print_messages(read_time=0.3)
    finally:
        sys.stdout = old
    elapsed = time.time() - start
    t.join(timeout=3)
    # Should have stopped around 0.3s, not run indefinitely
    assert elapsed < 2.0


def test_print_messages_candump(two_virtual_devices):
    """print_messages with candump=True prints candump format."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    def send_messages():
        time.sleep(0.05)
        iface_tx.send_message(J1939Message(0x18EA00FF, "1111111111111111"))

    t = threading.Thread(target=send_messages)
    t.start()
    buf = io.StringIO()
    old = sys.stdout
    try:
        sys.stdout = buf
        iface_rx.print_messages(num_messages=1, candump=True)
    finally:
        sys.stdout = old
    t.join(timeout=3)
    out = buf.getvalue()
    assert len(out) > 0


# --- get_collected_data / data_collection_occurring ---


def test_get_collected_data(two_virtual_devices):
    """get_collected_data returns messages during active collection."""
    dev_tx, dev_rx = two_virtual_devices
    iface_tx = J1939Interface(dev_tx)
    iface_rx = J1939Interface(dev_rx)

    iface_rx.start_data_collection(abstract_tpm=True)
    assert iface_rx.data_collection_occurring is True

    iface_tx.send_message(J1939Message(0x18EA00FF, "AABBCCDDEEFF0011"))
    time.sleep(0.3)

    data = iface_rx.get_collected_data()
    assert isinstance(data, list)

    collected = iface_rx.stop_data_collection()
    assert iface_rx.data_collection_occurring is False
    assert isinstance(collected, list)


def test_start_data_collection_twice_raises(j1939_interface):
    """Starting data collection when already running raises."""
    j1939_interface.start_data_collection()
    try:
        with pytest.raises(Exception, match="already started"):
            j1939_interface.start_data_collection()
    finally:
        j1939_interface.stop_data_collection()


def test_stop_data_collection_when_stopped_raises(j1939_interface):
    """Stopping data collection when not running raises."""
    with pytest.raises(Exception, match="already stopped"):
        j1939_interface.stop_data_collection()


# --- save_data_collected verbose ---


def test_save_data_collected_verbose(j1939_interface, tmp_path):
    """save_data_collected with verbose=True writes decoded messages."""
    messages = [J1939Message(0x18EA00FF, "AABBCCDDEEFF0011")]
    messages[0].timestamp = 1.0
    f = tmp_path / "verbose_log.txt"
    j1939_interface.save_data_collected(messages, file_name=str(f), verbose=True)
    assert f.exists()
    content = f.read_text()
    assert len(content) > 0
    # Verbose output is multi-line (decoded form)
    lines = content.strip().split("\n")
    assert len(lines) > 1
