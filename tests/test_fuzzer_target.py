"""Unit tests for J1939Fuzzer.Target class (no device)."""
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "truckdevil"))

from truckdevil.modules.j1939_fuzzer import J1939Fuzzer


Target = J1939Fuzzer.Target


def test_target_creation_int():
    t = Target(11)
    assert t.address == 11
    assert t.has_user_set_reboot_pgn() is False
    assert t.has_user_set_reboot_data_snip() is False


def test_target_creation_hex_string():
    t = Target("0x0B")
    assert t.address == 11


def test_target_creation_decimal_string():
    t = Target("11")
    assert t.address == 11


def test_target_address_out_of_range():
    with pytest.raises(ValueError, match="between 0 and 255"):
        Target(256)
    with pytest.raises(ValueError, match="between 0 and 255"):
        Target(-1)


def test_target_set_reboot_pgn_int():
    t = Target(0)
    t.reboot_pgn = 64965
    assert t.reboot_pgn == 64965
    assert t.has_user_set_reboot_pgn() is True


def test_target_set_reboot_pgn_hex_string():
    t = Target(0)
    t.reboot_pgn = "0xFDC5"
    assert t.reboot_pgn == 0xFDC5


def test_target_set_reboot_pgn_out_of_range():
    t = Target(0)
    with pytest.raises(ValueError, match="between 0 and 65535"):
        t.reboot_pgn = 70000


def test_target_set_reboot_data_snip():
    t = Target(0)
    t.reboot_data_snip = "AABBCCDD"
    assert t.reboot_data_snip == "AABBCCDD"
    assert t.has_user_set_reboot_data_snip() is True


def test_target_set_reboot_data_snip_with_0x():
    t = Target(0)
    t.reboot_data_snip = "0xAABB"
    assert t.reboot_data_snip == "AABB"


def test_target_set_reboot_data_snip_odd_length():
    t = Target(0)
    with pytest.raises(ValueError, match="even number"):
        t.reboot_data_snip = "AAB"


def test_target_set_reboot_data_snip_non_hex():
    t = Target(0)
    with pytest.raises(ValueError):
        t.reboot_data_snip = "ZZZZ"


def test_target_str_defaults():
    t = Target(11)
    s = str(t)
    assert "11" in s
    assert "not set" in s


def test_target_str_with_values():
    t = Target(11, reboot_pgn=100, reboot_data_snip="AABB")
    s = str(t)
    assert "11" in s
    assert "100" in s
    assert "AABB" in s


def test_target_full_construction():
    t = Target(0x0B, reboot_pgn="0xFDC5", reboot_data_snip="0xAABBCCDD")
    assert t.address == 0x0B
    assert t.reboot_pgn == 0xFDC5
    assert t.reboot_data_snip == "AABBCCDD"


# --- J1939Fuzzer target management (add/remove/modify) ---


@pytest.fixture
def fuzzer_with_device(j1939_cwd):
    """Create a J1939Fuzzer backed by a virtual device."""
    import uuid
    from truckdevil.libs.device import Device
    from truckdevil.modules.j1939_fuzzer import J1939Fuzzer

    channel = f"fzt-{uuid.uuid4().hex}"
    device = Device("virtual", None, channel, 250000)
    fuzzer = J1939Fuzzer(device)
    yield fuzzer
    if getattr(device, "can_bus", None) is not None:
        try:
            device.can_bus.shutdown()
        except Exception:
            pass


def test_fuzzer_add_target(fuzzer_with_device):
    fuzzer = fuzzer_with_device
    assert len(fuzzer.targets) == 0
    t = Target(11)
    fuzzer.add_target(t)
    assert len(fuzzer.targets) == 1
    assert fuzzer.targets[0].address == 11


def test_fuzzer_add_target_duplicate_raises(fuzzer_with_device):
    fuzzer = fuzzer_with_device
    fuzzer.add_target(Target(11))
    with pytest.raises(ValueError, match="already exists"):
        fuzzer.add_target(Target(11))


def test_fuzzer_remove_target(fuzzer_with_device):
    fuzzer = fuzzer_with_device
    fuzzer.add_target(Target(11))
    fuzzer.add_target(Target(22))
    assert len(fuzzer.targets) == 2
    fuzzer.remove_target(11)
    assert len(fuzzer.targets) == 1
    assert fuzzer.targets[0].address == 22


def test_fuzzer_remove_target_hex_string(fuzzer_with_device):
    fuzzer = fuzzer_with_device
    fuzzer.add_target(Target(0x0B))
    fuzzer.remove_target("0x0B")
    assert len(fuzzer.targets) == 0


def test_fuzzer_modify_target(fuzzer_with_device):
    fuzzer = fuzzer_with_device
    fuzzer.add_target(Target(11))
    fuzzer.modify_target(11, 100, "AABB")
    assert fuzzer.targets[0].reboot_pgn == 100
    assert fuzzer.targets[0].reboot_data_snip == "AABB"


def test_fuzzer_modify_target_hex_string(fuzzer_with_device):
    fuzzer = fuzzer_with_device
    fuzzer.add_target(Target(0x0B))
    fuzzer.modify_target("0x0B", 200, "CCDD")
    assert fuzzer.targets[0].reboot_pgn == 200


def test_fuzzer_targets_setter(fuzzer_with_device):
    fuzzer = fuzzer_with_device
    targets = [Target(1), Target(2), Target(3)]
    fuzzer.targets = targets
    assert len(fuzzer.targets) == 3


# --- J1939Fuzzer.mutate unit tests ---


def test_fuzzer_mutate_priority(fuzzer_with_device):
    from truckdevil.j1939.j1939 import J1939Message
    fuzzer = fuzzer_with_device
    msg = J1939Message(0x18EA00FF, "AABBCCDD")
    original_data = msg.data
    result = fuzzer.mutate(msg, mutate_priority=True)
    assert 0 <= result.priority <= 7
    assert result.data == original_data  # data untouched


def test_fuzzer_mutate_data(fuzzer_with_device):
    from truckdevil.j1939.j1939 import J1939Message
    fuzzer = fuzzer_with_device
    msg = J1939Message(0x18EA00FF, "AABBCCDD")
    result = fuzzer.mutate(msg, mutate_data=True)
    assert len(result.data) == 8  # 4 bytes = 8 hex chars


def test_fuzzer_mutate_all_fields(fuzzer_with_device):
    from truckdevil.j1939.j1939 import J1939Message
    fuzzer = fuzzer_with_device
    msg = J1939Message(0x18EA00FF, "AABBCCDD")
    result = fuzzer.mutate(
        msg,
        mutate_priority=True,
        mutate_reserved_bit=True,
        mutate_data_page_bit=True,
        mutate_pdu_format=True,
        mutate_pdu_specific=True,
        mutate_src_addr=True,
        mutate_data=True,
    )
    assert 0 <= result.priority <= 7
    assert result.reserved_bit in (0, 1)
    assert result.data_page_bit in (0, 1)
    assert 0 <= result.pdu_format <= 255
    assert 0 <= result.pdu_specific <= 255
    assert 0 <= result.src_addr <= 255


def test_fuzzer_mutate_data_length(fuzzer_with_device):
    from truckdevil.j1939.j1939 import J1939Message
    fuzzer = fuzzer_with_device
    msg = J1939Message(0x18EA00FF, "AABBCCDD")
    result = fuzzer.mutate(msg, mutate_data_length=True)
    # Length may have changed (shorter or longer)
    assert len(result.data) % 2 == 0  # always even hex chars


def test_fuzzer_generate_returns_message(fuzzer_with_device):
    fuzzer = fuzzer_with_device
    msg = fuzzer.generate(option=2)
    assert type(msg).__name__ == "J1939Message"
    assert 0 <= msg.can_id <= 0x1FFFFFFF
