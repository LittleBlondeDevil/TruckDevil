from truckdevil.libs.j1939_name import J1939Name

def test_j1939_name_decoding():
    # Example NAME: 0xA0123456789ABCDE
    # 0xA = 1010b
    # Bit 63: 1 (Arbitrary Address Capable)
    # Bits 62-60: 010b = 2 (Agricultural and Forestry Equipment)
    # Bits 59-56: 0000b = 0 (Vehicle System Instance)
    # Bits 55-49: 0000000b = 0 (Vehicle System)
    # Bit 48: 0 (Reserved)
    # Bits 47-40: 00000000b = 0 (Function)
    # ... and so on
    
    # Let's use a simpler one: 0x8000000000000000
    # AAC=1, IG=0, rest=0
    name = J1939Name(0x8000000000000000)
    assert name.arbitrary_address_capable == 1
    assert name.industry_group == 0
    assert name.identity_number == 0

    # Test with string
    name2 = J1939Name("0x8000000000000000")
    assert name2.arbitrary_address_capable == 1
    
    # Test with hex string no 0x
    name3 = J1939Name("8000000000000000")
    assert name3.arbitrary_address_capable == 1

def test_j1939_name_str():
    # Verify it doesn't crash and returns a string
    name = J1939Name(0x8000000000000000)
    s = str(name)
    assert "Arbitrary Address Capable: Yes" in s
    assert "Industry Group:            0" in s

    name_no = J1939Name(0x0000000000000000)
    assert "Arbitrary Address Capable: No" in str(name_no)


def test_j1939_name_industry_group_specific():
    # Industry group 2 (Agricultural and Forestry Equipment)
    # IG is bits 60-62. 2 << 60 = 0x2000000000000000
    name = J1939Name(0x2000000000000000)
    assert name.industry_group == 2
    assert name.get_vehicle_system_name() == "Industry group specific"
    assert name.get_function_name() == "Industry group specific"

    # Industry group 0 or 1
    name_on_highway = J1939Name(0x1000000000000000)
    assert name_on_highway.industry_group == 1
    assert name_on_highway.get_vehicle_system_name() != "Industry group specific"

