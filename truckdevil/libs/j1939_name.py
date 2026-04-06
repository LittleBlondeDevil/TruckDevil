import json
import os

class J1939NameDecoder:
    _instance = None
    _db = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(J1939NameDecoder, cls).__new__(cls)
            cls._instance._load_db()
        return cls._instance

    def _load_db(self):
        try:
            base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            json_path = os.path.join(base_path, "resources", "json_files", "dataBitDecoding.json")
            with open(json_path, "r") as f:
                self._db = json.load(f)
        except Exception:
            self._db = {}

    def get_name(self, spn, value):
        spn_str = str(spn)
        val_str = str(value)
        if self._db and spn_str in self._db:
            return self._db[spn_str].get(val_str, "Unknown")
        return "Unknown"

class J1939Name:
    def __init__(self, name_val):
        """
        :param name_val: 64-bit integer or hex string (16 chars)
        """
        if isinstance(name_val, str):
            # Strip 0x if present
            if name_val.startswith("0x"):
                name_val = name_val[2:]
            self.name_int = int(name_val, 16)
        else:
            self.name_int = name_val
        
        self.decode()
        self.decoder = J1939NameDecoder()

    def decode(self):
        # bitfields from LSB to MSB (J1939-81)
        # Identity Number: 21 bits (0-20)
        self.identity_number = self.name_int & 0x1FFFFF
        # Manufacturer Code: 11 bits (21-31)
        self.manufacturer_code = (self.name_int >> 21) & 0x7FF
        # ECU Instance: 3 bits (32-34)
        self.ecu_instance = (self.name_int >> 32) & 0x07
        # Function Instance: 5 bits (35-39)
        self.function_instance = (self.name_int >> 35) & 0x1F
        # Function: 8 bits (40-47)
        self.function = (self.name_int >> 40) & 0xFF
        # Reserved: 1 bit (48)
        self.reserved = (self.name_int >> 48) & 0x01
        # Vehicle System: 7 bits (49-55)
        self.vehicle_system = (self.name_int >> 49) & 0x7F
        # Vehicle System Instance: 4 bits (56-59)
        self.vehicle_system_instance = (self.name_int >> 56) & 0x0F
        # Industry Group: 3 bits (60-62)
        self.industry_group = (self.name_int >> 60) & 0x07
        # Arbitrary Address Capable: 1 bit (63)
        self.arbitrary_address_capable = (self.name_int >> 63) & 0x01

    def get_industry_group_name(self):
        return self.decoder.get_name(2846, self.industry_group)

    def get_vehicle_system_name(self):
        return self.decoder.get_name(2842, self.vehicle_system)

    def get_function_name(self):
        return self.decoder.get_name(2841, self.function)

    def get_manufacturer_name(self):
        return self.decoder.get_name(2838, self.manufacturer_code)

    def __str__(self):
        ig = self.get_industry_group_name()
        vs = self.get_vehicle_system_name()
        func = self.get_function_name()
        mfg = self.get_manufacturer_name()
        aac_str = "Yes" if self.arbitrary_address_capable else "No"
        
        lines = [
            f"NAME: 0x{self.name_int:016x}",
            f"  Arbitrary Address Capable: {aac_str}",
            f"  Industry Group:            {self.industry_group} ({ig})",
            f"  Vehicle System Instance:   {self.vehicle_system_instance}",
            f"  Vehicle System:            {self.vehicle_system} ({vs})",
            f"  Function:                  {self.function} ({func})",
            f"  Function Instance:         {self.function_instance}",
            f"  ECU Instance:              {self.ecu_instance}",
            f"  Manufacturer Code:         {self.manufacturer_code} ({mfg})",
            f"  Identity Number:           {self.identity_number}"
        ]
        return "\n".join(lines)
