import cmd
import time

from j1939.j1939 import J1939Interface, J1939Message
from libs.ecus import ECU


class ECUDiscovery:
    def __init__(self, device):
        self.devil = J1939Interface(device)
        self._known_ecus = []

    @property
    def known_ecus(self):
        return self._known_ecus

    def get_all_addresses(self) -> list:
        """
        returns all known ECU's addresses
        """
        return [e.address for e in self._known_ecus]

    def add_known_ecu(self, ecu: ECU):
        if ecu.address not in (e.address for e in self._known_ecus):
            self._known_ecus.append(ecu)


class DiscoveryCommands(cmd.Cmd):
    intro = "Welcome to the ECU Discovery tool."
    prompt = "(truckdevil.ecu_discovery) "

    def __init__(self, argv, device):
        super().__init__()
        self.ed = ECUDiscovery(device)

    def do_view_ecus(self, arg):
        """
        View information about all ECUs discovered on the bus.
        """
        if len(self.ed.get_all_addresses()) == 0:
            print("no ecu information stored. See the passive_scan command.")
            return
        for ecu in self.ed.known_ecus:
            print(ecu)

    def do_passive_scan(self, arg):
        """
        Passively scan the bus to find ECUs and store them in the list of discovered ecus.
        """
        print("scanning...")
        self.ed.devil.start_data_collection()
        time.sleep(10)
        messages = self.ed.devil.stop_data_collection()
        known_addresses = self.ed.get_all_addresses()
        for m in messages:
            ecu = ECU(m.src_addr)
            self.ed.add_known_ecu(ecu)
        ecus_added = len(self.ed.get_all_addresses()) - len(known_addresses)
        print("scanning complete.")
        if ecus_added > 0:
            print("added {} new ecus.".format(ecus_added))
        else:
            print("no new ecus found.")

    def do_active_scan(self, arg):
        """
        Send Request for Address Claimed to discover ECUs and their NAME value
        """
        print("scanning...")
        self.ed.devil.start_data_collection()
        rqst = J1939Message(can_id=0x18EA0000, data="00EE00")
        for addr in range(0, 256):
            rqst.pdu_specific = addr
            self.ed.devil.send_message(rqst)
        time.sleep(5)  # Give ecus 5 seconds to respond
        messages = self.ed.devil.stop_data_collection()
        known_addresses = self.ed.get_all_addresses()
        for m in messages:
            if m.pdu_format == 0xEE:
                ecu = ECU(m.src_addr)
                ecu.address_claimed_response = m
                self.ed.add_known_ecu(ecu)
        ecus_added = len(self.ed.get_all_addresses()) - len(known_addresses)
        print("scanning complete.")
        if ecus_added > 0:
            print("added {} new ecus.".format(ecus_added))
        else:
            print("no new ecus found.")


def main_mod(argv, device):
    dcli = DiscoveryCommands(argv, device)
    dcli.cmdloop()
