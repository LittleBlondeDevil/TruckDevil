import cmd
import copy
import time

from j1939.j1939 import J1939Interface, J1939Message
from libs.ecus import ECU


def input_to_int(in_str: str) -> int:
    """
    Takes user input string and converts to an integer
    """
    if in_str.startswith("0x"):
        return int(in_str, 16)
    return int(in_str)


class ECUDiscovery:
    def __init__(self, device):
        self.devil = J1939Interface(device)
        self._known_ecus = []

    @property
    def known_ecus(self):
        return self._known_ecus

    def get_ecu_by_address(self, address):
        for e in self._known_ecus:
            if e.address == address:
                return e
        return None

    def get_all_addresses(self) -> list:
        """
        returns all known ECU's addresses
        """
        return [e.address for e in self._known_ecus]

    def add_known_ecu(self, ecu: ECU) -> ECU:
        """
        Add an ECU to the list of known ECUs if it's not already there. If already added, return the one already found.
        """
        for e in self._known_ecus:
            if e.address == ecu.address:
                return e
        self._known_ecus.append(ecu)
        return ecu


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
                self.ed.add_known_ecu(ecu).address_claimed_response = m
        ecus_added = len(self.ed.get_all_addresses()) - len(known_addresses)
        print("scanning complete.")
        if ecus_added > 0:
            print("added {} new ecus.".format(ecus_added))
        else:
            print("no new ecus found.")

    def do_find_boot_msg(self, arg):
        """
        Provide the address of the ECU to discover it's reboot message in order to detect crashes.
        ECU must be reset during this test.

        usage: find_boot_msg <address>
        """
        argv = arg.split()
        if len(argv) == 0:
            print("expected address, see 'help find_boot_msg'")
            return
        address = input_to_int(argv[0])
        if address < 0 or address > 255:
            print("address should be between 0-255.")
            return
        while True:
            val = input("please shut down the ECU, enter y when done or q to quit: ")
            if val == 'q' or val == 'quit':
                return
            if val != 'y' and val != 'yes':
                print('input not recognized.')
                continue
            break
        print("waiting for messages to stop transmitting...")
        while self.ed.devil.read_one_message(timeout=0.5) is not None:
            continue
        self.ed.devil.start_data_collection()
        while True:
            val = input("please power on the ECU, enter y when done or q to quit: ")
            if val == 'q' or val == 'quit':
                self.ed.devil.stop_data_collection()
            if val != 'y' and val != 'yes':
                print('input not recognized.')
                continue
            break
        messages = self.ed.devil.stop_data_collection()
        reboot_message = None
        for m in messages:
            if m.src_addr == address:
                reboot_message = m
                break
        if reboot_message is None:
            print("no messages detected for ECU {}.".format(address))
        else:
            print("reboot message for ECU {}: \n{}".format(address, reboot_message))

    def do_find_proprietary(self, arg):
        """
        Provide the address of the ECU to discover the proprietary messages it's sending.
        Performs passive and active scanning techniques.

        usage: find_proprietary <address>
        """
        argv = arg.split()
        if len(argv) == 0:
            print("expected address, see 'help find_proprietary'")
            return
        address = input_to_int(argv[0])
        if address < 0 or address > 255:
            print("address should be between 0-255.")
            return
        print("Scanning...")
        self.ed.devil.start_data_collection()
        rqst = J1939Message(can_id=0x18EA0000, data="")
        rqst.pdu_specific = address
        prop_range = []
        for i in range(0, 256):
            prop_range.append("{0:02x}EF00".format(i))
            prop_range.append("{0:02x}FF00".format(i))
        for data in prop_range:
            rqst.data = data
            self.ed.devil.send_message(rqst)
        time.sleep(10)
        messages = self.ed.devil.stop_data_collection()
        e = self.ed.get_ecu_by_address(address)
        num_prop_messages = 0
        if e is not None:
            num_prop_messages = len(e.prop_messages)
        for m in messages:
            if m.src_addr == address and (m.pdu_format == 0xEF or m.pdu_format == 0xFF):
                if e is None:
                    e = ECU(address)
                    self.ed.add_known_ecu(e)
                e.add_prop_message(m)
        discovered = len(e.prop_messages) - num_prop_messages
        if discovered > 0:
            print("discovered {} new unique proprietary messages.".format(discovered))
        else:
            print("no additional proprietary messages found.")
        if len(e.prop_messages) > 0:
            print("Proprietary messages for address {}:".format(address))
            for p in e.prop_messages:
                print(p)

    def do_find_uds(self, arg):
        # TODO: add progress bar
        """
        Provide the address of the ECU to determine if it responds to a UDS session.
        Performs passive and active scanning techniques.

        usage: find_uds <address>
        """
        argv = arg.split()
        if len(argv) == 0:
            print("expected address, see 'help find_proprietary'")
            return
        address = input_to_int(argv[0])
        if address < 0 or address > 255:
            print("address should be between 0-255.")
            return
        print("Scanning...")
        self.ed.devil.start_data_collection()
        uds_pdu_formats = [0xDA, 0xDB, 0xCD, 0xCE, 0xEF]
        tester_present_request = "023E00FFFFFFFF"
        msg = J1939Message(0x180000F9, tester_present_request)
        msg.pdu_specific = address
        messages_to_send = []
        for f in uds_pdu_formats:
            msg.pdu_format = f
            for pri in range(0, 8):
                for dp in range(0, 2):
                    for rb in range(0, 2):
                        msg.priority = pri
                        msg.data_page_bit = dp
                        msg.reserved_bit = rb
                        messages_to_send.append(copy.copy(msg))
        for m in messages_to_send:
            self.ed.devil.send_message(m)
            time.sleep(0.5)
        time.sleep(5)
        messages = self.ed.devil.stop_data_collection()
        uniq_responses = []
        for m in messages:
            if m.pdu_format in uds_pdu_formats:
                if m.pdu_format == 0xEF and "027E" not in m.data:
                    continue
                if m.can_id not in [rsp.can_id for rsp in uniq_responses]:
                    uniq_responses.append(m)
        if len(uniq_responses) == 0:
            print("ECU did not respond to any tester present requests.")
        else:
            for u in uniq_responses:
                print("Tester present responses: \n{}".format(u))

    def do_request_pgn(self, arg):
        """
        Provide the address of the ECU and the PGN to request from it

        usage: request_pgn <address> <pgn>

        example (request ECU Identification Information from a brake controller):
        request_pgn 11 64965
        """
        argv = arg.split()
        if len(argv) != 2:
            print("expected address and pgn, see 'help request_pgn'")
            return
        address = input_to_int(argv[0])
        if address < 0 or address > 255:
            print("address should be between 0-255.")
            return
        pgn = input_to_int(argv[1])
        if pgn < 0 or pgn > 0x01FFFF:
            print("pgn should be between 0x0 - 0x1FFFF")
            return
        print("requesting {} from {}...".format(pgn, address))
        pgn_data = "{0:06x}".format(pgn)
        pgn_data = pgn_data[4:6] + pgn_data[2:4] + pgn_data[0:2]
        self.ed.devil.start_data_collection()
        rqst = J1939Message(can_id=0x18EA0000, data=pgn_data)
        rqst.pdu_specific = address
        self.ed.devil.send_message(rqst)
        time.sleep(5)
        messages = self.ed.devil.stop_data_collection()
        ack_msg = None
        found_msg = None
        for m in messages:
            if m.pdu_format == 0xE8:
                ack_msg = m

            if m.pgn == pgn:
                found_msg = m
        if ack_msg is None:
            print("ECU did not ack the request.")
        else:
            print("Acknowledgement message: \n{}".format(ack_msg))
        if found_msg is None:
            print("ECU did not send requested message.")
        else:
            print(found_msg)


def main_mod(argv, device):
    dcli = DiscoveryCommands(argv, device)
    dcli.cmdloop()
