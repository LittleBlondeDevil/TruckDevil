import copy
import time
import dill
import shlex
import json
import os

from truckdevil.j1939.j1939 import J1939Interface, J1939Message
from truckdevil.libs.command import Command
from truckdevil.libs.ecu import ECU
from truckdevil.libs.settings import SettingsManager, Setting


def get_ecu_name(address: int) -> str:
    """
    Look up the default ECU name from the J1939 database.
    """
    try:
        # Construct path to the json file
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        json_path = os.path.join(base_path, "resources", "json_files", "src_addr_list.json")
        with open(json_path, "r") as f:
            addr_list = json.load(f)
            return addr_list.get(str(address), "Unknown")
    except Exception:
        return "Unknown"


def format_ecu_address(address: int) -> str:
    """
    Format ECU address as: 0x<hex>: <name> (<decimal>)
    Example: 0x0b: Brake System Controller (11)
    """
    name = get_ecu_name(address)
    return "0x{:02x}: {} ({})".format(address, name, address)


def input_to_int(in_str: str) -> int:
    """
    Takes user input string and converts to an integer
    """
    if in_str.startswith("0x"):
        return int(in_str, 16)
    return int(in_str)


class ECUDiscovery:
    def __init__(self):
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


class DiscoveryCommands(Command):
    intro = "Welcome to the ECU Discovery tool."
    prompt = "(truckdevil.ecu_discovery) "

    def __init__(self, device):
        sm = SettingsManager()
        sm.add_setting(Setting("name_details", False).add_description("Show full J1939 NAME decoding details"))
        sm.add_setting(Setting("scan_interval", 10).add_description("Time in seconds to capture traffic for scans"))
        super().__init__(sm=sm)
        self.devil = J1939Interface(device)
        self.ed = ECUDiscovery()

    def do_save(self, arg):
        """
        save ECU information to file.

        usage: save <file_name>
        """
        argv = arg.split()
        if len(argv) != 1:
            print("expected file name, see 'help save'")
            return
        file_name = argv[0]
        try:
            dill.dump(self.ed, open(file_name, "xb"))
        except FileExistsError:
            print("file already exists")
            return
        print("ECU information saved to {}".format(file_name))

    def do_load(self, arg):
        """
        load ECU information from a file.

        usage: load <file_name>
        """
        argv = arg.split()
        if len(argv) != 1:
            print("expected file name, see 'help save'")
            return
        file_name = argv[0]
        self.ed = dill.load(open(file_name, "rb"))
        print("ECU information loaded from {}".format(file_name))

    def do_view_ecus(self, arg):
        """
        View information about all ECUs discovered on the bus.
        """
        if len(self.ed.get_all_addresses()) == 0:
            print("no ecu information stored. See the passive_scan command.")
            return

        import textwrap
        
        # Table configuration
        max_width = 100
        addr_width = 10
        db_name_width = 20
        name_id_width = max_width - addr_width - db_name_width - 6 # 6 for separators "| " and " | "

        header = f"{'address':<{addr_width}} | {'DB Name':<{db_name_width}} | {'unique 64-bit NAME ID':<{name_id_width}}"
        sep = "-" * max_width
        print(sep)
        print(header)
        print(sep)

        for ecu in self.ed.known_ecus:
            addr_str = f"0x{ecu.address:02x}"
            db_name = get_ecu_name(ecu.address)
            
            # Prepare the NAME ID column content
            name_id_content = "unknown"
            if ecu.name is not None:
                name_id_content = ecu.name
                if self.sm.name_details and ecu.name_decoded:
                    name_id_content += "\n" + str(ecu.name_decoded)
            
            # Wrap each piece of content
            addr_wrapped = textwrap.wrap(addr_str, width=addr_width)
            db_name_wrapped = textwrap.wrap(db_name, width=db_name_width)
            name_id_wrapped = []
            # For NAME ID, we want to preserve internal newlines (from decoded info)
            for part in name_id_content.split('\n'):
                name_id_wrapped.extend(textwrap.wrap(part, width=name_id_width))

            # Print the wrapped rows
            num_lines = max(len(addr_wrapped), len(db_name_wrapped), len(name_id_wrapped))
            for i in range(num_lines):
                a = addr_wrapped[i] if i < len(addr_wrapped) else ""
                d = db_name_wrapped[i] if i < len(db_name_wrapped) else ""
                n = name_id_wrapped[i] if i < len(name_id_wrapped) else ""
                print(f"{a:<{addr_width}} | {d:<{db_name_width}} | {n:<{name_id_width}}")
            print(sep)

        if not self.sm.name_details:
            print("\n(use set name_details True to see NAME decodes)")
        
        print("\nNote: Run active_scan to attempt to fill-out unknown NAME fields.")

    def do_passive_scan(self, arg):
        """
        Passively scan the bus to find ECUs and store them in the list of discovered ecus.
        """
        print("scanning...")
        self.devil.start_data_collection()
        time.sleep(self.sm.scan_interval)
        messages = self.devil.stop_data_collection()
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
        self.devil.start_data_collection()
        rqst = J1939Message(can_id=0x18EA0000, data="00EE00")
        for addr in range(0, 256):
            rqst.pdu_specific = addr
            self.devil.send_message(rqst)
        time.sleep(5)  # Give ecus 5 seconds to respond
        messages = self.devil.stop_data_collection()
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

    def do_signal_summary(self, arg):
        """
        Run traffic capture and print a formatted signal summary.
        Available only when pretty-j1939 is installed.
        """
        from truckdevil.libs.pretty_shim import PRETTY_AVAILABLE
        if not PRETTY_AVAILABLE:
            print("signal_summary requires pretty-j1939 to be installed.")
            return

        interval = self.sm.scan_interval
        print(f"Capturing traffic for {interval} seconds...")
        self.devil.start_data_collection()
        # The capture is processed by the pretty_shim because J1939Interface 
        # feeds messages to it during data collection if configured, 
        # or we might need to feed them manually if it's not.
        
        # Looking at J1939Interface.start_data_collection in truckdevil/j1939/j1939.py...
        time.sleep(interval)
        messages = self.devil.stop_data_collection()
        
        # We need to ensure the messages were described by the shim's describer.
        # J1939Interface._collection_loop usually doesn't call the describer.
        # It's usually called during print_messages or similar.
        # Let's manually feed the collected messages to the describer if needed.
        
        import io
        import contextlib

        # We suppress stdout and stderr here to capture any stray output from the pretty-j1939 
        # library while we feed it messages to build the summary.
        f = io.StringIO()
        with contextlib.redirect_stdout(f), contextlib.redirect_stderr(io.StringIO()):
            for m in messages:
                try:
                    self.devil.pretty_shim.get_pretty_output(m)
                except Exception:
                    continue
        
        captured_output = f.getvalue()

        self.devil.pretty_shim.print_summary()
        # If the library printed a summary during the loop, our print_summary 
        # should have handled it (it checks get_summary()).
        print("\nNote: This summary can be rendered as a Mermaid diagram.")

    def do_find_boot_msg(self, arg):  # noqa: C901
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
            if val == "q" or val == "quit":
                return
            if val != "y" and val != "yes":
                print("input not recognized.")
                continue
            break
        print("waiting for messages to stop transmitting...")
        while self.devil.read_one_message(timeout=0.5) is not None:
            continue
        self.devil.start_data_collection()
        while True:
            val = input("please power on the ECU, enter y when done or q to quit: ")
            if val == "q" or val == "quit":
                self.devil.stop_data_collection()
            if val != "y" and val != "yes":
                print("input not recognized.")
                continue
            break
        messages = self.devil.stop_data_collection()
        reboot_message = None
        for m in messages:
            if m.src_addr == address:
                reboot_message = m
                break
        if reboot_message is None:
            print("no messages detected for ECU {}.".format(format_ecu_address(address)))
        else:
            print("reboot message for ECU {}: \n{}".format(format_ecu_address(address), reboot_message))

    def do_find_proprietary(self, arg):  # noqa: C901
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
        self.devil.start_data_collection()
        rqst = J1939Message(can_id=0x18EA0000, data="")
        rqst.pdu_specific = address
        prop_range = []
        for i in range(0, 256):
            prop_range.append("{0:02x}EF00".format(i))
            prop_range.append("{0:02x}FF00".format(i))
        for data in prop_range:
            rqst.data = data
            self.devil.send_message(rqst)
        time.sleep(10)
        messages = self.devil.stop_data_collection()
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
        if e is None:
            print("no proprietary messages found for address {}.".format(format_ecu_address(address)))
            return
        discovered = len(e.prop_messages) - num_prop_messages
        if discovered > 0:
            print("discovered {} new unique proprietary messages.".format(discovered))
        else:
            print("no additional proprietary messages found.")
        if len(e.prop_messages) > 0:
            print("Proprietary messages for address {}:".format(format_ecu_address(address)))
            for p in e.prop_messages:
                print(p)

    def do_find_uds(self, arg):  # noqa: C901
        """
        Scan for ECUs that support UDS (Unified Diagnostic Services).
        Supports scanning ranges of destination addresses, source addresses, and priorities.

        usage: find_uds [dst=<range>] [src=<range>] [pri=<range>]

        Defaults:
            dst: All discovered ECUs (see active_scan)
            src: 0xf1, 0xf2
            pri: 0x18 (Priority 6)

        Ranges can be:
            Single value: 0x11
            Dash range: 0x11-0x20
            Comma list: 0x11,0x12,0x15

        Example:
            find_uds dst=0x11 src=0xf1-0xf2 pri=0x18,0x1c
        """
        def parse_range(range_str):
            if not range_str:
                return []
            try:
                if "," in range_str:
                    return [input_to_int(x.strip()) for x in range_str.split(",")]
                if "-" in range_str:
                    parts = range_str.split("-")
                    if len(parts) == 2:
                        start, end = parts
                        return list(range(input_to_int(start), input_to_int(end) + 1))
                return [input_to_int(range_str)]
            except ValueError:
                return []

        dst_list = self.ed.get_all_addresses()
        src_list = [0xf1, 0xf2]
        pri_list = [0x18]  # Default to 0x18 (Pri 6, RB 0, DP 0)

        argv = shlex.split(arg)
        if len(argv) > 0:
            # Backward compatibility: if first arg is just an address and not a key=value
            if "=" not in argv[0]:
                dst_list = [input_to_int(argv[0])]
                argv = argv[1:]

            for a in argv:
                if a.startswith("dst="):
                    dst_list = parse_range(a[4:])
                elif a.startswith("src="):
                    src_list = parse_range(a[4:])
                elif a.startswith("pri="):
                    pri_list = parse_range(a[4:])

        if not dst_list:
            print("No destination addresses provided and none discovered. See 'active_scan' or provide 'dst='.")
            return

        print(f"Scanning UDS on destinations {dst_list} from sources {src_list} with priorities {pri_list}...")

        uds_pdu_formats = [0xDA, 0xDB, 0xCD, 0xCE, 0xEF]
        uds_discovery_requests = ["023E00FFFFFFFF", "023E01FFFFFFFF", "013EFFFFFFFFFF", "021001FFFFFFFF"]

        self.devil.start_data_collection()
        messages = []
        try:
            total_msgs = len(dst_list) * len(src_list) * len(pri_list) * len(uds_pdu_formats) * len(uds_discovery_requests)
            sent_count = 0

            for dst in dst_list:
                for src in src_list:
                    for pri_val in pri_list:
                        priority = (pri_val >> 2) & 0x07
                        reserved = (pri_val >> 1) & 0x01
                        data_page = pri_val & 0x01

                        for f in uds_pdu_formats:
                            for req in uds_discovery_requests:
                                msg = J1939Message(0, req)
                                msg.src_addr = src
                                msg.pdu_specific = dst
                                msg.pdu_format = f
                                msg.priority = priority
                                msg.reserved_bit = reserved
                                msg.data_page_bit = data_page

                                self.devil.send_message(msg)
                                sent_count += 1
                                if sent_count % 10 == 0:
                                    print(f"Sent {sent_count}/{total_msgs} requests...")

            print(f"\nSent {sent_count} requests. Waiting for responses...")
            time.sleep(2)
        finally:
            messages = self.devil.stop_data_collection()

        uniq_responses = {} # key: (dst_addr, pdu_format) -> value: {srcs: set, pris: set}
        for m in messages:
            # Check if it's a response to one of our requests
            # Destination of response should be one of our sources
            if m.pdu_specific in src_list:
                # Format should be one of the UDS formats
                if m.pdu_format in uds_pdu_formats:
                    data = m.data
                    # Treat 7E PR, 50 PR, 7F NR, and 0xEF with 027E as confirmation
                    is_uds_pr = len(data) >= 4 and (data[2:4] == "7E" or data[2:4] == "50")
                    is_uds_nr = len(data) >= 6 and data[2:4] == "7F"
                    is_uds_ef = m.pdu_format == 0xEF and "027E" in data

                    if is_uds_pr or is_uds_nr or is_uds_ef:
                        key = (m.src_addr, m.pdu_format)
                        if key not in uniq_responses:
                            uniq_responses[key] = {"srcs": set(), "pris": set()}
                        # The working src/pri for THIS endpoint was the pdu_specific/priority of our request
                        # but we don't have the original request here easily.
                        # Wait, the response m.pdu_specific IS the src_addr we used in the request.
                        # The response m.priority IS likely the same priority as the request.
                        uniq_responses[key]["srcs"].add(m.pdu_specific)
                        uniq_responses[key]["pris"].add(m.priority)

        if not uniq_responses:
            print("No UDS responses detected.")
        else:
            import textwrap
            from j1939.j1939 import j1939_fields_to_can_id

            def format_range(s):
                if not s: return "-"
                l = sorted(list(s))
                if len(l) <= 3:
                    return ", ".join([f"0x{x:02x}" for x in l])
                return f"0x{l[0]:02x}-0x{l[-1]:02x}"

            # Table configuration
            max_width = 110
            addr_width = 8
            fmt_width = 6
            srcs_width = 15
            pris_width = 10
            ids_width = max_width - (addr_width + fmt_width + srcs_width + pris_width) - 12

            header = f"{'Target':<{addr_width}} | {'Fmt':<{fmt_width}} | {'Working Srcs':<{srcs_width}} | {'Pris':<{pris_width}} | {'Suggested Send/Recv IDs'}"
            sep = "-" * max_width
            print("\nDiscovered UDS-capable endpoints:")
            print(sep)
            print(header)
            print(sep)

            for (addr, fmt), info in uniq_responses.items():
                src_str = format_range(info["srcs"])
                pri_str = format_range(info["pris"])
                
                # Suggest IDs
                # We pick the first working src and priority
                best_src = sorted(list(info["srcs"]))[0]
                best_pri = sorted(list(info["pris"]))[0]
                
                # Request: Pri=best_pri, Res=0, DP=0, PF=fmt, PS=addr, SA=best_src
                req_id = j1939_fields_to_can_id(best_pri, 0, 0, fmt, addr, best_src)
                # Response: Pri=best_pri, Res=0, DP=0, PF=fmt, PS=best_src, SA=addr
                res_id = j1939_fields_to_can_id(best_pri, 0, 0, fmt, best_src, addr)
                
                ids_str = f"S: 0x{req_id:08X} / R: 0x{res_id:08X}"
                
                # Wrapping
                addr_wrapped = textwrap.wrap(f"0x{addr:02x}", width=addr_width)
                fmt_wrapped = textwrap.wrap(f"0x{fmt:02x}", width=fmt_width)
                srcs_wrapped = textwrap.wrap(src_str, width=srcs_width)
                pris_wrapped = textwrap.wrap(pri_str, width=pris_width)
                ids_wrapped = textwrap.wrap(ids_str, width=ids_width)

                num_lines = max(len(addr_wrapped), len(fmt_wrapped), len(srcs_wrapped), len(pris_wrapped), len(ids_wrapped))
                for i in range(num_lines):
                    a = addr_wrapped[i] if i < len(addr_wrapped) else ""
                    f = fmt_wrapped[i] if i < len(fmt_wrapped) else ""
                    s = srcs_wrapped[i] if i < len(srcs_wrapped) else ""
                    p = pris_wrapped[i] if i < len(pris_wrapped) else ""
                    d = ids_wrapped[i] if i < len(ids_wrapped) else ""
                    print(f"{a:<{addr_width}} | {f:<{fmt_width}} | {s:<{srcs_width}} | {p:<{pris_width}} | {d}")
                print(sep)

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
        print("requesting {} from {}...".format(pgn, format_ecu_address(address)))
        pgn_data = "{0:06x}".format(pgn)
        pgn_data = pgn_data[4:6] + pgn_data[2:4] + pgn_data[0:2]
        self.devil.start_data_collection()
        rqst = J1939Message(can_id=0x18EA0000, data=pgn_data)
        rqst.pdu_specific = address
        self.devil.send_message(rqst)
        time.sleep(5)
        messages = self.devil.stop_data_collection()
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

    def do_back(self, arg=None):
        """
        Return to the main menu
        """
        return True

    def complete_save(self, text, line, begidx, endidx):
        import glob as g

        if not text:
            return g.glob("*")
        return g.glob(text + "*")

    def complete_load(self, text, line, begidx, endidx):
        return self.complete_save(text, line, begidx, endidx)


def main_mod(argv, device):
    if device is None:
        print("add device first.")
        return
    dcli = DiscoveryCommands(device)
    if len(argv) > 0:
        dcli.run_commands(argv)
    else:
        dcli.cmdloop()
