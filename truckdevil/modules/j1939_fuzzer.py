import time
import random
import threading
import copy
import sys
import dill

from j1939.j1939 import J1939Message, J1939Interface, j1939_fields_to_can_id
from libs.command import Command
from libs.settings import SettingsManager, Setting


class J1939Fuzzer:
    class Target:
        def __init__(self, address, reboot_pgn=None, reboot_data_snip=None):

            self.__addr = 0
            self.__reboot_pgn = None
            self.__reboot_data_snip = None

            self.address = address
            if reboot_pgn is not None:
                self.reboot_pgn = reboot_pgn
            if reboot_data_snip is not None:
                self.reboot_data_snip = reboot_data_snip

        @property
        def address(self):
            return self.__addr

        @address.setter
        def address(self, value):
            if isinstance(value, str):
                if value.startswith("0x"):
                    value = int(value, 16)
                else:
                    value = int(value)

            if 0 <= value <= 255:
                self.__addr = value
            else:
                raise ValueError("addresses must be between 0 and 255")
            return

        @property
        def reboot_pgn(self):
            return self.__reboot_pgn

        @reboot_pgn.setter
        def reboot_pgn(self, value):
            if isinstance(value, str):
                if value.startswith("0x"):
                    value = int(value, 16)
                else:
                    value = int(value)
            if 0 <= value <= 65535:
                self.__reboot_pgn = value
            else:
                raise ValueError("Valid reboot_pgn values are between 0 and 65535")

        def has_user_set_reboot_pgn(self):
            if self.__reboot_pgn is None:
                return False
            return True

        @property
        def reboot_data_snip(self):
            return self.__reboot_data_snip

        @reboot_data_snip.setter
        def reboot_data_snip(self, value):
            if value.startswith("0x"):
                value = value.strip("0x")
            if len(value) % 2 != 0 or len(value) > 3570:
                raise ValueError('Length of data must be an even number and shorter than 1785 bytes')
            int(value, 16)  # should raise ValueError if not hexadecimal string
            self.__reboot_data_snip = value

        def has_user_set_reboot_data_snip(self):
            if self.__reboot_data_snip is None:
                return False
            return True

        def __str__(self):
            pgn = "not set"
            data_snip = "not set"
            if self.has_user_set_reboot_pgn():
                pgn = self.reboot_pgn
            if self.has_user_set_reboot_data_snip():
                data_snip = self.reboot_data_snip
            return "address: {:<3} reboot_pgn: {:<5} reboot_data_snip: {}".format(self.address, pgn, data_snip)

    def __init__(self, device):
        self._targets = []  # Each target should have an optional field to specify what message is sent from the ECU

        self.baseline = []
        self.baseline_messages = []
        self.test_cases = []

        self.devil = J1939Interface(device)
        self.done_fuzzing = False
        self.pause_fuzzing = False
        self.fuzzed_messages = []
        self.lock_fuzzed_messages = threading.RLock()

        self.sm = SettingsManager()
        sl = [
            Setting("baseline_time", 60).add_constraint("minimum", lambda x: 10 <= x)
                .add_description("The amount of time to record the baseline for, in seconds."),

            Setting("num_messages", 5000).add_constraint("minimum", lambda x: 1 <= x)
                .add_description("Number of test cases to generate"),

            Setting("mode", 0).add_constraint("allowed_states", lambda x: 0 <= x <= 2)
                .add_description("There are 3 modes to create test cases: 0 - mutational, 1 - generational"
                                 "2 - mutational/generational. "),

            Setting("generate_data_option", 0).add_constraint("allowed_states", lambda x: 0 <= x <= 2)
                .add_description("When performing generational fuzzing, there are 3 options: 0 - Generate test case "
                                 "data based on J1939 standard, 1 - Generate test case data randomly with standard "
                                 "length, 2 - Generate test case data randomly with random length"),

            Setting("check_frequency", 20).add_constraint("minimum", lambda x: 1 <= x)
                .add_description("how long to wait between analysing for anomalies, in seconds."),

            Setting("message_frequency", 0.5).add_constraint("minimum", lambda x: 0.0 <= x)
                .add_description("the amount of time to wait between sending each fuzzed message, in seconds."),

            Setting("diff_tolerance", 5).add_constraint("minimum", lambda x: 0 <= x)
                .add_description(
                "the acceptable difference in the volume of messages between the "
                "baseline and the current interval to determine if a crash has occurred. "
                "A percentage value is expected."),

            Setting("test_case_can_id", 0).add_constraint("range", lambda x: 0 <= x <= 0x1FFFFFFF)
                .add_description("CAN ID set for each test case."),

            Setting("test_case_priority", 0).add_constraint("range", lambda x: 0 <= x <= 7)
                .add_description("Priority set for each test case."),

            Setting("test_case_reserved_bit", 0).add_constraint("range", lambda x: 0 <= x <= 1)
                .add_description("Reserved bit of CAN ID for each test case."),

            Setting("test_case_data_page_bit", 0).add_constraint("range", lambda x: 0 <= x <= 1)
                .add_description("Data page bit of CAN ID for each test case."),

            Setting("test_case_pdu_format", 0).add_constraint("range", lambda x: 0 <= x <= 255)
                .add_description("PDU Format byte for each test case. 0-239 for destination specific, 240+ "
                                 "for broadcast."),

            Setting("test_case_pdu_specific", 0).add_constraint("range", lambda x: 0 <= x <= 255)
                .add_description("PDU Specific byte for each test case. If PDU Format is 0-239, this is the destination"
                                 " address. If PDU Format is 240+, this is extension."),

            Setting("test_case_src_address", 0).add_constraint("range", lambda x: 0 <= x <= 255)
                .add_description("Source address to set for each test case"),

            Setting("test_case_data", "")
                .add_constraint("max_length", lambda x: len(x) <= (2 * 1785))
                .add_constraint("even_bytes", lambda x: len(x) % 2 == 0)
                .add_description("Data to be set for the test case"),

            Setting("mutate_priority", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Should the generator mutate the test case priority field?"),

            Setting("mutate_reserved_bit", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Should the generator mutate the test case reserved bit field?"),

            Setting("mutate_data_page_bit", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Should the generator mutate the test case data page bit field?"),

            Setting("mutate_pdu_format", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Should the generator mutate the test case PDU Format field?"),

            Setting("mutate_pdu_specific", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Should the generator mutate the test case PDU Specific field?"),

            Setting("mutate_src_address", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Should the generator mutate the source address?"),

            Setting("mutate_data", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Should the generator mutate the data field?"),

            Setting("mutate_data_length", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Should the generator mutate the length of the data field?")
        ]

        for setting in sl:
            self.sm.add_setting(setting)



    @property
    def targets(self):
        """
        Get the list of targets

        :return: the targets list
        """
        return self._targets

    @targets.setter
    def targets(self, val: []):
        """
        Set the list of targets
        """
        self._targets = val

    def add_target(self, tgt):
        """
        Add a target object to the targets list, if it doesn't exist

        :param tgt: target object to add to list
        """
        if tgt.address not in [t.address for t in self.targets]:
            self._targets.append(tgt)
            return
        raise ValueError("Target with this address already exists")

    def remove_target(self, address):
        """
        Remove a target object from the targets list

        :param address: Address of target object to remove from list
        """
        if isinstance(address, str):
            if address.startswith("0x"):
                address = int(address, 16)
            else:
                address = int(address)

        for idx, t in enumerate(self._targets):
            if t.address == address:
                tmp = self._targets[:idx]
                tmp.extend(self._targets[idx + 1:])
                self._targets = tmp

    def modify_target(self, address, pgn, data):
        """
        Modify the reboot PGN and data snippet of a target

        :param address: Address of target
        :param pgn: new reboot PGN
        :param data: new reboot data snippet
        """
        if isinstance(address, str):
            if address.startswith("0x"):
                address = int(address, 16)
            else:
                address = int(address)

        for idx, t in enumerate(self._targets):
            if t.address == address:
                self._targets[idx] = self.Target(address, pgn, data)

    def mutate(self, message: J1939Message, mutate_priority=False, mutate_reserved_bit=False,
               mutate_data_page_bit=False, mutate_pdu_format=False, mutate_pdu_specific=False, mutate_src_addr=False,
               mutate_data=False, mutate_data_length=False) -> J1939Message:
        """
        Given a J1939_Message, mutate different parts of it randomly depending on the arguments

        :param message: required, this is the starting message that will be mutated
        :param mutate_priority: if true, modify priority to a random value between 0-7
        :param mutate_reserved_bit: if true, modify reserved bit to either 0 or 1
        :param mutate_data_page_bit: if true, modify data page bit to either 0 or 1
        :param mutate_pdu_format: if true, modify pdu format 50% chance of being 0-239, 50% chance of being 240-255
        :param mutate_pdu_specific: if true, modify pdu specific to random value between 0-255
        :param mutate_src_addr: if true, modify source address to a random value between 0-255
        :param mutate_data: if true, mutates a random number of bytes to random values between 0-255.
        :param mutate_data_length: if true, makes the data either shorter or longer
        :return: the mutated message
        """
        if mutate_priority:
            message.priority = random.randint(0, 7)
        if mutate_reserved_bit:
            message.reserved_bit = random.randint(0, 1)
        if mutate_data_page_bit:
            message.data_page_bit = random.randint(0, 1)
        if mutate_pdu_format:
            destination_specific = random.randint(0, 1)
            if destination_specific:
                message.pdu_format = random.randint(0, 239)
            else:
                message.pdu_format = random.randint(240, 255)
        if mutate_pdu_specific:
            message.pdu_specific = random.randint(0, 255)
        if mutate_src_addr:
            message.src_addr = random.randint(0, 255)
        message_data_bytes = int(len(message.data) / 2)
        if mutate_data and message_data_bytes > 0:
            num_bytes_to_mutate = random.randint(1, message_data_bytes)
            for i in range(0, num_bytes_to_mutate):
                byte_to_mutate = random.randint(0, message_data_bytes - 1)
                data_byte = hex(random.randint(0, 255))[2:].zfill(2)
                message.data = message.data[0:byte_to_mutate * 2] + data_byte + message.data[byte_to_mutate * 2 + 2:]
        if mutate_data_length:
            shorter = random.randint(0, 1)
            if shorter:
                num_bytes = random.randint(0, message_data_bytes - 1)
                message.data = message.data[0:num_bytes * 2]
            else:
                num_bytes_added = random.randint(1, 1785 - message_data_bytes)
                for i in range(0, num_bytes_added + 1):
                    data_byte = hex(random.randint(0, 255))[2:].zfill(2)
                    message.data += data_byte
        return message

    def generate(self, option=0, **test_case_values):
        """
        Generate and return a J1939_Message based on optional parameters.

        :param option: optional int (0-2), if not given then generate a random option between 0-2
            0) generate data based on the pgn, data length and format matching the specified pgn
               in this case, all of the data within will be generated based on acceptable ranges
               for example, if field is 1 byte long, it will be between 0-255 (even if operationally it only allows 0-200)
            1) generate data randomly based on data length of specified pgn
            2) generate random data length and random data
        :param test_case_values:
            See below
        :Keyword Arguments:
            can_id: optional int, if not given then generate the other fields to create the can_id
            priority: optional int, if not given then generate a random one between 0-7
            reserved_bit: optional int, if not given then generate a random one between 0-1
            data_page_bit: optional int, if not given then generate a random one between 0-1
            pdu_format: optional int, if not given then generate a random one between 0-255
            pdu_specific: optional int, if not given then generate a random one between 0-255
            src_addr: optional int, if not given then generate a random one between 0-255
            data: optional hex string, if not given then generate a hex string based on one of three options
        :return: J1939_Message object containing the generated message
        """
        can_id = test_case_values.setdefault("can_id", None)
        if can_id is None:
            priority = test_case_values.setdefault("priority", random.randint(0, 7))
            reserved_bit = test_case_values.setdefault("reserved_bit", random.randint(0, 1))
            data_page_bit = test_case_values.setdefault("data_page_bit", random.randint(0, 1))
            src_addr = test_case_values.setdefault("src_addr", random.randint(0, 255))
            pdu_format = test_case_values.setdefault("pdu_format", None)
            if pdu_format is None:
                destination_specific = random.randint(0, 1)
                if destination_specific:
                    pdu_format = random.randint(0, 239)
                else:
                    pdu_format = random.randint(240, 255)
            pdu_specific = test_case_values.setdefault("pdu_specific", random.randint(0, 255))

            if pdu_format < 240:
                pgn = pdu_format << 8
            else:
                pgn = (pdu_format << 8) + pdu_specific

            can_id = j1939_fields_to_can_id(priority, reserved_bit, data_page_bit, pdu_format, pdu_specific, src_addr)
        else:
            pgn = can_id >> 8 & 0xFFFF
            if pgn < 0xF000:
                pgn = can_id >> 8 & 0xFF00
        if pgn == 60928 and option == 0:
            option = 1

        data = test_case_values.setdefault("data", None)
        if data is None:
            if 2 < option < 0:
                option = random.randint(0, 2)
            if option == 0:
                data = ''
                try:
                    pgn_info = self.devil.pgn_list[str(pgn)]
                    if isinstance(pgn_info['pgnDataLength'], int):
                        data_len = pgn_info['pgnDataLength']
                    else:
                        raise KeyError
                    spn_list = pgn_info['spnList']
                    bin_data = ''
                    used_bits = 0
                    for spn in spn_list:
                        spn_info = self.devil.spn_list[str(spn)]
                        if isinstance(spn_info['spnLength'], int):
                            spn_length = spn_info['spnLength']  # number of bits
                        else:
                            raise KeyError  # length is variable
                        max_val = (2 ** spn_length) - 1  # maximum int value for x number of bits (ex: 255 for 8 bits)

                        val = random.randint(0, max_val)
                        bin_val = bin(val)[2:].zfill(spn_length)
                        bin_data = bin_data + bin_val
                        used_bits += spn_length
                        if spn_info['bitPositionStart'] > used_bits:
                            filler = (spn_info['bitPositionStart'] - used_bits) * '1'
                            bin_data = bin_data + filler
                            used_bits += len(filler)
                    bits_left = (data_len * 8 - used_bits) * '1'
                    if len(bits_left) > 0:
                        data = (hex(int(bin_data + bits_left, 2))[2:].zfill(data_len * 2)).upper()
                    else:
                        data = (hex(int(bin_data, 2))[2:].zfill(int(len(bin_data) / 4))).upper()
                except KeyError:
                    option = 1
            if option == 1:
                try:
                    pgn_info = self.devil.pgn_list[str(pgn)]
                    if isinstance(pgn_info['pgnDataLength'], int):
                        data_len = pgn_info['pgnDataLength']  # number of bytes to generate is based on data length
                        # specified in pgn
                        data = ''
                        for i in range(0, data_len):
                            data_byte = hex(random.randint(0, 255))[2:].zfill(2)
                            data += data_byte
                    else:
                        raise KeyError
                except KeyError:
                    option = 2
            if option == 2:
                long = random.randint(0, 9)
                if long == 9:
                    data_len = random.randint(9, 1785)  # number of bytes to generate
                else:
                    data_len = random.randint(0, 8)  # number of bytes to generate
                data = ''
                for i in range(0, data_len):
                    data_byte = hex(random.randint(0, 255))[2:].zfill(2)
                    data += data_byte
        message = J1939Message(can_id, data)
        return message

    def anomaly_check(self):
        """
        Checks for anomalies/differences from the baseline every x seconds, based on check_frequency variable
        """
        start_time = time.time()
        previous_interval_messages = []
        num_crashes = 0
        while not self.done_fuzzing:
            if self.devil.device.m2_used:
                self.devil.device.flush_m2()
            self.devil.start_data_collection()
            time.sleep(self.sm.check_frequency)
            if self.done_fuzzing:
                break
            incoming_messages = self.devil.stop_data_collection()
            # crash analysis
            any_anomalies = False
            after_fuzz = []
            for x in range(256):
                node = {'total_messages': 0, 'pgns': {}, 'boot_msg_found': False}
                after_fuzz.append(node)
            for m in incoming_messages:
                after_fuzz[m.src_addr]['total_messages'] += 1
                # TODO: maybe get rid of the collection pgns?
                if m.pgn not in after_fuzz[m.src_addr]['pgns']:
                    after_fuzz[m.src_addr]['pgns'][m.pgn] = 1
                else:
                    after_fuzz[m.src_addr]['pgns'][m.pgn] += 1
                if len(self.targets) > 0:
                    for t in self.targets:
                        if t.address == m.src_addr:
                            if t.has_user_set_reboot_pgn() and t.has_user_set_reboot_data_snip():
                                if t.reboot_pgn == m.pgn and t.reboot_data_snip in m.data:
                                    after_fuzz[m.src_addr]['boot_msg_found'] = True
                            elif t.has_user_set_reboot_pgn():
                                if t.reboot_pgn == m.pgn:
                                    after_fuzz[m.src_addr]['boot_msg_found'] = True
                            elif t.has_user_set_reboot_data_snip():
                                if t.reboot_data_snip in m.data:
                                    after_fuzz[m.src_addr]['boot_msg_found'] = True
            addresses = [t.address for t in self.targets] if len(self.targets) != 0 else list(range(0, 256))
            for src in addresses:
                anomaly = False
                message = ""
                base_per_sec = self.baseline[src]['total_messages'] / self.sm.baseline_time
                curr_per_sec = after_fuzz[src]['total_messages'] / self.sm.check_frequency
                if after_fuzz[src]['boot_msg_found']:
                    anomaly = True
                    any_anomalies = True
                    message = "targets reboot message was detected."
                elif curr_per_sec == 0 and base_per_sec != 0:
                    anomaly = True
                    any_anomalies = True
                    message = "The baseline had messages for this node, but this interval did not."
                elif curr_per_sec > 0:
                    percent_diff = ((abs(base_per_sec - curr_per_sec)) / ((base_per_sec + curr_per_sec) / 2)) * 100
                    if percent_diff > self.sm.diff_tolerance:
                        anomaly = True
                        any_anomalies = True
                        message = "Number of messages changed by " + "{:.2f}".format(percent_diff) + "%"
                if anomaly:
                    print("\n    source: " + str(src))
                    print("        interval messages/second: " + str(curr_per_sec))
                    print("        interval pgns sent to: " + str(after_fuzz[src]['pgns']))
                    print("        baseline messages/second: " + str(base_per_sec))
                    print("        baseline pgns sent to: " + str(self.baseline[src]['pgns']))
                    print("        Reason: " + message)

            if any_anomalies:
                self.pause_fuzzing = True
                num_crashes = num_crashes + 1
                filename_previous = "crashReport_" + str(int(start_time)) + "_previous_" + str(num_crashes)
                filename_current = "crashReport_" + str(int(start_time)) + "_current_" + str(num_crashes)
                if len(previous_interval_messages) > 0:
                    print("    Stored previous interval fuzzed messages to: " + filename_previous)
                    self.devil.save_data_collected(previous_interval_messages, filename_previous, False)
                print("    Stored current interval fuzzed messages to: " + filename_current)
                self.devil.save_data_collected(self.fuzzed_messages, filename_current, False)

                val = input("Please restart the ECU. Once complete, enter 'y' to continue / 'q' to quit fuzzing: ")
                if val.lower() == "yes" or val.lower() == "y":
                    self.pause_fuzzing = False
                elif val.lower() == "quit" or val.lower() == "q":
                    self.done_fuzzing = True
                    self.pause_fuzzing = False
                    return
            else:
                with self.lock_fuzzed_messages:
                    previous_interval_messages = copy.copy(self.fuzzed_messages)
                    self.fuzzed_messages.clear()

    def create_fuzz_list(self):
        self.test_cases = []
        for i in range(0, self.sm.num_messages):
            choice = self.sm.mode
            # either mutate or generate
            if choice == 2:
                choice = random.randint(0, 1)
            # mutate a message from the baseline
            if choice == 0:
                mutate_index = random.randint(0, len(self.baseline_messages) - 1)
                m = copy.copy(self.baseline_messages[mutate_index])
                if self.sm["test_case_can_id"].updated:
                    m.can_id = self.sm.test_case_can_id
                else:
                    if self.sm["test_case_priority"].updated:
                        m.priority = self.sm.test_case_priority
                    if self.sm['test_case_reserved_bit'].updated:
                        m.reserved_bit = self.sm.test_case_reserved_bit
                    if self.sm['test_case_data_page_bit'].updated:
                        m.data_page_bit = self.sm.test_case_data_page_bit
                    if self.sm['test_case_pdu_format'].updated:
                        m.pdu_format = self.sm.test_case_pdu_format
                    if self.sm['test_case_pdu_specific'].updated:
                        m.pdu_specific = self.sm.test_case_pdu_specific
                    if self.sm["test_case_src_address"].updated:
                        m.src_addr = self.sm.test_case_src_address
                if self.sm["test_case_data"].updated:
                    m.data = self.sm.test_case_data
                # mutate_pdu_specific = True
                # if len(self.targets) > 0:
                #    which = random.randint(0, len(self.targets) - 1)
                #    target_addr = self.targets[which].address
                #    m.dst_addr = target_addr
                #    mutate_pdu_specific = False

                m = self.mutate(m,
                                self.sm.mutate_priority,
                                self.sm.mutate_reserved_bit,
                                self.sm.mutate_data_page_bit,
                                self.sm.mutate_pdu_format,
                                self.sm.mutate_pdu_specific,
                                self.sm.mutate_src_address,
                                self.sm.mutate_data,
                                self.sm.mutate_data_length)

            # generate a message
            elif choice == 1:
                test_case_values = {}
                if self.sm["test_case_can_id"].updated:
                    test_case_values["can_id"] = self.sm.test_case_can_id
                else:
                    if self.sm["test_case_priority"].updated:
                        test_case_values["priority"] = self.sm.test_case_priority
                    if self.sm["test_case_reserved_bit"].updated:
                        test_case_values["reserved_bit"] = self.sm.test_case_reserved_bit
                    if self.sm["test_case_data_page_bit"].updated:
                        test_case_values["data_page_bit"] = self.sm.test_case_data_page_bit
                    if self.sm["test_case_pdu_format"].updated:
                        test_case_values["pdu_format"] = self.sm.test_case_pdu_format
                    if self.sm["test_case_pdu_specific"].updated:
                        test_case_values["pdu_specific"] = self.sm.test_case_pdu_specific
                    if self.sm["test_case_src_address"].updated:
                        test_case_values["src_addr"] = self.sm.test_case_src_address
                if self.sm["test_case_data"].updated:
                    test_case_values["data"] = self.sm.test_case_data
                #if len(self.targets) > 0:
                #    which = random.randint(0, len(self.targets) - 1)
                #    test_case_values["dst_addr"] = self.targets[which].address
                m = self.generate(option=self.sm.generate_data_option, **test_case_values)
            self.test_cases.append(m)
        return

    def record_baseline(self):
        if self.devil.device.m2_used:
            self.devil.device.flush_m2()
        print("Baselining for " + str(self.sm.baseline_time) + " seconds...")
        self.devil.start_data_collection()
        time.sleep(self.sm.baseline_time)
        self.baseline_messages = self.devil.stop_data_collection()
        if len(self.baseline_messages) == 0:
            return []

        self.baseline = []
        for i in range(256):
            node = {'total_messages': 0, 'pgns': {}}
            self.baseline.append(node)
        for m in self.baseline_messages:
            self.baseline[m.src_addr]['total_messages'] += 1
            if m.pgn not in self.baseline[m.src_addr]['pgns']:
                self.baseline[m.src_addr]['pgns'][m.pgn] = 1
            else:
                self.baseline[m.src_addr]['pgns'][m.pgn] += 1
        print("Baselining complete.")


# https://stackoverflow.com/questions/3160699/python-progress-bar/34482761#34482761
def progressbar(it, prefix="", size=60, file=sys.stdout):
    count = len(it)

    def show(j):
        x = int(size * j / count)
        file.write("%s[%s%s] %i/%i\r" % (prefix, "#" * x, "." * (size - x), j, count))
        file.flush()

    show(0)
    for i, item in enumerate(it):
        yield item
        show(i + 1)
    file.write("\n")
    file.flush()


class FuzzerCommands(Command):
    # TODO: add save and load commands to save/load settings/test cases/baseline/targets
    intro = "Welcome to the truckdevil J1939 Fuzzer."
    prompt = "(truckdevil.j1939_fuzzer) "

    def __init__(self, device):
        super().__init__()
        self.fz = J1939Fuzzer(device)

    def do_settings(self, arg):
        """Show the settings and each setting value"""
        print(self.fz.sm)
        return

    def do_save(self, arg):
        """
        Save settings, targets, generated test cases, baseline, or all information to a file.

        usage: save <(all, fuzz_settings, targets, test_cases, baseline)> <file_name>

        Verbs:
            all             Saves settings, targets, test_cases, and baseline info
            fuzz_settings   Saves all current settings
            targets         Saves list of targets
            test_cases      Saves list of generated test cases
            baseline        Saves the baseline information for all nodes
        """
        argv = arg.split()
        if len(argv) < 2:
            print("expected selection and file name, see 'help save'")
            return
        selection = argv[0]
        file_name = argv[1]
        try:
            f = open(file_name, "xb")
        except FileExistsError:
            print("file already exists")
            return
        if selection == "all":
            fz = copy.copy(self.fz)
            fz.devil = None
            dill.dump(fz, f)
            print("everything saved to {}".format(file_name))
        elif selection == "fuzz_settings":
            dill.dump(self.fz.sm, f)
            print("settings saved to {}".format(file_name))
        elif selection == "targets":
            dill.dump(self.fz.targets, f)
            print("targets saved to {}".format(file_name))
        elif selection == "test_cases":
            dill.dump(self.fz.test_cases, f)
            print("test cases saved to {}".format(file_name))
        elif selection == "baseline":
            dill.dump([self.fz.sm.baseline_time, self.fz.baseline, self.fz.baseline_messages], f)
            print("baseline data saved to {}".format(file_name))

    def do_load(self, arg):
        """
        Load settings, targets, generated test cases, baseline, or all information from a file.

        usage: load <(all, fuzz_settings, targets, test_cases, baseline)> <file_name>

        Verbs:
            all             Loads settings, targets, test_cases, and baseline info
            fuzz_settings   Loads all current settings
            targets         Loads list of targets
            test_cases      Loads list of generated test cases
            baseline        Loads the baseline information for all nodes
        """
        argv = arg.split()
        if len(argv) < 2:
            print("expected selection and file name, see 'help save'")
            return
        selection = argv[0]
        file_name = argv[1]
        f = open(file_name, "rb")
        if selection == "all":
            tmp_devil = self.fz.devil
            self.fz = dill.load(f)
            self.fz.devil = tmp_devil
            print("everything loaded from {}".format(file_name))
        elif selection == "fuzz_settings":
            self.fz.sm = dill.load(f)
            print("settings loaded from {}".format(file_name))
        elif selection == "targets":
            self.fz.targets = dill.load(f)
            print("targets loaded from {}".format(file_name))
        elif selection == "test_cases":
            self.fz.test_cases = dill.load(f)
            print("test cases loaded from {}".format(file_name))
        elif selection == "baseline":
            baseline_info = dill.load(f)
            self.fz.sm.set("baseline_time", int(baseline_info[0]))
            self.fz.baseline = baseline_info[1]
            self.fz.baseline_messages = baseline_info[2]
            print("baseline data loaded from {}".format(file_name))

    def do_set(self, arg):
        """
        Provide a setting name and a value to set the setting. For a list of
        available settings and their current and default values see the
        settings command.

        example:
        set baseline_time 100
        """
        argv = arg.split()
        name = argv[0]
        if len(argv) == 1:
            print("expected value, see 'help set'")
            return
        try:
            if self.fz.sm[name].datatype == int:
                if argv[1].startswith("0x"):
                    self.fz.sm.set(name, int(argv[1], 16))
                else:
                    self.fz.sm.set(name, int(argv[1]))
            elif self.fz.sm[name].datatype == float:
                self.fz.sm.set(name, float(argv[1]))
            elif self.fz.sm[name].datatype == bool:
                if argv[1] in ["True", "true", "on", 1]:
                    self.fz.sm.set(name, True)
                elif argv[1] in ["False", "false", "off", 0]:
                    self.fz.sm.set(name, False)
                else:
                    self.fz.sm.set(name, argv[1])
            else:
                self.fz.sm.set(name, argv[1])
        except ValueError as e:
            print("Could not set: {}".format(e))
        return

    def do_target(self, arg):
        """
        Add, remove, clear, and modify targets

        usage: target <(add, modify, remove)> <address> [PGN [REBOOTDATA]]

        Verbs:
            add         Adds a new target to the end of the list
            modify      Change an existing target
            remove      Delete a target from the list
            list        Show a list of the current targets
            clear       Empty the list of targets out

        Arguments:
            address     An address for the target [0..255]
            PGN         Paramater Group Number (PGN)
            REBOOTDATA  Message the ECU returns when it reboots


        examples:
        target add 231 60928 0x1122AABB
        target list
        target modify 231 66425 0x0
        target remove 231
        target clear
        """
        argv = arg.split()

        def safe_get(vec, index, default):
            try:
                rval = vec[index]
            except:
                return default
            return rval

        tgtcmd = safe_get(argv, 0, None)
        if tgtcmd is None or tgtcmd == "list":
            for tgt in self.fz.targets:
                print(tgt)
            return

        if "clear" == argv[0]:
            self.fz.targets.clear()
            return

        if len(argv) <= 1:
            print("address expected:\n"
                  "\tusage: target <(add, modify, remove)> <address> [PGN [REBOOTDATA]]")
            return

        if "remove" == argv[0]:
            try:
                for addr in argv[1:]:
                    addr = int(addr)
                    self.fz.remove_target(addr)
            except ValueError as e:
                print("error: {}".format(e))
            return

        addr = safe_get(argv, 1, -1)
        pgn = safe_get(argv, 2, None)
        data = safe_get(argv, 3, None)

        if "modify" == argv[0]:
            self.fz.modify_target(addr, pgn, data)
            return

        if "add" == argv[0]:
            try:
                newtgt = self.fz.Target(addr, pgn, data)
            except ValueError as e:
                print("Error: {}".format(e))
                return

            self.fz.add_target(newtgt)
            return

        print("unrecognized command: {}".format(argv[0]))
        return

    def do_record_baseline(self, arg):
        """
        Record a baseline for fuzzing against
        """
        self.fz.record_baseline()
        if len(self.fz.baseline) == 0:
            print("No messages detected during baseline.")
        return

    def do_show_baseline(self, arg):
        """
        Show the baseline results
        """
        if len(self.fz.baseline_messages) == 0:
            print("No baseline has been recorded yet. See the record_baseline command.")
        print(
            "Recorded {:<6} messages in {:<6} seconds".format(len(self.fz.baseline_messages), self.fz.sm.baseline_time))
        print("Baseline time: {:<6} messages per second".format(
            len(self.fz.baseline_messages) / self.fz.sm.baseline_time))

    def do_generate_test_cases(self, arg):
        """
        Generate the messages the fuzzer will send during the fuzzing
        """
        if len(self.fz.baseline) == 0 and (self.fz.sm.mode != 1):
            print("No baseline recorded yet. See 'help record_baseline'")
            return
        print("Creating " + str(self.fz.sm.num_messages) + " messages to fuzz...")
        self.fz.create_fuzz_list()
        return

    def do_start_fuzzer(self, arg):
        """
        Start the fuzzer
        """
        if len(self.fz.baseline) == 0:
            print("No baseline recorded yet. See 'help record_baseline'")
            return
        if len(self.fz.test_cases) == 0:
            print("No test cases generated yet. See 'help generate_test_cases'")
            return

        self.fz.done_fuzzing = False
        self.fz.pause_fuzzing = False
        self.fz.fuzzed_messages = []
        self.fz.lock_fuzzed_messages = threading.RLock()

        anomaly_check_thread = threading.Thread(target=self.fz.anomaly_check, daemon=False)
        anomaly_check_thread.start()

        try:
            for i in progressbar(range(self.fz.sm.num_messages), "Sending: ", 40):
                m = self.fz.test_cases[i]
                self.fz.devil.send_message(m, tp_dst_addr=0)
                with self.fz.lock_fuzzed_messages:
                    self.fz.fuzzed_messages.append(m)
                time.sleep(self.fz.sm.message_frequency)
                while self.fz.pause_fuzzing:
                    time.sleep(1)
                if self.fz.done_fuzzing:
                    break
            self.fz.done_fuzzing = True
        except KeyboardInterrupt:
            self.fz.done_fuzzing = True

        return

    @staticmethod
    def do_back(self, arg=None):
        """
        Return to the main menu
        """
        return True

    @staticmethod
    def do_EOF(self, arg=None):
        """
        Following a ctrl-d quit the whole program
        """
        sys.exit(0)


def main_mod(argv, device):
    fcli = FuzzerCommands(device)
    if len(argv) > 0:
        fcli.run_commands(argv)
    else:
        fcli.cmdloop()
