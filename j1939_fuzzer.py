import argparse
import cmd
import time
import random
import threading, queue
import multiprocessing
from ctypes import c_bool
import copy
import sys

import truckDevil as td

from TruckDevil.settings import SettingsManager, Setting


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

            if isinstance(value, str) and value.startswith("0x"):
                value = int(value, 16)

            if isinstance(value, int):
                if 0 <= value <= 65535:
                    self.__reboot_pgn = value
                else:
                    print("Valid reboot_pgn values are between 0 and 65535")

        def has_user_set_reboot_pgn(self):
            if self.__reboot_pgn is None:
                return False
            return True

        @property
        def reboot_data_snip(self):
            return self.__reboot_data_snip

        @reboot_data_snip.setter
        def reboot_data_snip(self, value):
            if isinstance(value, str) and value.startswith("0x"):
                self.__reboot_data_snip = value

        def has_user_set_reboot_data_snip(self):
            if self.__reboot_data_snip is None:
                return False
            return True


    def __init__(self, devil):
        self.targets = []  # Each target should have an optional field to specify what message is sent from the ECU

        self.baseline = []
        self.baseline_messages = []
        self.test_cases = []

        self.devil = devil
        self.done_fuzzing = False
        self.pause_fuzzing = False
        self.fuzzed_messages = []
        self.lock_fuzzed_messages = threading.RLock()

        self.sm = SettingsManager()
        sl = [
            # TODO: change default to 60
            Setting("baseline_time", 10).add_constraint("minimum", lambda x: 10 <= x)
                .add_description("the amount of time to record the baseline for, in seconds."),

            Setting("check_frequency", 20).add_constraint("minimum", lambda x: 1 <= x)
                .add_description("how long to wait between analysing for anomalies, in seconds."),

            Setting("num_messages", 5000).add_constraint("minimum", lambda x: 1 <= x)
                .add_description("number of test cases to generate"),

            Setting("message_frequency", 0.5).add_constraint("minimum", lambda x: 0.0 <= x)
                .add_description("the amount of time to wait between sending each fuzzed message, in seconds."),

            Setting("mode", 0).add_constraint("allowed_states", lambda x: 0 <= x <= 2)
                .add_description("There are 3 modes: mutational (0), generational (1), mutational/generational (2). "),

            Setting("test_case_priority", 0).add_constraint("range", lambda x: 0 <= x <= 7)
                .add_description("Priority set for each test case."),

            Setting("mutate_priority", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Should the generator mutate the test case priority field?"),

            Setting("test_case_pgn", 0).add_constraint("range", lambda x: 0 <= x <= 65535)
                .add_description("PGN value set on each test case"),

            Setting("mutate_pgn", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Should the generator mutate the test case pgn?"),

            Setting("test_case_src_address", 0).add_constraint("range", lambda x: 0 <= x <= 255)
                .add_description("Source address to set for each test case"),

            Setting("mutate_src_address", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Should the generator mutate the source address?"),

            Setting("test_case_data", "")
                .add_constraint("max_length", lambda x: len(x) <= (2 * 1785))
                .add_constraint("even_bytes", lambda x: len(x) % 2 == 0)
                .add_description("Data to be set for the test case"),

            Setting("mutate_data", False).add_constraint("boolean", lambda x: type(x) is bool)
                .add_description("Should the generator mutate the data field?"),

            Setting("diff_tolerance", 5).add_constraint("minimum", lambda x: 0 <= x)
                .add_description(
                         "the acceptable difference in the volume of messages between the "
                         "baseline and the current interval to determine if a crash has occurred. "
                         "A percentage value is expected."),
        ]

        for setting in sl:
            self.sm.add_setting(setting)

    '''
    given a J1939_Message, mutate different parts of it randomly depending on the arguments
    message: required, this is the starting message that will be mutated
    mutate_priority: if true, modify priority to a random value between 0-7
    mutate_src_addr: if true, modify src_addr to a random value between 0-255
    mutate_dst_addr: if true, modify dst_addr to a random value between 0-255
    mutate_pgn: if true, modify the pgn to a random value depending on the value of dst_addr.
                if the dst_addr is 0xFF, make pgn random value of 0-65535
                if the dst_addr is <0xFF, make pgn random value of 0-61439 (only modifying the first byte, second byte will be 0x00)
    mutate_data: if true, mutates a random number of bytes to random values between 0-255. Keeps data length the same.
    returns the mutated message
    '''

    def mutate(self, message, mutate_priority=False, mutate_src_addr=False, mutate_dst_addr=False, mutate_pgn=False,
               mutate_data=False, mutate_data_length=False):
        if mutate_priority:
            pri = random.randint(0, 7)
            message.priority = pri
        if mutate_src_addr:
            message.src_addr = random.randint(0, 255)
        if mutate_dst_addr:
            message.dst_addr = random.randint(0, 255)
        if mutate_pgn:
            if message.dst_addr == 255:
                val = random.randint(0, 65535)  # include destination specific and broadcast PGNs
            else:
                val = random.randint(0, 61439)  # only include destination specific PGNs

            if val < 61440:  # if in the destination specific range
                val = val & 0xFF00  # only use the first byte
            message.pgn = val
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

    '''
    Generate and return a J1939_Message based on optional parameters.
    priority: optional int, if not given then generate a random one between 0-7
    pgn: optional int, if not given then generate a random one between 0-65535
    dst_addr: optional int, if not given then generate a random one between 0-255
    src_addr: optional int, if not given then generate a random one between 0-255
    data: optional hex string, if not given then generate a hex string based on one of three options
    option: optional int (1-3), if not given then generate a random option between 1-3
            1) generate data based on the pgn, data length and format matching the specified pgn
               in this case, all of the data within will be generated based on acceptable ranges
               for example, if field is 1 byte long, it will be between 0-255 (even if operationally it only allows 0-200)
            2) generate data randomly based on data length of specified pgn
            3) generate random data length and random data
    '''

    def generate(self, priority=random.randint(0, 7), pgn=None, dst_addr=random.randint(0, 255),
                 src_addr=random.randint(0, 255), data=None, option=None):
        if pgn is None:
            if dst_addr == 255:
                pgn = random.randint(0, 65535)  # include destination specific and broadcast PGNs
            else:
                pgn = random.randint(0, 61439)  # only include destination specific PGNs

        if pgn <= 255:  # pgn is only 2 hex digits
            pgn = 0
        elif 255 < pgn <= 4095:  # pgn is only 3 hex digits
            pgn = pgn & 0xF00  # only use the first nibble
        elif 4095 < pgn < 61440:  # if in the destination specific range
            pgn = pgn & 0xFF00  # only use the first byte
        if data is None:
            if option is None or 3 < option < 1:
                option = random.randint(1, 3)
            if option == 1:
                data = ''
                try:
                    pgn_info = self.devil._pgn_list[str(pgn)]
                    if isinstance(pgn_info['pgnDataLength'], int):
                        data_len = pgn_info['pgnDataLength']
                    else:
                        raise KeyError
                    spn_list = pgn_info['spnList']
                    bin_data = ''
                    used_bits = 0
                    for spn in spn_list:
                        spn_info = self.devil._spn_list[str(spn)]
                        if isinstance(spn_info['spnLength'], int):
                            spn_length = spn_info['spnLength']  # number of bits
                        else:
                            raise KeyError  # length is variable
                        max_val = (2 ** spn_length) - 1  # maximum int value for x number of bits (ex: 255 for 8 bits)

                        val = random.randint(0, max_val)
                        bin_val = bin(val)[2:].zfill(spn_length)
                        filler = (spn_info['bitPositionStart'] - used_bits) * '1'
                        bin_data = bin_val + filler + bin_data
                        used_bits += spn_length
                        used_bits += len(filler)
                    bits_left = (data_len * 8 - used_bits) * '1'
                    if len(bits_left) > 0:
                        data = (hex(int(bits_left + bin_data, 2))[2:]).upper()
                    else:
                        data = (hex(int(bin_data, 2))[2:].zfill(int(len(bin_data) / 4))).upper()

                except KeyError:
                    option = 2
            if option == 2:
                try:
                    pgn_info = self.devil._pgn_list[str(pgn)]
                    if isinstance(pgn_info['pgnDataLength'], int):
                        data_len = pgn_info['pgnDataLength']  # number of bytes to generate is based on data length
                        # specified in pgn
                    else:
                        data_len = random.randint(0, 1785)  # number of bytes to generate is random if pgn exists but
                        # the length is variable
                except KeyError:
                    data_len = random.randint(0, 1785)  # number of bytes to generate is random if pgn does not exist
                data = ''
                for i in range(0, data_len):
                    data_byte = hex(random.randint(0, 255))[2:].zfill(2)
                    data += data_byte
            if option == 3:
                data_len = random.randint(0, 1785)  # number of bytes to generate
                data = ''
                for i in range(0, data_len):
                    data_byte = hex(random.randint(0, 255))[2:].zfill(2)
                    data += data_byte
        message = td.J1939_Message(priority, pgn, dst_addr, src_addr, data)
        return message

    '''
    checks for anomalies/differences from the baseline every x seconds, 
    based on check_frequency variable
    '''

    def anomaly_check(self):
        start_time = time.time()
        previous_interval_messages = []
        num_crashes = 0
        while not self.done_fuzzing:
            self.devil._m2.flushInput()
            self.devil.startDataCollection()
            time.sleep(self.check_frequency)
            if self.done_fuzzing:
                break
            incoming_messages = self.devil.stopDataCollection()
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
                            after_fuzz[m.src_addr]['boot_msg_found'] = False
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
                base_per_sec = self.baseline[src]['total_messages'] / self.baseline_time
                curr_per_sec = after_fuzz[src]['total_messages'] / self.check_frequency
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
                    if percent_diff > self.diff_tolerance:
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
                    self.devil.saveDataCollected(previous_interval_messages, filename_previous, False)
                print("    Stored current interval fuzzed messages to: " + filename_current)
                self.devil.saveDataCollected(self.fuzzed_messages, filename_current, False)

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
        for i in range(0, self.num_messages):
            choice = self.mode
            # either mutate or generate
            if choice == 2:
                choice = random.randint(0, 1)
            # mutate a message from the baseline
            if choice == 0:
                mutate_index = random.randint(0, len(self.baseline_messages) - 1)
                m = copy.copy(self.baseline_messages[mutate_index])
                # TODO: make these parameters based on settings
                if self.sm["test_case_priority"].updated:
                    m.priority = self.sm.test_case_priority
                if self.sm["test_case_src_address"].updated:
                    m.src_addr = self.sm.test_case_src_address
                if self.sm["test_case_pgn"].updated:
                    m.pgn = self.sm.test_case_pgn
                if self.sm["test_case_data"].updated:
                    m.data = self.sm.test_case_data
                mutate_dst_address = True
                if len(self.targets) > 0:
                    which = random.randint(0, len(self.targets))
                    target_addr = self.targets[which].address
                    m.dst_addr = target_addr
                    mutate_dst_address = False

                m = self.mutate(m,
                                self.sm.mutate_priority,
                                self.sm.mutate_src_address,
                                mutate_dst_address,
                                self.sm.mutate_pgn,
                                self.sm.mutate_data)

            # generate a message
            elif choice == 1:
                # TODO: make these parameters based on settings
                # (priority=random.randint(0, 7), pgn=None, dst_addr=random.randint(0, 255), src_addr=random.randint(0, 255), data=None, option=None):
                # m = self.generate(self.test_case_priority, self.test_case_pgn, self.)
                m = self.generate(src_addr=0x00, dst_addr=0x0B)
            self.test_cases.append(m)
        return

    def record_baseline(self):
        self.devil._m2.flushInput()
        print("Baselining for " + str(self.sm.baseline_time) + " seconds...")
        self.devil.startDataCollection()
        time.sleep(self.sm.baseline_time)
        self.baseline_messages = self.devil.stopDataCollection()
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


class FuzzerCommands(cmd.Cmd):
    intro = "Welcome to the TruckDevil J1939 Fuzzer."
    prompt = "(truckdevil.fuzz) "

    def __init__(self, devil):
        super().__init__()
        self.fz = J1939Fuzzer(devil)

    def do_settings(self, arg):
        """Show the settings and each setting value"""
        print(self.fz.sm)
        return

    def do_set(self, arg):
        """
        Provide a setting name and a value to set the setting. For a list of
        available settings and their current and default values see the
        settings command.

        example:
        set baseline_time 100

        For list type settings pass a space separated list

        example:
        set testable_pgns one two three
        """
        argv = arg.split()
        name = argv[0]
        if len(argv) == 1:
            print("expected value, see 'help set'")
            return
        try:
            if self.fz.sm[name].datatype == int:
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
                pgn = "not set"
                data_snip = "not set"
                if tgt.has_user_set_reboot_pgn():
                    pgn = tgt.reboot_pgn
                if tgt.has_user_set_reboot_data_snip():
                    data_snip = tgt.reboot_data_snip
                # TODO: has_user_set flags aren't working for target
                print("address: {:<3} pgn: {:<5} data: {}".format(tgt.address, pgn, data_snip))
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
                    for idx, t in enumerate(self.fz.targets):
                        if t.address == addr:
                            tmp = self.fz.targets[:idx]
                            tmp.extend(self.fz.targets[idx + 1:])
                            self.fz.targets = tmp

            except ValueError as e:
                print("error: {}".format(e))
            return

        addr = safe_get(argv, 1, -1)
        pgn = safe_get(argv, 2, None)
        data = safe_get(argv, 3, None)

        if "modify" == argv[0]:
            for idx, t in enumerate(self.fz.targets):
                if t.address == addr:
                    self.fz.targets[idx] = self.fz.Target(addr, pgn, data)
            return

        if "add" == argv[0]:
            try:
                newtgt = self.fz.Target(addr, pgn, data)
            except ValueError as e:
                print("Error: {}".format(e))
                return

            self.fz.targets.append(newtgt)
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
        if len(self.fz.baseline) == 0:
            print("No baseline has been recorded yet. See the record baseline command.")
        print("Recorded {:<6} messages in {:<6} seconds".format(len(self.fz.baseline), self.fz.sm.baseline_time))
        print("Baseline time: {:<6} messages per second".format(len(self.fz.baseline) / self.fz.sm.baseline_time))

    def do_generate_test_cases(self, arg):
        """
        Generate the messages the fuzzer will send during the fuzzing
        """
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
                # TODO: re-enable sending
                # self.fz.devil.sendMessage(m)
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


def main_mod(devil):
    fcli = FuzzerCommands(devil)
    fcli.cmdloop()
