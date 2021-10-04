import time
import random
import threading, queue
import multiprocessing
from ctypes import c_bool
import copy
import sys

import truckDevil as td


class J1939Fuzzer:
    def __init__(self, devil):
        # how long to record messages on the BUS for
        self.baseline_time = 20
        # analyze every X seconds
        self.check_frequency = 20
        # how many messages to send during fuzzing
        self.num_messages = 5000
        # time to sleep between sending messages
        self.message_frequency = 0.5
        # 0 = mutate, 1 = generate, or 2 = mutate/generate
        self.mode = 0
        # percent
        self.diff_tolerance = 5
        self.targets = []  # Each target should have an optional field to specify what message is sent from the ECU
        # after restarting, default is Address Claimed message
        self.testable_pgns = []

        self.baseline = []
        self.baseline_messages = []

        self.devil = devil
        self.done_fuzzing = False
        self.pause_fuzzing = False
        self.fuzzed_messages = []
        self.lock_fuzzed_messages = threading.RLock()

        self.modifiable = {'btime': 'baseline_time', 'afreq': 'check_frequency', 'sfreq': 'message_frequency',
                           'mode': 'mode', 'tolerance': 'diff_tolerance', 'msgtotal': 'num_messages',
                           'pgns': 'testable_pgns'}

    def save_setting(self, setting, value):
        set_field = True
        if self.modifiable[setting]:
            if setting == "btime" and (not isinstance(value, int) or value <= 0):
                print("Baseline time must be an integer > 0")
                set_field = False
            elif setting == "afreq" and (not isinstance(value, int) or value <= 0):
                print("Analysis Frequency must be an integer > 0")
                set_field = False
            elif setting == "sfreq" and (not isinstance(value, float) or value <= 0):
                print("Send Frequency must be a decimal > 0")
                set_field = False
            elif setting == "mode" and (not isinstance(value, int) or value < 0 or value > 2):
                print("Mode must be between 0-2")
                set_field = False
            elif setting == "tolerance" and (not isinstance(value, int) or value < 0):
                print("Tolerance Difference must be a positive integer")
                set_field = False
            # TODO: add checking for pgns lists
            if set_field:
                setattr(self, self.modifiable[setting], value)
        else:
            print("That setting does not exist")

    def modify_targets(self):
        # TODO: pretty print this
        # print("Current Targets : " + str([str(t) for t in self.targets]))
        print("Add Target: 'add [address]'")
        print("Delete Target: 'delete [address]'")
        print("Clear Targets: 'clear'")
        command = input("Select an option (? for help, q to return): ")
        if "add" in command:
            while True:
                try:
                    address = int(command.partition("add")[2].strip())
                    break
                except ValueError:
                    print("Specified address must be between 0-255")
            if 0 <= address < 256:
                if len([t for t in self.targets if t.address == address]) > 0:
                    replace = input("Address already in target list, replace it? (y or n) ")
                    if replace != "y" and replace != "yes":
                        return
                print("Most ECUs send a message when it first boots, which may help indicate a crash. For "
                      "instance, the J1939 standard requires each ECU send an Address Claimed message before "
                      "other communication (PGN 60928), but proprietary protocol messages are also sometimes "
                      "present.")
                option = input("Does this target send a specific message when it reboots? (y or n) ")
                if option == "y" or option == "yes":
                    while True:
                        try:
                            pgn = int(input("What PGN is the message? (Default: 60928) "))
                            break
                        except ValueError:
                            print("PGN must be between 0-65535")
                    if 0 <= pgn < 65536:
                        while True:
                            data_snip = input("What hex string data does the message contain? (e.g. "
                                              "'1122AABB', or '' to exclude) ").strip("0x")
                            try:
                                if len(data_snip) > 0:
                                    int(data_snip, 16)
                            except ValueError:
                                print("Data string must be in hexadecimal format")
                                continue
                            target = self.Target(address, pgn, data_snip)
                            self.targets.append(target)
                            break
                else:
                    target = self.Target(address)
                    self.targets.append(target)
            else:
                print("Specified address must be between 0-255")
        elif "delete" in command:
            address = command.partition("delete")[2].strip()
            if isinstance(address, int) and address >= 0 or address < 256:
                if len([t for t in self.targets if t.address == address]) > 0:
                    self.targets.remove(address)
                else:
                    print("Target not in list")
            else:
                print("Specified address must be between 0-255")
        elif "clear" in command:
            confirm = input("Are you sure you want to clear all target info? (y or n) ")
            if confirm == "y" or confirm == "yes":
                self.targets = []

    def describe_setting(self, setting):
        if self.modifiable[setting]:
            if setting == "btime":
                print("Baseline time is the amount of time to record the baseline for, in seconds. (Default: 60)")
            elif setting == "afreq":
                print("Analysis Frequency is how long to wait between analysing for anomalies, in seconds. (Default: "
                      "20)")
            elif setting == "sfreq":
                print("Send Frequency is the amount of time to wait between sending each fuzzed message, in seconds. "
                      "(Default: 0.5)")
            elif setting == "mode":
                # TODO: add more info here
                print("There are 3 modes: mutational (0), generational (1), mutational/generational (2). ")
            elif setting == "tolerance":
                print("Tolerance Difference is the acceptable difference in the volume of messages between the "
                      "baseline and the current interval to determine if a crash has occurred. A percentage value is "
                      "expected. (Default: 5%)")
            # TODO: add descriptions for targets and pgns lists
        else:
            print("That setting does not exist")

    def settings_menu(self):
        fuzz_str = "\n***** Fuzzer Settings *****"
        fuzz_str += "\nBaseline Time(btime): " + str(self.baseline_time) + "s | Analysis Frequency(afreq): " + str(
            self.check_frequency) + "s"
        fuzz_str += "\nSend Frequency(sfreq): " + str(self.message_frequency) + " | Fuzz mode(mode): " + str(self.mode)
        fuzz_str += "\nTotal Messages (msgtotal): " + str(self.num_messages) + " | "
        fuzz_str += "\nTolerance Difference(tolerance): " + str(self.diff_tolerance) + "%"
        if len(self.targets) == 0:
            fuzz_str += "\nTarget Addresses: ALL"
        else:
            fuzz_str += "\nTarget Addresses: "
            for target in self.targets:
                fuzz_str += str(target)
        if len(self.testable_pgns) == 0:
            fuzz_str += "\nTestable PGNs(pgns): ALL"
        else:
            fuzz_str += "\nTestable PGNs(pgns): "
            for pgn in self.testable_pgns:
                fuzz_str += str(pgn)
                # TODO: pretty print this so a large list does not break it
                # maybe make it so they have to choose either a specific PGN, or destination-specific/broadcast ranges?
        fuzz_str += "\n\nView detailed description of setting with command 'NAME ?'"
        fuzz_str += "\nChange setting with command 'NAME=VALUE'"
        return fuzz_str

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

    def generate(self, priority=None, pgn=None, dst_addr=None, src_addr=None, data=None, option=None):
        if (priority == None):
            priority = random.randint(0, 7)
        if (dst_addr == None):
            dst_addr = random.randint(0, 255)
        if (src_addr == None):
            src_addr = random.randint(0, 255)
        if (pgn == None):
            if (dst_addr == 255):
                pgn = random.randint(0, 65535)  # include destination specific and broadcast PGNs
            else:
                pgn = random.randint(0, 61439)  # only include destination specific PGNs

        if (pgn <= 255):  # pgn is only 2 hex digits
            pgn = 0
        elif (pgn > 255 and pgn <= 4095):  # pgn is only 3 hex digits
            pgn = int(hex(pgn)[2:3] + '00', 16)  # only use the first nibble
        elif (pgn > 4095 and pgn < 61440):  # if in the destination specific range
            pgn = int(hex(pgn)[2:4] + '00', 16)  # only use the first byte
        if (data == None):
            if (option == None or option < 1 or option > 3):
                option = random.randint(1, 3)
            if (option == 1):
                data = ''
                try:
                    pgn_info = self.devil._pgn_list[str(pgn)]
                    if (isinstance(pgn_info['pgnDataLength'], int)):
                        dataLen = pgn_info['pgnDataLength']
                    else:
                        raise KeyError
                    spnList = pgn_info['spnList']
                    bin_data = ''
                    usedBits = 0
                    for spn in spnList:
                        spn_info = self.devil._spn_list[str(spn)]
                        if (isinstance(spn_info['spnLength'], int)):
                            spnLength = spn_info['spnLength']  # number of bits
                        else:
                            raise KeyError  # length is variable
                        maxVal = (2 ** spnLength) - 1  # maximum int value for x number of bits (ex: 255 for 8 bits)

                        val = random.randint(0, maxVal)
                        bin_val = bin(val)[2:].zfill(spnLength)
                        filler = (spn_info['bitPositionStart'] - usedBits) * '1'
                        bin_data = bin_val + filler + bin_data
                        usedBits += spnLength
                        usedBits += len(filler)
                    bitsLeft = (dataLen * 8 - usedBits) * '1'
                    if (len(bitsLeft) > 0):
                        data = (hex(int(bitsLeft + bin_data, 2))[2:]).upper()
                    else:
                        data = (hex(int(bin_data, 2))[2:].zfill(int(len(bin_data) / 4))).upper()

                except KeyError:
                    option = 2
            if (option == 2):
                try:
                    pgn_info = self.devil._pgn_list[str(pgn)]
                    if (isinstance(pgn_info['pgnDataLength'], int)):
                        dataLen = pgn_info[
                            'pgnDataLength']  # number of bytes to generate is based on data length specified in pgn
                    else:
                        dataLen = random.randint(0,
                                                 1785)  # number of bytes to generate is random if pgn exists but the length is variable
                except KeyError:
                    dataLen = random.randint(0, 1785)  # number of bytes to generate is random if pgn does not exist
                data = ''
                for i in range(0, dataLen):
                    data_byte = hex(random.randint(0, 255))[2:].zfill(2)
                    data += data_byte
            if (option == 3):
                dataLen = random.randint(0, 1785)  # number of bytes to generate
                data = ''
                for i in range(0, dataLen):
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
                        if t.address == m.src_addr and t.reboot_pgn == m.pgn and t.reboot_data in m.data:
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
        fuzz_list = []
        for i in range(0, self.num_messages):
            choice = self.mode
            # either mutate or generate
            if choice == 2:
                choice = random.randint(0, 1)
            # mutate a message from the baseline
            if choice == 0:
                mutate_index = random.randint(0, len(self.baseline_messages) - 1)
                # TODO: make these parameters based on settings
                m = self.mutate(self.baseline_messages[mutate_index], mutate_priority=False,
                                mutate_src_addr=False,
                                mutate_dst_addr=False,
                                mutate_pgn=False, mutate_data=True)
            # generate a message
            elif choice == 1:
                # TODO: make these parameters based on settings
                m = self.generate(src_addr=0x00, dst_addr=0x0B)
            fuzz_list.append(m)
        return fuzz_list

    def record_baseline(self):
        self.devil._m2.flushInput()
        print("Baselining for " + str(self.baseline_time) + " seconds...")
        self.devil.startDataCollection()
        time.sleep(self.baseline_time)
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

    class Target:
        def __init__(self, address, reboot_pgn=None, reboot_data_snip=None):
            self.address = address
            self.reboot_pgn = reboot_pgn
            self.reboot_data = reboot_data_snip

        def __str__(self):
            target_str = "Address: " + "0x{:02x}".format(self.address) + " (" + str(self.address) + ")\n"
            if self.reboot_pgn is not None:
                target_str += "Boot message PGN: " + "0x{:04x}".format(self.reboot_pgn) + " (" + str(
                    self.reboot_pgn) + ")\n"
            if self.reboot_data is not None:
                target_str += "Boot message data contains: " + self.reboot_data


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


def main_mod(devil):
    print("\n***** J1939 Fuzzer *****\n"
          "  1) View settings\n"
          "  2) Record baseline\n"
          "  3) View baseline results\n"
          "  4) Set targets\n"
          "  5) Start Fuzzer")
    fuzzer = J1939Fuzzer(devil)
    while True:
        fuzz_select = input("\nSelect an option (? for help, q to return): ")
        if fuzz_select == "q" or fuzz_select == "quit" or fuzz_select == "exit":
            return
        elif fuzz_select == "1":
            print(fuzzer.settings_menu())
        elif fuzz_select == "2":
            fuzzer.record_baseline()
            if len(fuzzer.baseline) == 0:
                print("No messages detected during the baseline.")
        elif fuzz_select == "3":
            if len(fuzzer.baseline) == 0:
                print("Baseline has not been recorded yet.")
            else:
                # TODO: pretty print the baseline results
                # print(str(fuzzer.baseline))
                print("Baseline time: " + str(len(fuzzer.baseline_messages) / fuzzer.baseline_time) + " per second")
        elif fuzz_select == "4":
            fuzzer.modify_targets()
        elif fuzz_select == "5":
            if len(fuzzer.baseline) == 0:
                q = input("Baseline has not been recorded yet. Record now (y or n)? ")
                if q == "y" or q == "yes":
                    fuzzer.record_baseline()
                    if len(fuzzer.baseline) == 0:
                        print("No messages detected during the baseline.")
                        continue
                else:
                    continue
            print("Creating " + str(fuzzer.num_messages) + " messages to fuzz...")
            generated_messages = fuzzer.create_fuzz_list()

            fuzzer.done_fuzzing = False
            fuzzer.pause_fuzzing = False
            fuzzer.fuzzed_messages = []
            fuzzer.lock_fuzzed_messages = threading.RLock()

            anomaly_check_thread = threading.Thread(target=fuzzer.anomaly_check, daemon=False)
            anomaly_check_thread.start()
            try:
                for i in progressbar(range(fuzzer.num_messages), "Sending: ", 40):
                    m = generated_messages[i]
                    # TODO: re-enable sending
                    # fuzzer.devil.sendMessage(m)
                    with fuzzer.lock_fuzzed_messages:
                        fuzzer.fuzzed_messages.append(m)
                    time.sleep(fuzzer.message_frequency)
                    while fuzzer.pause_fuzzing:
                        time.sleep(1)
                    if fuzzer.done_fuzzing:
                        break
                fuzzer.done_fuzzing = True
            except KeyboardInterrupt:
                fuzzer.done_fuzzing = True
        elif '=' in fuzz_select:
            setting = fuzz_select.partition('=')[0]
            value = fuzz_select.partition('=')[2]
            if setting in fuzzer.modifiable:
                fuzzer.save_setting(setting, value)
            else:
                print("That setting does not exist")
        elif '?' in fuzz_select:
            if fuzz_select == "?":
                print("\n***** J1939 Fuzzer *****\n"
                      "  1) View settings\n"
                      "  2) Record baseline\n"
                      "  3) View baseline results\n"
                      "  4) Set targets\n"
                      "  5) Start Fuzzer")
            else:
                setting = fuzz_select.partition('?')[0].strip()
                if setting in fuzzer.modifiable:
                    fuzzer.describe_setting(setting)
                else:
                    print("That setting does not exist")
