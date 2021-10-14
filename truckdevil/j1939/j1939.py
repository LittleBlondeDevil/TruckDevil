import serial
import threading
import time
import math
import copy
import json
import os
import can


def j1939_fields_to_can_id(priority, reserved_bit, data_page_bit, pdu_format, pdu_specific, src_addr):
    return int(bin(priority)[2:].zfill(3) + bin(reserved_bit)[2:].zfill(1) +
               bin(data_page_bit)[2:].zfill(1) + bin(pdu_format)[2:].zfill(8) + bin(pdu_specific)[2:].zfill(8) +
               bin(src_addr)[2:].zfill(8), 2)


class J1939Interface:
    def __init__(self, device):
        """
        Initializes truckdevil

        :param device_type: either "m2" or "socketcan" (Default value = 'm2').
        :param port: serial port that the M2 is connected to, if used. For example: COM7 or /dev/ttyX. 0 if not using M2."
        :param channel: CAN channel to send/receive on. For example: can0, can1, or vcan0. (Default value = 'can0')
        :param can_baud: baudrate on the CAN bus. Most common are 250000 and 500000. Use 0 for autobaud detection. (Default value = 0)
        """
        self.device = device

        self.m_manager = MessageManagement()

        self._print_messages_time_done = False
        self._print_messages_timer = None

        self._data_collection_occurring = False
        self._collected_messages = []
        self._lock_collected_messages = threading.RLock()
        self._collection_thread = None

        self.pgn_list = {}
        with open(os.path.join('resources', 'json_files', 'pgn_list.json')) as pgn_file:
            self.pgn_list = json.load(pgn_file)

        self.spn_list = {}
        with open(os.path.join('resources', 'json_files', 'spn_list.json')) as spn_file:
            self.spn_list = json.load(spn_file)

        self.src_addr_list = {}
        with open(os.path.join('resources', 'json_files', 'src_addr_list.json')) \
                as src_addr_file:
            self.src_addr_list = json.load(src_addr_file)

        self.bit_decoding_list = {}
        with open(os.path.join('resources', 'json_files', 'dataBitDecoding.json')) \
                as bit_decoding_file:
            self.bit_decoding_list = json.load(bit_decoding_file)

        self.uds_services_list = {}
        with open(os.path.join('resources', 'json_files', 'UDS_services.json')) \
                as UDS_services_file:
            self.uds_services_list = json.load(UDS_services_file)

        self.uds_functions_list = {}
        with open(os.path.join('resources', 'json_files', 'UDS_functions.json')) \
                as UDS_functions_file:
            self.uds_functions_list = json.load(UDS_functions_file)

        self.uds_nrc_list = {}
        with open(os.path.join('resources', 'json_files', 'UDS_NRC.json')) \
                as UDS_NRC_file:
            self.uds_nrc_list = json.load(UDS_NRC_file)

    @property
    def data_collection_occurring(self):
        return self._data_collection_occurring

    def get_collected_data(self):
        """
        Gets all of the messages that have been collected

        :return: the collected_messages list
        """
        with self._lock_collected_messages:
            messages = self._collected_messages
        return messages

    def _add_to_collected_messages(self, message):
        with self._lock_collected_messages:
            # Add message to collectedMessages list
            self._collected_messages.append(message)

    def _clear_collected_messages(self):
        with self._lock_collected_messages:
            self._collected_messages = []

    def _set_print_messages_time_done(self):
        """Used by internal timer for printMessages function."""
        self._print_messages_time_done = True

    def print_messages(self, abstract_tpm=True, read_time=None, num_messages=None, verbose=False, log_to_file=False):
        """
        Read and print all messages from device. If readTime and numMessages are both specified, stop printing when whichever one is reached first.

        :param abstract_tpm: whether to abstract multipacket messages or instead to show all Transport Protocol messages (Default value = True)
        :param read_time: the amount of time to print messages for. If not specified, it will not be limited
        :param num_messages: number of messages to print before stopping. If not specified, it will not be limited
        :param verbose: whether or not to print the message in decoded form (Default value = False)
        :param log_to_file: whether or not to log the messages to a file (Default value = False)
        """
        # Only allow if data collection is not occurring
        if self.data_collection_occurring:
            raise Exception('stop data collection before proceeding with this function')
        # If optional readTime is utilized
        if read_time is not None:
            self._print_messages_timer = threading.Timer(
                read_time, self._set_print_messages_time_done
            )
            self._print_messages_timer.start()
        messages_printed = 0
        self.m_manager.reset_conversations()
        self._print_messages_time_done = False
        # Log to file
        if log_to_file:
            file_name = 'm2_collected_data_' + str(int(time.time()))
            log_file = open(file_name, "x")
            log_file.write(
                """Priority    PGN    Source --> Destination
                [Num Bytes]    data""" + '\n'
            )
        # Keep printing while our timer isn't done or the number of
        # messages to print hasn't been reached (whichever comes first).
        # If neither are utilized, keep going forever
        while self._print_messages_time_done is False and (num_messages is None or messages_printed < num_messages):
            # Only allow if data collection is not occurring
            if self.data_collection_occurring:
                raise Exception(
                    """data collection began abruptly, stop data collection 
                    before proceeding with this function"""
                )
            j1939_message = self.read_one_message(abstract_tpm, self.m_manager)
            # Print/log the message
            if not verbose:
                print(j1939_message)
                if log_to_file:
                    log_file.write(str(j1939_message) + '\n')
            else:
                print(self.get_decoded_message(j1939_message))
                if log_to_file:
                    log_file.write(self.get_decoded_message(j1939_message) + '\n')
            messages_printed = messages_printed + 1
        # Close the log file before exiting
        if log_to_file:
            log_file.close()
        if read_time is not None:
            self._print_messages_timer.cancel()

    def read_messages_until(self, **params):
        """
        Read all messages from device until a specific message is found, at least one parameter should be specified to
        look for.

        :param params:
            See below
        :Keyword Arguments:
            can_id: if specified, the target message must have this CAN ID
            priority: if specified, the target message must have this priority
            reserved_bit: if specified, the target message must have the reserved bit set to this
            data_page_bit: if specified, the target message must have the data page bit set to this
            pdu_format: if specified, the target message must have this PDU Format
            pdu_specific: if specified, the target message must have this PDU Specific
            src_addr: if specified, the target message must have this source address
            data_contains: if specified, the target message must contain this hex string in the data portion, ex:
                "0102AABB"
        :return: both the target message (J1939Message) that matched the specified parameters, and the list of messages
            that were collected while searching
        """
        if len(params) == 0:
            raise Exception("at least one parameter must be included to search for")

        collected_messages = []
        manager = MessageManagement()
        while True:
            j1939_message = self.read_one_message(abstract_tpm=False, message_manager=manager)
            collected_messages.append(j1939_message)
            matched = True
            for param in params:
                target_val = params[param]
                if param == "can_id" and j1939_message.can_id != target_val:
                    matched = False
                    break
                if param == "priority" and j1939_message.priority != target_val:
                    matched = False
                    break
                if param == "reserved_bit" and j1939_message.reserved_bit != target_val:
                    matched = False
                    break
                if param == "data_page_bit" and j1939_message.data_page_bit != target_val:
                    matched = False
                    break
                if param == "pdu_format" and j1939_message.pdu_format != target_val:
                    matched = False
                    break
                if param == "pdu_specific" and j1939_message.pdu_specific != target_val:
                    matched = False
                    break
                if param == "src_addr" and j1939_message.src_addr != target_val:
                    matched = False
                    break
                if param == "data_contains" and target_val not in j1939_message.data:
                    matched = False
                    break
            if matched:
                return j1939_message, collected_messages

    def start_data_collection(self, abstract_tpm=True):
        """
        Starts reading and storing messages

        :param abstract_tpm: whether to abstract multipacket messages or instead to show all Transport Protocol messages
         (Default value = True)
        """
        if self._data_collection_occurring:
            raise Exception('data collection already started')

        # Wait until the previous collection thread has stopped
        if self._collection_thread is not None and self._collection_thread.is_alive():
            self._collection_thread.join()

        self._clear_collected_messages()

        self._data_collection_occurring = True
        self._collection_thread = threading.Thread(target=self._read_message, args=(abstract_tpm, 0.5,), daemon=True)
        self._collection_thread.start()

    def stop_data_collection(self):
        """
        Stops reading and storing messages, resets all data

        :returns: the collected_messages list
        """
        if not self._data_collection_occurring:
            raise Exception('data collection is already stopped')
        self._data_collection_occurring = False
        self.m_manager.reset_conversations()
        data_collected = self.get_collected_data()
        self._clear_collected_messages()
        return data_collected

    def save_data_collected(self, messages, file_name=None, verbose=False):
        # TODO: fix save/load functions
        """
        Save the collected messages to a file

        :param messages: the collected messages outputted from stopDataCollection
        :param file_name: the name of the file to save the data to. If not specified, defaults to: "m2_collected_data_[time]"
        :param verbose: whether or not to save the message in decoded form (Default value = False)
        """
        # If given messages list is empty
        if len(messages) == 0:
            raise Exception('messages list is empty')
        if file_name is None:
            file_name = 'm2_collected_data_' + str(int(time.time()))
        f = open(file_name, "x")
        f.write("""Priority    PGN    Source --> Destination    [Num Bytes]    data""" + '\n')
        for m in messages:
            if not verbose:
                f.write(str(m) + '\n')
            else:
                f.write(self.get_decoded_message(m) + '\n')
        f.close()

    def import_data_collected(self, file_name):
        # TODO: fix save/load functions
        """
        Converts log file to list of J1939_Message objects

        :param file_name: the name of the file where the data is saved
        :returns: list of J1939_Message objects from log file
        """
        messages = []
        if os.path.exists(file_name):
            with open(file_name, 'r') as inFile:
                first_line = True
                for line in inFile:
                    if first_line:
                        first_line = False
                    else:
                        parts = line.split()
                        if len(parts) == 7 and parts[3] == '-->' and '[' in line:
                            message = J1939Message(
                                priority=int(parts[0]),
                                pgn=int(parts[1], 16),
                                dst_addr=int(parts[4], 16),
                                src_addr=int(parts[2], 16),
                                data=parts[6]
                            )
                            messages.append(message)
                return messages
        else:
            raise Exception('file name given does not exist.')

    def _read_message(self, abstract_tpm=True, timeout=None):
        """
        Read and store messages in the collectedMessages array.
        For internal function use.
        """
        while True:
            # Keep the thread from executing if not in collection state
            if not self.data_collection_occurring:
                break
            j1939_message = self.read_one_message(abstract_tpm, self.m_manager, timeout)
            if j1939_message is None:
                continue  # timeout occurred
            self._add_to_collected_messages(j1939_message)

    def read_one_message(self, abstract_tpm=False, message_manager=None, timeout=None):
        if message_manager is None:
            message_manager = self.m_manager
        while True:
            # Look for full multipacket message to return first
            j1939_message = message_manager.find_full_multipacket_message()
            if j1939_message is not None:
                return j1939_message

            # Look for full ISO-TP message to return next
            j1939_message = message_manager.find_full_isotp_message()
            if j1939_message is not None:
                return j1939_message

            # Next read from device
            can_msg = self.device.read(timeout=timeout)
            if can_msg is None:
                return None  # timeout occurred
            data = ''.join('{:02x}'.format(x) for x in can_msg.data)
            j1939_message = J1939Message(can_msg.arbitration_id, data)

            # Multipacket message received, broadcasted or peer-to-peer request to send
            if j1939_message.pgn == 0xec00 and (j1939_message.data[0:2] == "20" or j1939_message.data[0:2] == "10"):
                mp_message = _J1939MultiPacketMessage(j1939_message)
                message_manager.add_new_conversation(mp_message)
                if abstract_tpm:
                    continue

            # Multipacket data transfer message received
            elif j1939_message.pgn == 0xeb00:
                message_manager.add_to_existing_conversation(j1939_message)
                if abstract_tpm:
                    continue

            # UDS ISO-TP message received, first frame
            elif j1939_message.pgn == 0xda00 and j1939_message.data[0:1] == '1':
                iso_tp_message = _J1939ISOTPMessage(j1939_message)
                message_manager.add_new_isotp_conversation(iso_tp_message)
                if abstract_tpm:
                    continue

            # UDS ISO-TP message received, consecutive frame
            elif j1939_message.pgn == 0xda00 and j1939_message.data[0:1] == '2':
                message_manager.add_to_existing_isotp_conversation(j1939_message)
                if abstract_tpm:
                    continue

            # UDS ISO-TP message received, flow control frame
            elif j1939_message.pgn == 0xda00 and j1939_message.data[0:1] == '3':
                if abstract_tpm:
                    continue
            return j1939_message

    def send_message(self, message):
        # Get total number of bytes to send
        data_bytes = int(len(message.data) / 2)

        # Sending multipacket message - if number of bytes to send is more than 8 (ex: 1CECFF000820120003FFCAFE00)
        if data_bytes > 8:
            # create transport protocol connection management can_id
            can_id = j1939_fields_to_can_id(message.priority, message.reserved_bit, message.data_page_bit, 0xEC,
                                            message.dst_addr, message.src_addr)

            # Change int to 4 character hex string
            num_bytes = "%04X" % data_bytes
            num_packets = "%02X" % math.ceil(data_bytes / 7)

            pgn_str = hex(message.pgn)[2:].zfill(4)
            if message.dst_addr == 0xFF:
                # Send BAM message (ex: 20120003FFCAFE00)
                control_message = ("20" + num_bytes[2:4] + num_bytes[0:2]
                                   + num_packets + "FF" + pgn_str[2:4] + pgn_str[0:2] + "00")
            else:
                # Send RTS message
                control_message = ("10" + num_bytes[2:4] + num_bytes[0:2]
                                   + num_packets + "FF" + pgn_str[2:4] + pgn_str[0:2] + "00")

            msg = can.Message(arbitration_id=can_id, is_extended_id=True, dlc=8, data=bytes.fromhex(control_message))
            with self.device.device_lock:
                # Send BAM or RTS message
                self.device.send(msg)
            if message.dst_addr == 0xFF:
                # Sleep 100ms before transmitting next message as stated in standard
                time.sleep(0.1)
            else:
                # Sleep 150ms before transmitting next message to allow for CTS to come through
                time.sleep(0.15)

            # create transport protocol data transfer can_id
            can_id = j1939_fields_to_can_id(message.priority, message.reserved_bit, message.data_page_bit, 0xEB,
                                            message.dst_addr, message.src_addr)
            for i in range(0, int(num_packets, 16)):
                # If a full 7 bytes is available
                if (i * 7) < data_bytes - data_bytes % 7:
                    seven_bytes = message.data[i * 14:(i * 14) + 14]
                # Pad remaining last packet with FF for data
                else:
                    seven_bytes = (message.data[i * 14:(i * 14) + ((data_bytes % 7) * 2)]
                                   + "FF" * (7 - (data_bytes % 7)))
                data_transfer = "%02X" % (i + 1)
                data_transfer += seven_bytes
                msg = can.Message(arbitration_id=can_id, is_extended_id=True, dlc=8, data=bytes.fromhex(data_transfer))
                with self.device.device_lock:
                    self.device.send(msg)
                time.sleep(0.01)

        # Sending non-multipacket message - if number of bytes to send is less than or equal to 8
        else:
            # TODO: send less than 8 bytes without padding?
            msg = can.Message(arbitration_id=message.can_id, is_extended_id=True,
                              data=bytes.fromhex(message.data + "FF" * (8 - data_bytes)))

            with self.device.device_lock:
                self.device.send(msg)

    def get_decoded_message(self, message=None):
        """
        Decodes a J1939_Message object into human-readable string

        :param message: J1939_Message object to be decoded
        :returns: the decoded message as a string
        """
        if isinstance(message, J1939Message) is False or message is None:
            raise Exception('Must include an instance of a J1939_Message')
        decoded = str(message) + '\n'
        # Only include this portion if src and dest addrs are in list
        if (str(message.src_addr) in self.src_addr_list) and (str(message.dst_addr) in self.src_addr_list):
            decoded += (
                    '    ' + self.src_addr_list[str(message.src_addr)] +
                    " --> " + self.src_addr_list[str(message.dst_addr)] +
                    '\n'
            )
        # Only include this portion if the pgn of the message is in pgn_list
        if str(message.pgn) in self.pgn_list:
            decoded += (
                    '    PGN(' + str(message.pgn) + '): ' +
                    self.pgn_list[str(message.pgn)]['acronym'] +
                    '\n'
            )
            decoded += (
                    '      Label: ' +
                    self.pgn_list[str(message.pgn)]['parameterGroupLabel'] +
                    '\n'
            )
            if message.pgn == 0xDA00:
                try:
                    decoded += self._uds_decode(message)
                except (ValueError, UnboundLocalError):
                    decoded += '      Cannot decode UDS message, incorrect form'
                return decoded
            decoded += (
                    '      PGNDataLength: ' +
                    str(self.pgn_list[str(message.pgn)]['pgnDataLength']) +
                    '\n'
            )
            decoded += (
                    '      TransmissionRate: ' +
                    self.pgn_list[str(message.pgn)]['transmissionRate'] +
                    '\n'
            )
            # Only decode data if it matches the num bytes it's supposed to
            if (self.pgn_list[str(message.pgn)]['pgnDataLength']
                    == len(message.data) / 2):
                # For each spn that is part the given pgn
                for spn in self.pgn_list[str(message.pgn)]['spnList']:
                    # Only include this portion if the spn is in the spn_list
                    if str(spn) in self.spn_list:
                        decoded += (
                                '      SPN(' +
                                str(spn) + '): ' +
                                self.spn_list[str(spn)]['spnName'] +
                                '\n'
                        )
                        # Ensure it's not a variable length SPN
                        if (self.spn_list[str(spn)]['spnLength']
                                != "variable"):
                            total_bits = self.spn_list[str(spn)]['spnLength']
                            start_bit = self.spn_list[str(spn)]['bitPositionStart']
                            end_bit = start_bit + total_bits

                            bin_data_total = bin(int(message.data, 16))[2:] \
                                .zfill(int((len(message.data) / 2) * 8))
                            bin_data = bin_data_total[start_bit:end_bit]
                            extracted_data = int(bin_data, 2)
                            # Swap endianness if greater then 1 byte
                            if 8 < total_bits <= 16:  # (2 bytes)
                                extracted_data = int.from_bytes(extracted_data.to_bytes(2, byteorder='little'),
                                                                byteorder='big', signed=False)
                            if 16 < total_bits <= 24:  # (3 bytes)
                                extracted_data = int.from_bytes(extracted_data.to_bytes(3, byteorder='little'),
                                                                byteorder='big', signed=False)
                            if 24 < total_bits <= 32:  # (4 bytes)
                                extracted_data = int.from_bytes(extracted_data.to_bytes(4, byteorder='little'),
                                                                byteorder='big', signed=False)
                            if 32 < total_bits <= 40:  # (5 bytes)
                                extracted_data = int.from_bytes(extracted_data.to_bytes(5, byteorder='little'),
                                                                byteorder='big', signed=False)
                            if 48 < total_bits <= 56:  # (6 bytes)
                                extracted_data = int.from_bytes(extracted_data.to_bytes(6, byteorder='little'),
                                                                byteorder='big', signed=False)
                            if 56 < total_bits <= 64:  # (7 bytes)
                                extracted_data = int.from_bytes(extracted_data.to_bytes(7, byteorder='little'),
                                                                byteorder='big', signed=False)

                            # If all 1's, don't care about value, don't add
                            if extracted_data != int("1" * total_bits, 2) or total_bits == 1:
                                # If bit data type, use bit_decoding_list
                                if (self.spn_list[str(spn)]['units'] == 'bit'
                                        and str(spn)
                                        in self.bit_decoding_list):
                                    decoded += (
                                            '        ' + str(int(bin_data, 2)) +
                                            ' : ' +
                                            self.bit_decoding_list[str(spn)][str(int(bin_data, 2))] +
                                            '\n'
                                    )
                                # if ascii data type, convert
                                elif self.spn_list[str(spn)]['units'] == 'ASCII':
                                    try:
                                        to_ascii = extracted_data.to_bytes(len(bin_data) // 8, byteorder='big')
                                        decoded += (
                                                '        ' + bin_data +
                                                ' : ' + str(to_ascii, 'latin-1') +
                                                '\n'
                                        )
                                    except UnicodeDecodeError:
                                        continue
                                else:
                                    # Multiply by the resolution and add offset to get appropriate range
                                    try:
                                        extracted_data = (
                                                (extracted_data *
                                                 (self.spn_list[str(spn)]['resolutionNumerator'] /
                                                  self.spn_list[str(spn)]['resolutionDenominator'])) +
                                                self.spn_list[str(spn)]['offset']
                                        )
                                    except TypeError:
                                        continue
                                    if extracted_data.is_integer():
                                        extracted_data = str(int(extracted_data))
                                    else:
                                        extracted_data = "%.2f" % extracted_data
                                    decoded += (
                                            '        ' + str(extracted_data) +
                                            ' ' +
                                            self.spn_list[str(spn)]['units'] +
                                            '\n'
                                    )
            # Otherwise add a message that it's not the correct form
            else:
                decoded += '      Cannot decode SPNs\n'
        return decoded

    def _uds_decode(self, message):
        """
        Takes in J1939_message and return the decoded string
        For internal function use.
        """
        decoded = ''
        # Frame type is first nibble
        frame_type = message.data[0:1]
        # 0 is single frame
        if frame_type == '0':
            # Size is between 0 and 7 bytes
            size = int(message.data[1:2], 16)
            service_id = message.data[2:4].upper()
            uds_data = message.data[4:2 + (size * 2)].upper()
        # 1 is first frame - don't decode data
        elif frame_type == '1':
            # Size is between 8 and 4095 bytes
            size = int(message.data[1:4], 16)
            decoded += (
                    '      Type: First frame, indicating ' +
                    str(size) +
                    ' bytes of an incoming message' +
                    '\n'
            )
            return decoded
        # 2 is consecutive frame
        elif frame_type == '2':
            # Index is between 0 and 15
            data_index = int(message.data[1:2], 16)
            decoded += (
                    '      Type: Consecutive frame, indicating this is index ' +
                    str(data_index) +
                    '\n'
            )
            return decoded
        # 3 is flow control frame - don't decode data
        elif frame_type == '3':
            # 0 (continue), 1 (wait), 2 (overflow/abort)
            fc_flag = int(message.data[1:2], 16)
            fc_flag_code = ''
            if fc_flag == 0:
                fc_flag_code = 'continue to send'
            elif fc_flag == 1:
                fc_flag_code = 'wait'
            elif fc_flag == 2:
                fc_flag_code = 'overflow/abort'
            else:
                fc_flag_code = 'unknown error'
            # 0: remaining frames sent without flow control or delay,
            # >0: send number of frames before waiting for the next
            # flow control frame
            block_size = int(message.data[2:4], 16)
            block_size_code = ''
            if block_size == 0:
                block_size_code = 'remaining frames to be sent without flow control or delay'
            else:
                block_size_code = 'send number of frames before waiting for the next flow control frame'
            # <=127 (separation time in m),
            # 241-249 (100-900 microseconds)
            separation_time = int(message.data[4:6], 16)
            separation_time_code = ''
            if separation_time <= 127:
                separation_time_code = 'milliseconds'
            elif 241 <= separation_time <= 249:
                separation_time = int(hex(separation_time)[3:4], 16) * 100
                separation_time_code = 'microseconds'
            else:
                separation_time_code = 'unknown error'
            decoded += '      Type: Flow control frame, with the following characteristics:\n'
            decoded += (
                    '          FC Flag: ' +
                    str(fc_flag) + ' - ' +
                    fc_flag_code + '\n'
            )
            decoded += (
                    '          Block size: ' +
                    str(block_size) + ' - ' +
                    block_size_code + '\n'
            )
            decoded += (
                    '          Separation Time: ' +
                    str(separation_time) + ' - ' +
                    separation_time_code + '\n'
            )
            return decoded
        # Frame put back together by truckdevil
        else:
            size = int((len(message.data) - 2) / 2)
            service_id = message.data[2:4].upper()
            uds_data = message.data[4:].upper()
        if int(service_id, 16) == 0x7F:
            decoded += '      UDS service: Negative Response Code\n'
            decoded += (
                    '        *request service ID: 0x' +
                    uds_data[0:2] + ' - ' +
                    self.uds_services_list[uds_data[0:2]]['service'] + '\n'
            )
            decoded += (
                    '        *response code: 0x' +
                    uds_data[2:4] + ' - ' +
                    self.uds_nrc_list[uds_data[2:4]]['name'] + '\n'
            )
            decoded += (
                    '            description: ' +
                    self.uds_nrc_list[uds_data[2:4]]['description'] + '\n'
            )
            return decoded
        try:
            service = copy.deepcopy(self.uds_services_list[service_id])
        except KeyError:
            return decoded + '      UDS Service ID ' + str(service_id) + ' does not exist\n'

        decoded += '      PGNDataLength: ' + str(size + 1) + '\n'
        decoded += '      UDS service: ' + service['service']
        if service['type'] == 'request' or service['type'] == 'response':
            decoded += ' - ' + service['type'] + '\n'
            data_bytes = service['data_bytes']
        elif (service['type'] == 'multiRequest' or
              service['type'] == 'multiResponse'):
            if service['type'] == 'multiRequest':
                decoded += ' - ' + 'request' + '\n'
            else:
                decoded += ' - ' + 'response' + '\n'
            controller_byte = str(int(uds_data[0:2], 16))
            if controller_byte in service['parameters'].keys():
                data_bytes = service['parameters'][controller_byte]['data_bytes']
            elif 'others' in service['parameters'].keys():
                data_bytes = service['parameters']['others']['data_bytes']
            else:
                return decoded
        subfunction = None
        if service['subfunction_supported']:
            suppress_pos = int(bin(int(uds_data[0:2], 16))[2:].zfill(8)[0:1], 2)
            subfunction = int(bin(int(uds_data[0:2], 16))[2:].zfill(8)[1:], 2)
            decoded += (
                    '      suppress positive response? : ' +
                    str(bool(suppress_pos)) + '\n'
            )
        data_index = 0
        temp_length_of_memory_address = -1
        temp_length_of_memory_size = -1
        temp_scaling_byte_data_type = -1
        temp_length_scaling_byte = -1
        temp_routine_identifier = -1
        temp_length_file_path_and_name = -1
        temp_mode_of_operation = -1
        temp_length_file_size_parameter = -1
        temp_length_max_number_of_block_length = -1
        temp_length_event_type_record = -1
        for func_name in data_bytes:
            if data_index >= len(uds_data) / 2:
                break
            if "*" in func_name:
                data_bytes.append(func_name)
                func_name = func_name.replace("*", "")

            # Odd functions that need special care
            if (func_name == 'dataFormatIdentifier2' and
                    (temp_mode_of_operation == 'deleteFile'
                     or temp_mode_of_operation == 'readDir')):
                continue
            elif (func_name == 'fileSizeParameterLength' and
                  (temp_mode_of_operation == 'deleteFile'
                   or temp_mode_of_operation == 'readFile'
                   or temp_mode_of_operation == 'readDir')):
                continue

            decoded += '        *' + func_name + '\n'
            function = self.uds_functions_list[func_name]
            decoded += (
                    '            description: ' +
                    function['description'] + '\n'
            )
            if (function['type'] == 'bit' and
                    function['numBytes'] != 'variable'):
                if (subfunction is not None and
                        data_bytes.index(func_name) == 0):
                    val = function['parameters'][str(subfunction)]
                else:
                    func_data = (uds_data[data_index * 2:function['numBytes'] * 2
                                                         + data_index * 2])
                    try:
                        val = function['parameters'][str(int(func_data, 16))]
                    except KeyError:
                        val = 'cannot decode value (out of range)'
                decoded += '            value: ' + val + '\n'
                if func_name == 'modeOfOperation':
                    temp_mode_of_operation = val
                data_index += function['numBytes']
            elif (function['type'] == 'list' and
                  function['numBytes'] != 'variable'):
                func_data = (uds_data[data_index * 2:function['numBytes'] * 2
                                                     + data_index * 2])
                bin_data = bin(int(func_data, 16))[2:] \
                    .zfill(function['numBytes'] * 8)
                for param in function['parameters']:
                    decoded += (
                            '            *' +
                            function['parameters'][param]['name'] +
                            '\n'
                    )
                    decoded += (
                            '              description: ' +
                            function['parameters'][param]['description'] +
                            '\n'
                    )
                    if function['parameters'][param]['units'] == 'list':
                        for nestedParam in function['parameters'][param]['parameters']:
                            decoded += (
                                    '              *' +
                                    function['parameters'][param]['parameters'][nestedParam]['name'] +
                                    '\n'
                            )
                            decoded += (
                                    '                description: ' +
                                    function['parameters'][param]['parameters'][nestedParam]['description'] +
                                    '\n'
                            )
                            start_position = function['parameters'][param]['startPosition']
                            start_nested_position = (
                                    start_position +
                                    function['parameters'][param]['parameters'][nestedParam]['startPosition']
                            )
                            total_len = function['parameters'][param]['parameters'][nestedParam]['totalLen']
                            inner_func_data = bin_data[start_nested_position: start_nested_position + total_len]
                            val = (
                                str(int(inner_func_data, 2)
                                    * int(function['parameters'][param]['parameters'][nestedParam]['resolution']))
                            )
                            if function['parameters'][param]['parameters'][nestedParam]['units'] == 'bit':
                                decoded += (
                                        '                value: ' +
                                        function['parameters'][param]['parameters'][nestedParam]['bitDecoding'][val] +
                                        '\n'
                                )
                            else:
                                decoded += (
                                        '                value: ' +
                                        val + ' ' +
                                        function['parameters'][param]['parameters'][nestedParam]['units'] +
                                        '\n'
                                )
                    else:
                        start_position = function['parameters'][param]['startPosition']
                        total_len = function['parameters'][param]['totalLen']
                        inner_func_data = bin_data[start_position:start_position + total_len]
                        val = (
                            str(int(inner_func_data, 2)
                                * int(function['parameters'][param]['resolution']))
                        )

                        if function['parameters'][param]['name'] == 'dataType':
                            temp_scaling_byte_data_type = int(val)
                        elif function['parameters'][param]['name'] == "LengthOfMemoryAddress":
                            temp_length_of_memory_address = int(inner_func_data, 2)
                        elif function['parameters'][param]['name'] == "LengthOfMemorySize":
                            temp_length_of_memory_size = int(inner_func_data, 2)
                        elif function['parameters'][param]['name'] == "numBytes":
                            temp_length_scaling_byte = int(val)
                        elif function['parameters'][param]['name'] == "lengthMaxNumberOfBlockLength":
                            temp_length_max_number_of_block_length = int(val)
                        elif function['parameters'][param]['name'] == "eventType":
                            event_type = int(val)
                            if event_type == 1 or event_type == 2:
                                temp_length_event_type_record = 1
                            elif event_type == 3:
                                temp_length_event_type_record = 2
                            elif event_type == 7:
                                temp_length_event_type_record = 10
                            else:
                                temp_length_event_type_record = 0

                        if function['parameters'][param]['units'] == 'bit':
                            decoded += (
                                    '              value: ' +
                                    function['parameters'][param]['bitDecoding'][val] +
                                    '\n'
                            )
                        elif function['parameters'][param]['units'] == 'hexValue':
                            decoded += (
                                    '              value: 0x' +
                                    hex(int(val))[2:].upper() +
                                    '\n'
                            )
                        else:
                            decoded += (
                                    '              value: ' +
                                    val + ' ' +
                                    function['parameters'][param]['units'] +
                                    '\n'
                            )
                data_index += function['numBytes']
            elif (function['type'] == 'value' and
                  function['numBytes'] != 'variable'):
                func_data = (
                    uds_data[data_index * 2:function['numBytes'] * 2 + data_index * 2]
                )
                val = int(func_data, 16) * function['resolution']
                decoded += (
                        '            value: ' +
                        str(val) + ' ' +
                        function['units'] +
                        '\n'
                )
                if func_name == 'filePathAndNameLength':
                    temp_length_file_path_and_name = val
                if func_name == 'fileSizeParameterLength':
                    temp_length_file_size_parameter = val
                data_index += function['numBytes']
            elif (function['type'] == 'hexValue' and
                  function['numBytes'] != 'variable'):
                func_data = (
                    uds_data[data_index * 2:function['numBytes'] * 2
                                            + data_index * 2]
                )
                if func_name == 'periodicDataIdentifier':
                    decoded += '            value: 0xF2' + func_data + '\n'
                else:
                    decoded += '            value: 0x' + func_data + '\n'
                data_index += function['numBytes']
            elif (function['type'] == 'largeBit' and
                  function['numBytes'] != 'variable'):
                if func_name == 'routineInfo':
                    decoded += '            optional value - not used' + '\n'
                    continue
                func_data = (
                    uds_data[data_index * 2:function['numBytes'] * 2
                                            + data_index * 2]
                )
                val = str(int(func_data, 16))
                for param in function['parameters']:
                    range_nums = param.split('-')
                    if len(range_nums) == 1:
                        if val == range_nums[0]:
                            # Found it
                            param_name = function['parameters'][param]
                    else:
                        if range_nums[0] <= val <= range_nums[1]:
                            param_name = function['parameters'][param]
                decoded += (
                        '            value: ' + val +
                        ' - ' + param_name + '\n'
                )
                if func_name == 'routineIdentifier':
                    temp_routine_identifier = param_name
                data_index += function['numBytes']
            elif (function['type'] == 'optional' and
                  function['numBytes'] == 'variable'):
                if (func_name == 'scalingByteExtension' and
                        temp_scaling_byte_data_type in function['dependentOnValues']):
                    func_data = (
                        uds_data[data_index * 2:temp_length_scaling_byte * 2
                                                + data_index * 2]
                    )
                    decoded += '            value: 0x' + func_data + '\n'
                    data_index += temp_length_scaling_byte
                else:
                    decoded += '            optional value - not used' + '\n'
                    continue
            elif (function['type'] == 'NA' and
                  function['numBytes'] == 'variable'):
                if func_name == 'memoryAddress':
                    func_data = (
                        uds_data[data_index * 2:temp_length_of_memory_address * 2 + data_index * 2]
                    )
                    decoded += '            value: 0x' + func_data + '\n'
                    data_index += temp_length_of_memory_address
                elif (func_name == 'memorySize' and
                      service['service'] == 'DynamicallyDefineDataIdentifier' and
                      subfunction == 1):
                    func_data = uds_data[data_index * 2:1 * 2 + data_index * 2]
                    decoded += (
                            '            value: ' +
                            str(int(func_data, 16)) +
                            ' bytes\n'
                    )
                    data_index += 1
                elif func_name == 'memorySize':
                    func_data = (
                        uds_data[data_index * 2:temp_length_of_memory_size * 2 + data_index * 2]
                    )
                    decoded += (
                            '            value: ' +
                            str(int(func_data, 16)) +
                            ' bytes\n'
                    )
                    data_index += temp_length_of_memory_size
                elif (func_name == 'securitySeed' or
                      func_name == 'securityAccessDataOrKey' or
                      func_name == 'routineStatusRecord' or
                      func_name == 'routineControlOptionRecord' or
                      (func_name == 'maxNumberOfBlockLength'
                       and service['service'] != 'RequestFileTransfer') or
                      func_name == 'transferRequestParameterRecord' or
                      func_name == 'transferResponseParameterRecord' or
                      (func_name == 'dataRecord'
                       and service['service'] == 'WriteMemoryByAddress') or
                      func_name == 'serviceToRespondToRecord'):
                    func_data = uds_data[data_index * 2:]
                    decoded += '            value: 0x' + func_data + '\n'
                    data_index = len(uds_data) / 2 + 1
                elif func_name == 'filePathAndName':
                    func_data = (
                        uds_data[data_index * 2:temp_length_file_path_and_name * 2
                                                + data_index * 2]
                    )
                    bytes_object = bytes.fromhex(func_data)
                    decoded += (
                            '            value: ' +
                            bytes_object.decode("ASCII") +
                            '\n'
                    )
                    data_index += temp_length_file_path_and_name
                elif (func_name == 'fileSizeUncompressed' or
                      func_name == 'fileSizeCompressed'):
                    func_data = (
                        uds_data[data_index * 2:temp_length_file_size_parameter * 2
                                                + data_index * 2]
                    )
                    decoded += (
                            '            value: ' +
                            str(int(int(func_data, 16) / 1000)) +
                            ' Kbyte\n'
                    )
                    data_index += temp_length_file_size_parameter
                elif func_name == 'maxNumberOfBlockLength':
                    func_data = (
                        uds_data[data_index * 2:temp_length_max_number_of_block_length * 2
                                                + data_index * 2]
                    )
                    decoded += (
                            '            value: ' +
                            str(int(int(func_data, 16))) +
                            ' bytes\n'
                    )
                    data_index += temp_length_max_number_of_block_length
                elif func_name == 'eventTypeRecord':
                    func_data = (
                        uds_data[data_index * 2:temp_length_event_type_record * 2
                                                + data_index * 2]
                    )
                    decoded += '            value: 0x' + func_data + '\n'
                    data_index += temp_length_event_type_record
                else:
                    decoded += '            length is variable' + '\n'
                    data_index = len(uds_data) / 2 + 1
        return decoded


class MessageManagement:
    def __init__(self):
        self._conversations = []
        self._lock_conversations = threading.RLock()

        self._uds_conversations = []
        self._lock_uds_conversations = threading.RLock()

    def reset_conversations(self):
        with self._lock_conversations:
            self._conversations = []
        with self._lock_uds_conversations:
            self._uds_conversations = []

    def find_full_multipacket_message(self):
        self._lock_conversations.acquire()
        for i in range(0, len(self._conversations)):
            # Found one ready to send - return it
            if self._conversations[i].readyToSend:
                message = self._conversations[i].completeMessage
                del self._conversations[i]
                self._lock_conversations.release()
                return message
        self._lock_conversations.release()

    def find_full_isotp_message(self):
        self._lock_uds_conversations.acquire()
        for i in range(0, len(self._uds_conversations)):
            # Found one ready to send - return it
            if self._uds_conversations[i].readyToSend:
                message = self._uds_conversations[i].completeMessage
                del self._uds_conversations[i]
                self._lock_uds_conversations.release()
                return message
        self._lock_uds_conversations.release()

    def add_new_conversation(self, message):
        with self._lock_conversations:
            self._conversations.append(message)

    def add_to_existing_conversation(self, message):
        # Find the correct conversation
        self._lock_conversations.acquire()
        for i in range(0, len(self._conversations)):
            # Correct conversation found
            if self._conversations[i].completeMessage.src_addr == message.src_addr \
                    and self._conversations[i].completeMessage.dst_addr == message.dst_addr:
                self._conversations[i].received_packets += 1
                # Received all the packets
                if self._conversations[i].complete:
                    bytes_left = (self._conversations[i].num_bytes - self._conversations[i].received_bytes)
                    self._conversations[i].received_bytes += bytes_left
                    data_index = (bytes_left * 2) + 2
                    # Copy final bytes
                    self._conversations[i].completeMessage.data += message.data[2:data_index]
                    # Ready to send next time a message is read
                    self._conversations[i].readyToSend = True
                    # More packets needed, add 7 bytes of data to stored message
                else:
                    self._conversations[i].received_bytes += 7
                    # Skip first byte, this is counter
                    self._conversations[i].completeMessage.data += message.data[2:16]
                break
        self._lock_conversations.release()

    def add_new_isotp_conversation(self, message):
        with self._lock_uds_conversations:
            self._uds_conversations.append(message)

    def add_to_existing_isotp_conversation(self, message):
        self._lock_uds_conversations.acquire()
        for i in range(0, len(self._uds_conversations)):
            # Correct UDS message
            if self._uds_conversations[i].completeMessage.src_addr == message.src_addr and \
                    self._uds_conversations[i].completeMessage.dst_addr == message.dst_addr:
                # The index of this received message
                index_byte = int(message.data[1:2], 16)
                # Correct order of data received
                if index_byte == self._uds_conversations[i].nextExpectedIndex:
                    # Received all data bytes (including the current packet)
                    if self._uds_conversations[i].complete(curr_received=7):
                        bytes_left = (
                                self._uds_conversations[i].num_bytes -
                                self._uds_conversations[i].received_bytes
                        )
                        self._uds_conversations[i].received_bytes += bytes_left
                        data_index = int((bytes_left * 2) + 2)
                        # Copy final bytes
                        self._uds_conversations[i].completeMessage.data += message.data[2:data_index]
                        self._uds_conversations[i].completeMessage.total_bytes = (
                                len(self._uds_conversations[i].completeMessage.data) / 2
                        )
                        # Ready to send next time a message is read
                        self._uds_conversations[i].readyToSend = True
                        # More packets needed, add 7 bytes of data
                    # to stored message
                    else:
                        self._uds_conversations[i].received_bytes += 7
                        self._uds_conversations[i].completeMessage.data += message.data[2:16]
                        # If indexByte is 15, we start back over
                        # at 0 for next sequence number
                        if index_byte == 15:
                            self._uds_conversations[i].nextExpectedIndex = 0
                        else:
                            self._uds_conversations[i].nextExpectedIndex += 1
                    break
                    # Something happened, delete?
                else:
                    del self._uds_conversations[i]
        self._lock_uds_conversations.release()

class J1939Message:
    def __init__(self, can_id: int, data: str, total_bytes=None):
        """

        """
        if can_id < 0 or can_id > 0x1FFFFFFF:
            raise ValueError("invalid CAN ID")
        try:
            if len(data) > 0:
                int(data, 16)
        except ValueError:
            raise ValueError('Data must be in hexadecimal format')
        if (len(data) % 2 != 0 or
                len(data) > 3570):
            raise ValueError('Length of data must be an even number and shorter than 1785 bytes')
        if total_bytes is None:
            total_bytes = len(data) / 2
        self._can_id = can_id
        self._data = data
        self._total_bytes = int(total_bytes)

    @property
    def can_id(self):
        return self._can_id

    @can_id.setter
    def can_id(self, value):
        if value < 0 or value > 0x1FFFFFFF:
            raise ValueError("invalid CAN ID")
        self._can_id = value

    @property
    def priority(self):
        return self._can_id >> 26

    @priority.setter
    def priority(self, value):
        if value < 0 or value > 7:
            raise ValueError("priority is between 0-7")
        self._can_id = j1939_fields_to_can_id(value, self.reserved_bit, self.data_page_bit, self.pdu_format,
                                              self.pdu_specific, self.src_addr)

    @property
    def reserved_bit(self):
        return self._can_id >> 25 & 1

    @reserved_bit.setter
    def reserved_bit(self, value):
        if value < 0 or value > 1:
            raise ValueError("reserved bit is either 0 or 1")
        self._can_id = j1939_fields_to_can_id(self.priority, value, self.data_page_bit, self.pdu_format,
                                              self.pdu_specific, self.src_addr)

    @property
    def data_page_bit(self):
        return self._can_id >> 24 & 1

    @data_page_bit.setter
    def data_page_bit(self, value):
        if value < 0 or value > 1:
            raise ValueError("data page bit is either 0 or 1")
        self._can_id = j1939_fields_to_can_id(self.priority, self.reserved_bit, value, self.pdu_format,
                                              self.pdu_specific, self.src_addr)

    @property
    def pdu_format(self):
        return self._can_id >> 16 & 0xFF

    @pdu_format.setter
    def pdu_format(self, value):
        if value < 0 or value > 0xFF:
            raise ValueError("pdu format is between 0-255")
        self._can_id = j1939_fields_to_can_id(self.priority, self.reserved_bit, self.data_page_bit, value,
                                              self.pdu_specific, self.src_addr)

    @property
    def pdu_specific(self):
        return self._can_id >> 8 & 0xFF

    @pdu_specific.setter
    def pdu_specific(self, value):
        if value < 0 or value > 0xFF:
            raise ValueError("pdu specific is between 0-255")
        self._can_id = j1939_fields_to_can_id(self.priority, self.reserved_bit, self.data_page_bit, self.pdu_format,
                                              value, self.src_addr)

    @property
    def src_addr(self):
        return self._can_id & 0xFF

    @src_addr.setter
    def src_addr(self, value):
        if value < 0 or value > 0xFF:
            raise ValueError("source address is between 0-255")
        self._can_id = j1939_fields_to_can_id(self.priority, self.reserved_bit, self.data_page_bit, self.pdu_format,
                                              self.pdu_specific, value)

    @property
    def pgn(self):
        pgn = self._can_id >> 8 & 0xFFFF
        if pgn < 0xF000:
            return self._can_id >> 8 & 0xFF00
        return pgn

    @property
    def dst_addr(self):
        if self.pdu_format < 0xF0:
            return self.pdu_specific
        return 0xFF

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value: str):
        try:
            if len(value) > 0:
                int(value, 16)
        except ValueError:
            raise ValueError('Data must be in hexadecimal format')
        if (len(value) % 2 != 0 or
                len(value) > 3570):
            raise ValueError('Length of data must be an even number and shorter than 1785 bytes')
        self._data = value

    @property
    def total_bytes(self):
        return self._total_bytes

    @total_bytes.setter
    def total_bytes(self, value):
        self._total_bytes = value

    def __str__(self):
        """
        Overrides default str method to return the parsed message
        example: "priority  pgn  src_addr --> dst_addr  [total_bytes]  data"
        """
        return hex(self.can_id) + "  %02X %04X %02X --> %02X [%d]  %s" % (self.priority, self.pgn,
                                                                            self.src_addr, self.dst_addr,
                                                                            self.total_bytes, self.data.upper())


class _J1939MultiPacketMessage:
    """
    Creates a new multipacket message - for internal use only to deal with Transport Protocol

    :param first_message: a J1939_Message object to initialize the multipacket message
    """

    def __init__(self, first_message=None):
        if isinstance(first_message, J1939Message) is False or first_message is None:
            raise Exception('Must include an instance of a J1939_Message')

        self.num_bytes = int(first_message.data[4:6] + first_message.data[2:4], 16)
        self.num_packets = int(first_message.data[6:8], 16)
        self.received_packets = 0
        self.received_bytes = 0

        pdu_format = int(first_message.data[12:14], 16)
        if pdu_format > 0xEF:
            pdu_specific = int(first_message.data[10:12], 16)
        else:
            pdu_specific = first_message.dst_addr

        total_bytes = self.num_bytes
        data = ""
        can_id = j1939_fields_to_can_id(first_message.priority, 0, 0, pdu_format, pdu_specific, first_message.src_addr)

        # Create new message with TP abstracted
        self.completeMessage = J1939Message(can_id, data, total_bytes)
        # Multipacket message not completed
        self.readyToSend = False

    @property
    def complete(self):
        # If all expected packets have been added to multipacket message
        if self.received_packets == self.num_packets:
            return True
        else:
            return False


class _J1939ISOTPMessage:
    #TODO: fix and test this
    """
    Creates a new ISO-TP (ISO 15765-2) message - for internal use only to deal with long UDS messages

    :param first_message: a J1939_Message object to initialize the ISO-TP message
    """

    def __init__(self, first_message=None):
        if (isinstance(first_message, J1939Message) == False or
                first_message is None):
            raise Exception('Must include an instance of a J1939_Message')

        # Between 8 and 4095 bytes
        self.num_bytes = int(first_message.data[1:4], 16)

        priority = first_message.priority
        pgn = 0xDA00
        dst_addr = first_message.dst_addr
        src_addr = first_message.src_addr
        # Add 40 for truckdevil decoder to know this is a created ISO-TP
        # message, not a properly formatted one
        data = '40' + first_message.data[4:]

        self.received_bytes = (len(data) - 2) / 2

        self.nextExpectedIndex = 1

        # Create new message
        self.completeMessage = J1939Message(
            priority, pgn,
            dst_addr, src_addr,
            data
        )

        # ISO TP message not ready to send
        self.readyToSend = False

    def complete(self, curr_received=0):
        # If all expected data has been received
        if self.received_bytes + curr_received >= self.num_bytes:
            return True
        else:
            return False
