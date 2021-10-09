import serial
import threading
import time
import math
import copy
import json
import os
import can


class J1939Interface:
    def __init__(self, device):
        """
        Initializes truckdevil

        :param device_type: either "m2" or "socketcan" (Default value = 'm2').
        :param port: serial port that the M2 is connected to, if used. For example: COM7 or /dev/ttyX. 0 if not using M2."
        :param channel: CAN channel to send/receive on. For example: can0, can1, or vcan0. (Default value = 'can0')
        :param can_baud: baudrate on the CAN bus. Most common are 250000 and 500000. Use 0 for autobaud detection. (Default value = 0)
        """
        self._device = device
        if device.m2_used:
            self._lockM2 = threading.RLock()

        self._conversations = []
        self._lockConversations = threading.RLock()

        self._UDSconversations = []
        self._lockUDSConversations = threading.RLock()

        self._dataCollectionOccurring = False

        self._collectedMessages = []
        self._lockCollectedMessages = threading.RLock()

        self._collectionThread = None

        self._printMessagesTimeDone = False
        self._printMessagesTimer = None

        self._pgn_list = {}
        with open(os.path.join('resources', 'json_files', 'pgn_list.json')) as pgn_file:
            self._pgn_list = json.load(pgn_file)

        self._spn_list = {}
        with open(os.path.join('resources', 'json_files', 'spn_list.json')) as spn_file:
            self._spn_list = json.load(spn_file)

        self._src_addr_list = {}
        with open(os.path.join('resources', 'json_files', 'src_addr_list.json')) \
                as src_addr_file:
            self._src_addr_list = json.load(src_addr_file)

        self._bit_decoding_list = {}
        with open(os.path.join('resources', 'json_files', 'dataBitDecoding.json')) \
                as bit_decoding_file:
            self._bit_decoding_list = json.load(bit_decoding_file)

        self._UDS_services_list = {}
        with open(os.path.join('resources', 'json_files', 'UDS_services.json')) \
                as UDS_services_file:
            self._UDS_services_list = json.load(UDS_services_file)

        self._UDS_functions_list = {}
        with open(os.path.join('resources', 'json_files', 'UDS_functions.json')) \
                as UDS_functions_file:
            self._UDS_functions_list = json.load(UDS_functions_file)

        self._UDS_NRC_list = {}
        with open(os.path.join('resources', 'json_files', 'UDS_NRC.json')) \
                as UDS_NRC_file:
            self._UDS_NRC_list = json.load(UDS_NRC_file)

    def start_data_collection(self, abstractTPM=True):
        """
        Starts reading and storing messages

        :param abstractTPM: whether to abstract multipacket messages or instead to show all Transport Protocol messages (Default value = True)
        """
        if self._dataCollectionOccurring:
            raise Exception('data collection already started')
        with self._lockCollectedMessages:
            self._collectedMessages = []

        self._dataCollectionOccurring = True

        if self._collectionThread is None or self._collectionThread.is_alive() is False:
            # If collectionThread hasn't been started before
            self._collectionThread = threading.Thread(
                target=self._readMessage, args=(abstractTPM,),
                daemon=True
            )
            self._collectionThread.start()

    def get_collected_data(self):
        """
        Gets all of the messages that have been collected

        :return: the collectedMessages list
        """
        with self._lockCollectedMessages:
            messages = self._collectedMessages
        return messages

    def stop_data_collection(self):
        """
        Stops reading and storing messages, resets all data

        :returns: the collectedMessages list
        """
        if not self._dataCollectionOccurring:
            raise Exception('data collection is already stopped')
        self._dataCollectionOccurring = False
        with self._lockConversations:
            self._conversations = []
        with self._lockUDSConversations:
            self._UDSconversations = []
        with self._lockCollectedMessages:
            data_collected = self._collectedMessages
            self._collectedMessages = []
        return data_collected

    def save_data_collected(self, messages, file_name=None, verbose=False):
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
        if (str(message.src_addr) in self._src_addr_list) and (str(message.dst_addr) in self._src_addr_list):
            decoded += (
                    '    ' + self._src_addr_list[str(message.src_addr)] +
                    " --> " + self._src_addr_list[str(message.dst_addr)] +
                    '\n'
            )
        # Only include this portion if the pgn of the message is in pgn_list
        if str(message.pgn) in self._pgn_list:
            decoded += (
                    '    PGN(' + str(message.pgn) + '): ' +
                    self._pgn_list[str(message.pgn)]['acronym'] +
                    '\n'
            )
            decoded += (
                    '      Label: ' +
                    self._pgn_list[str(message.pgn)]['parameterGroupLabel'] +
                    '\n'
            )
            if message.pgn == 0xDA00:
                try:
                    decoded += self._UDSDecode(message)
                except (ValueError, UnboundLocalError):
                    decoded += '      Cannot decode UDS message, incorrect form'
                return decoded
            decoded += (
                    '      PGNDataLength: ' +
                    str(self._pgn_list[str(message.pgn)]['pgnDataLength']) +
                    '\n'
            )
            decoded += (
                    '      TransmissionRate: ' +
                    self._pgn_list[str(message.pgn)]['transmissionRate'] +
                    '\n'
            )
            # Only decode data if it matches the num bytes it's supposed to
            if (self._pgn_list[str(message.pgn)]['pgnDataLength']
                    == len(message.data) / 2):
                # For each spn that is part the given pgn
                for spn in self._pgn_list[str(message.pgn)]['spnList']:
                    # Only include this portion if the spn is in the spn_list
                    if str(spn) in self._spn_list:
                        decoded += (
                                '      SPN(' +
                                str(spn) + '): ' +
                                self._spn_list[str(spn)]['spnName'] +
                                '\n'
                        )
                        # Ensure it's not a variable length SPN
                        if (self._spn_list[str(spn)]['spnLength']
                                != "variable"):
                            total_bits = self._spn_list[str(spn)]['spnLength']
                            start_bit = self._spn_list[str(spn)]['bitPositionStart']
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
                                if (self._spn_list[str(spn)]['units'] == 'bit'
                                        and str(spn)
                                        in self._bit_decoding_list):
                                    decoded += (
                                            '        ' + str(int(bin_data, 2)) +
                                            ' : ' +
                                            self._bit_decoding_list[str(spn)][str(int(bin_data, 2))] +
                                            '\n'
                                    )
                                # if ascii data type, convert
                                elif self._spn_list[str(spn)]['units'] == 'ASCII':
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
                                                 (self._spn_list[str(spn)]['resolutionNumerator'] /
                                                  self._spn_list[str(spn)]['resolutionDenominator'])) +
                                                self._spn_list[str(spn)]['offset']
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
                                            self._spn_list[str(spn)]['units'] +
                                            '\n'
                                    )
            # Otherwise add a message that it's not the correct form
            else:
                decoded += '      Cannot decode SPNs\n'
        return decoded

    def print_messages(self, abstract_tpm=True, read_time=None, num_messages=None, verbose=False, log_to_file=False):
        """
        Read and print all messages from M2. If readTime and numMessages are both specified, stop printing when whichever one is reached first.

        :param abstract_tpm: whether to abstract multipacket messages or instead to show all Transport Protocol messages (Default value = True)
        :param read_time: the amount of time to print messages for. If not specified, it will not be limited
        :param num_messages: number of messages to print before stopping. If not specified, it will not be limited
        :param verbose: whether or not to print the message in decoded form (Default value = False)
        :param log_to_file: whether or not to log the messages to a file (Default value = False)
        """
        # Only allow if data collection is not occurring
        if self._dataCollectionOccurring:
            raise Exception('stop data collection before proceeding with this function')
        # If optional readTime is utilized
        if read_time is not None:
            self._printMessagesTimer = threading.Timer(
                read_time, self._setPrintMessagesTimeDone
            )
            self._printMessagesTimer.start()
        messages_printed = 0
        with self._lockConversations:
            self._conversations = []
        with self._lockUDSConversations:
            self._UDSconversations = []
        self._printMessagesTimeDone = False
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
        while (self._printMessagesTimeDone == False and
               (num_messages is None or messages_printed < num_messages)):
            # Only allow if data collection is not occurring
            if self._dataCollectionOccurring:
                raise Exception(
                    """data collection began abruptly, stop data collection 
                    before proceeding with this function"""
                )
            # Look for full multipacket message to return first
            self._lockConversations.acquire()
            for i in range(0, len(self._conversations)):
                # Found one ready to send - return it
                if self._conversations[i].readyToSend:
                    message = self._conversations[i].completeMessage
                    del self._conversations[i]
                    if not verbose:
                        # Print completed multipacket message
                        print(message)
                        if log_to_file:
                            log_file.write(str(message) + '\n')
                    else:
                        # Print the completed multipacket message in decoded form
                        print(self.get_decoded_message(message))
                        if log_to_file:
                            log_file.write(
                                self.get_decoded_message(message) +
                                '\n'
                            )
                    messages_printed = messages_printed + 1
                    break
            self._lockConversations.release()

            # Look for full ISO-TP message to return next
            self._lockUDSConversations.acquire()
            for i in range(0, len(self._UDSconversations)):
                # Found one ready to send - return it
                if self._UDSconversations[i].readyToSend:
                    message = self._UDSconversations[i].completeMessage
                    del self._UDSconversations[i]
                    if not verbose:
                        # Print the completed ISO-TP message
                        print(message)
                        if log_to_file:
                            log_file.write(
                                str(message) +
                                '\n'
                            )
                    else:
                        # Print the completed ISO-TP message in decoded form
                        print(self.get_decoded_message(message))
                        if log_to_file:
                            log_file.write(
                                self.get_decoded_message(message) +
                                '\n'
                            )
                    messages_printed = messages_printed + 1
                    break
            self._lockUDSConversations.release()

            # Get one CAN message from M2 (ex: 18EF0B00080102030405060708)
            can_msg = self._device.read()
            """
            can_packet = self._readOneMessage()

            # src_addr is byte 4
            src_addr = int(can_packet[6:8], 16)

            # pgn is byte 2 and 3, where byte 2 is pdu_format and
            # byte 3 is pdu_specific
            pgn = can_packet[2:6]

            pdu_format = int(pgn[0:2], 16)
            pdu_specific = int(pgn[2:4], 16)

            # If pdu_format is 0-239 then pdu_specific is dst_addr,
            # otherwise it is group extension
            if pdu_format < 240:
                dst_addr = pdu_specific
                # Add 00 to pgn if destination specific
                # (ex: EC0B pgn becomes EC00 with dst_addr 0x0B)
                pgn = pgn[0:2] + "00"
            else:
                # Broadcast message
                dst_addr = 0xFF

            pgn = int(pgn, 16)

            # priority is bits 4-6 in byte 1 of message
            # (ex: byte 1 = 0x18, 0b00011000 = priority of 6)
            priority = int(int(can_packet[0:2], 16) / 4)

            # dlc (data length) is byte 5
            dlc = int(can_packet[8:10], 16)
            
            # data is contained in bytes 6-13, in hex string format
            data = can_packet[10:26]

            message = J1939Message(
                priority, pgn,
                dst_addr, src_addr,
                data, dlc
            )
            """
            data = ''.join('{:02x}'.format(x) for x in can_msg.data)
            j1939_message = J1939Message(can_msg.arbitration_id, data)

            # Multipacket message received, broadcasted or
            # peer-to-peer request to send
            if j1939_message.pgn == 0xec00 and (j1939_message.data[0:2] == "20" or j1939_message.data[0:2] == "10"):
                mp_message = _J1939MultiPacketMessage(j1939_message)
                with self._lockConversations:
                    self._conversations.append(mp_message)
                # If abstractTPM is True, break and don't print this message
                if abstract_tpm:
                    continue

            # Multipacket data transfer message received
            if j1939_message.pgn == 0xeb00:
                # Find the correct conversation
                self._lockConversations.acquire()
                for i in range(0, len(self._conversations)):
                    # Correct conversation found
                    if self._conversations[i].completeMessage.src_addr == j1939_message.src_addr \
                            and self._conversations[i].completeMessage.dst_addr == j1939_message.dst_addr:
                        self._conversations[i].received_packets += 1
                        # Received all the packets
                        if self._conversations[i].complete():
                            bytes_left = (self._conversations[i].num_bytes - self._conversations[i].received_bytes)
                            self._conversations[i].received_bytes += bytes_left
                            data_index = (bytes_left * 2) + 2
                            # Copy final bytes
                            self._conversations[i].completeMessage.data += j1939_message.data[2:data_index]
                            # Ready to send next time a message is read
                            self._conversations[i].readyToSend = True
                            # More packets needed, add 7 bytes of data to stored message
                        else:
                            self._conversations[i].received_bytes += 7
                            # Skip first byte, this is counter
                            self._conversations[i].completeMessage.data += j1939_message.data[2:16]
                        break
                self._lockConversations.release()
                # If abstractTPM is True, continue and don't print this message
                if abstract_tpm:
                    continue
            # UDS ISO-TP message received, first frame
            if j1939_message.pgn == 0xda00 and j1939_message.data[0:1] == '1':
                iso_tp_message = _J1939ISOTPMessage(j1939_message)
                with self._lockUDSConversations:
                    self._UDSconversations.append(iso_tp_message)
                # If abstractTPM is True, break and don't print this message
                if abstract_tpm:
                    continue
            # UDS ISO-TP message received, consecutive frame
            elif j1939_message.pgn == 0xda00 and j1939_message.data[0:1] == '2':
                self._lockUDSConversations.acquire()
                for i in range(0, len(self._UDSconversations)):
                    # Correct UDS message
                    if self._UDSconversations[i].completeMessage.src_addr == j1939_message.src_addr and \
                            self._UDSconversations[i].completeMessage.dst_addr == j1939_message.dst_addr:
                        # The index of this received message
                        index_byte = int(j1939_message.data[1:2], 16)
                        # Correct order of data received
                        if index_byte == self._UDSconversations[i].nextExpectedIndex:
                            # Received all data bytes (including the current packet)
                            if self._UDSconversations[i].complete(curr_received=7):
                                bytes_left = (
                                        self._UDSconversations[i].num_bytes -
                                        self._UDSconversations[i].received_bytes
                                )
                                self._UDSconversations[i].received_bytes += bytes_left
                                data_index = int((bytes_left * 2) + 2)
                                # Copy final bytes
                                self._UDSconversations[i].completeMessage.data += j1939_message.data[2:data_index]
                                self._UDSconversations[i].completeMessage.total_bytes = (
                                        len(self._UDSconversations[i].completeMessage.data) / 2
                                )
                                # Ready to send next time a message is read
                                self._UDSconversations[i].readyToSend = True
                                # More packets needed, add 7 bytes of data
                            # to stored message
                            else:
                                self._UDSconversations[i].received_bytes += 7
                                self._UDSconversations[i].completeMessage.data += j1939_message.data[2:16]
                                # If indexByte is 15, we start back over
                                # at 0 for next sequence number
                                if index_byte == 15:
                                    self._UDSconversations[i].nextExpectedIndex = 0
                                else:
                                    self._UDSconversations[i].nextExpectedIndex += 1
                            break
                            # Something happened, delete?
                        else:
                            del self._UDSconversations[i]
                self._lockUDSConversations.release()
                # If abstractTPM is True, break and don't print this message
                if abstract_tpm:
                    continue
            # UDS ISO-TP message received, flow control frame
            elif j1939_message.pgn == 0xda00 and j1939_message.data[0:1] == '3':
                # If abstractTPM is True, break and don't print this message
                if abstract_tpm:
                    continue
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
            self._printMessagesTimer.cancel()

    def readMessagesUntil(self, data_contains=None,
                          target_src_addr=None, target_dst_addr=None,
                          target_pgn=None):
        """
        Read all messages from M2 until a specific message is found, atleast one parameter should be specified to look for.

        :param data_contains: if specified, the message must contain this hex string in the data portion, ex: "010203"
        :param target_src_addr: if specified, the message must have a src_addr of this parameter, ex: 0xF9
        :param target_dst_addr: if specified, the message must have a dst_addr of this parameter, ex: 0x0B
        :param target_pgn: if specified, the message must have a pgn of this parameter, ex: 0xF004
        :returns: both the message that matched the specified parameters, and the list of messages that were collected while searching
        """
        if (data_contains is None and
                target_src_addr is None and
                target_dst_addr is None and
                target_pgn is None):
            raise Exception("""atleast one parameter (dataContains, 
                src_addr, dst_addr, pgn) must be included"""
                            )

        conversations = []
        UDS_conversations = []
        collectedMessages = []
        while True:
            # Look for full multipacket message to return first,
            # if none found, receive from socket
            for i in range(0, len(conversations)):
                # Found one ready to send - return it
                if conversations[i].readyToSend:
                    message = conversations[i].completeMessage
                    del conversations[i]
                    # Add completed multipacket message to collectedMessages list
                    collectedMessages.append(message)
                    if ((data_contains is None or data_contains in message.data) and
                            (target_src_addr is None or message.src_addr == target_src_addr) and
                            (target_dst_addr is None or message.dst_addr == target_dst_addr) and
                            (target_pgn is None or message.pgn == target_pgn)):
                        return message, collectedMessages
                    break

            # Look for full ISO-TP message to return next,
            # if none found, receive from socket
            for i in range(0, len(UDS_conversations)):
                # Found one ready to send - return it
                if UDS_conversations[i].readyToSend:
                    message = UDS_conversations[i].completeMessage
                    del UDS_conversations[i]
                    # Add completed ISO-TP message to collectedMessages list
                    collectedMessages.append(message)
                    if ((data_contains is None or data_contains in message.data) and
                            (target_src_addr is None or message.src_addr == target_src_addr) and
                            (target_dst_addr is None or message.dst_addr == target_dst_addr) and
                            (target_pgn is None or message.pgn == target_pgn)):
                        return message, collectedMessages
                    break

            # Get one CAN message from M2 (ex: 18EF0B00080102030405060708)
            can_packet = self._readOneMessage()

            # src_addr is byte 4
            src_addr = int(can_packet[6:8], 16)

            # pgn is byte 2 and 3, where byte 2 is pdu_format
            # and byte 3 is pdu_specific
            pgn = can_packet[2:6]

            pdu_format = int(pgn[0:2], 16)
            pdu_specific = int(pgn[2:4], 16)

            # If pdu_format is 0-239 then pdu_specific is dst_addr,
            # otherwise it is group extension
            if pdu_format < 240:
                dst_addr = pdu_specific
                # Add 00 to pgn if destination specific
                # (ex: EC0B pgn becomes EC00 with dst_addr 0x0B)
                pgn = pgn[0:2] + "00"
            else:
                # Broadcast message
                dst_addr = 0xFF
            pgn = int(pgn, 16)

            # priority is bits 4-6 in byte 1 of message
            # (ex: byte 1 = 0x18, 0b00011000 = priority of 6)
            priority = int(int(can_packet[0:2], 16) / 4)

            # dlc (data length) is byte 5
            dlc = int(can_packet[8:10], 16)

            # data is contained in bytes 6-13, in hex string format
            data = can_packet[10:26]
            message = J1939Message(
                priority, pgn,
                dst_addr, src_addr,
                data, dlc
            )

            # Multipacket message received, broadcasted or
            # peer-to-peer request to send
            if (pgn == 0xec00 and
                    (data[0:2] == "20" or data[0:2] == "10")):
                mp_message = _J1939MultiPacketMessage(message)
                conversations.append(mp_message)

            # Multipacket data transfer message recieved
            if pgn == 0xeb00:
                # Find the correct conversation
                for i in range(0, len(conversations)):
                    # Found correct conversation
                    if (conversations[i].completeMessage.src_addr == src_addr and
                            conversations[i].completeMessage.dst_addr == dst_addr):
                        conversations[i].received_packets += 1
                        # Received all the packets
                        if conversations[i].complete():
                            bytes_left = (
                                    conversations[i].num_bytes
                                    - conversations[i].received_bytes
                            )
                            conversations[i].received_bytes += bytes_left
                            data_index = (bytes_left * 2) + 2
                            # Copy final bytes
                            conversations[i].completeMessage \
                                .data += data[2:data_index]
                            # Ready to send next time a message is read
                            conversations[i].readyToSend = True
                            # More packets needed, add 7 bytes of data to stored message
                        else:
                            conversations[i].received_bytes += 7
                            # Skip first byte, this is counter
                            conversations[i].completeMessage \
                                .data += data[2:16]
                        break

                        # UDS ISO-TP message received, first frame
            if (pgn == 0xda00 and
                    message.data[0:1] == '1'):
                iso_tp_message = _J1939ISOTPMessage(message)
                UDS_conversations.append(iso_tp_message)

            # UDS ISO-TP message recieved, consecutive frame
            elif (pgn == 0xda00 and
                  message.data[0:1] == '2'):
                # Find the correct conversation
                for i in range(0, len(UDS_conversations)):
                    # Correct UDS message
                    if (UDS_conversations[i].completeMessage.src_addr == src_addr and
                            UDS_conversations[i].completeMessage.dst_addr == dst_addr):
                        # The index of this received message
                        indexByte = int(message.data[1:2], 16)
                        # Correct order of data received
                        if indexByte == UDS_conversations[i].nextExpectedIndex:
                            # Received all data bytes (including the current packet)
                            if UDS_conversations[i].complete(curr_received=7):
                                bytes_left = (
                                        UDS_conversations[i].num_bytes -
                                        UDS_conversations[i].received_bytes
                                )
                                UDS_conversations[i].received_bytes += bytes_left
                                data_index = int((bytes_left * 2) + 2)
                                # Copy final bytes
                                UDS_conversations[i].completeMessage \
                                    .data += data[2:data_index]
                                UDS_conversations[i].completeMessage.total_bytes = (
                                        len(UDS_conversations[i].completeMessage.data) / 2
                                )
                                # Ready to send next time a message is read
                                UDS_conversations[i].readyToSend = True
                                # More packets needed, add 7 bytes of data
                            # to stored message
                            else:
                                UDS_conversations[i].received_bytes += 7
                                UDS_conversations[i].completeMessage \
                                    .data += data[2:16]
                                # If indexByte is 15, we start back over
                                # at 0 for next sequence number
                                if indexByte == 15:
                                    UDS_conversations[i].nextExpectedIndex = 0
                                else:
                                    UDS_conversations[i].nextExpectedIndex += 1
                            break
                            # Something happened, delete?
                        else:
                            del UDS_conversations[i]
                            # Add message to collectedMessages list
            collectedMessages.append(message)
            # If the message matches the one we're looking for
            if ((data_contains is None or data_contains in message.data) and
                    (target_src_addr is None or message.src_addr == target_src_addr) and
                    (target_dst_addr is None or message.dst_addr == target_dst_addr) and
                    (target_pgn is None or message.pgn == target_pgn)):
                return message, collectedMessages

    def _sendMessageM2(self, message):
        """
        Send message to M2 to get pushed to the BUS.

        :param message: a J1939_Message to be sent on the BUS
        """
        # can_packet = "$18EF0B00080102030405060708*"
        # Add start delimiter - used by M2
        can_packet = "$"
        # pri is bits 4-6 in byte 1 of message
        # (ex: byte 1 = 0x18, 0b00011000 = priority of 6)
        pri = (hex(int('000'
                       + bin(message.priority)[2:].zfill(3)
                       + '00', 2))[2:4].zfill(2).upper())

        can_packet += pri
        # Get total number of bytes to send
        data_bytes = int(len(message.data) / 2)

        dst_addr = hex(message.dst_addr)[2:].zfill(2).upper()
        pgn = hex(message.pgn)[2:].zfill(4).upper()
        src_addr = hex(message.src_addr)[2:].zfill(2).upper()
        dlc = hex(data_bytes)[2:].zfill(2)
        data = message.data.upper()

        # Sending multipacket message - if number of bytes to send is
        # more than 8 (ex: 1CECFF000820120003FFCAFE00)
        if data_bytes > 8:
            # EC is byte 2
            can_packet += 'EC'
            # Change int to 4 character hex string
            num_bytes = "%04X" % data_bytes
            num_packets = "%02X" % math.ceil(data_bytes / 7)
            # Destination address is byte 3
            can_packet += dst_addr
            # Source address is byte 4
            can_packet += src_addr
            # Data length (dlc) is byte 5
            # (multipacket messages are always 8 bytes each)
            can_packet += '08'

            if message.dst_addr == 0xFF:
                # Send BAM message (ex: 20120003FFCAFE00)
                control_message = ("20" + num_bytes[2:4] + num_bytes[0:2]
                                   + num_packets + "FF" + pgn[2:4] + pgn[0:2] + "00")
            else:
                # Send RTS message
                control_message = ("10" + num_bytes[2:4] + num_bytes[0:2]
                                   + num_packets + "FF" + pgn[2:4] + pgn[0:2] + "00")
            # Bytes 6-13 is the control message
            can_packet += control_message
            # Add end delimiter, in use by M2
            can_packet += "*"
            with self._lockM2:
                # Send BAM or RTS message
                self._m2.write(can_packet.encode('utf-8'))
            if message.dst_addr == 0xFF:
                # Sleep 100ms before transmitting next message as
                # stated in standard
                time.sleep(0.1)
            else:
                # Sleep 150ms before transmitting next message to
                # allow for CTS to come through
                time.sleep(0.15)

            # New packet
            can_packet = "$"
            # Byte 1 is priority
            can_packet += pri
            # EB is byte 2 for data transfer packet
            can_packet += 'EB'
            # Destination address is byte 3
            can_packet += dst_addr
            # Source address is byte 4
            can_packet += src_addr
            # Data length (dlc) is byte 5
            # (multipacket messages are always 8 bytes each)
            can_packet += '08'

            for i in range(0, int(num_packets, 16)):
                # If a full 7 bytes is available
                if (i * 7) < data_bytes - data_bytes % 7:
                    seven_bytes = data[i * 14:(i * 14) + 14]
                # Pad remaining last packet with FF for data
                else:
                    seven_bytes = (data[i * 14:(i * 14) + ((data_bytes % 7) * 2)]
                                   + "FF" * (7 - (data_bytes % 7))
                                   )
                data_transfer = "%02X" % (i + 1)
                data_transfer += seven_bytes
                with self._lockM2:
                    # Adds end delimiter
                    self._m2.write((can_packet + data_transfer + '*') \
                                   .encode('utf-8'))
                time.sleep(0.01)

        # Sending non-multipacket message -
        # if number of bytes to send is less than or equal to 8
        else:
            # The first half of pgn is pdu_format (byte 2)
            can_packet += pgn[0:2]

            # If a destination specific message, pdu_specific (byte 3)
            # will be destination address, otherwise it is the last half of pgn
            if message.dst_addr != 0xff:
                can_packet += dst_addr
            else:
                can_packet += pgn[2:]

            # Source address is byte 4
            can_packet += src_addr

            # dlc (data length) is byte 5
            can_packet += dlc

            # data is in bytes 6-13, padded with FF's if less than 8 bytes
            can_packet += data
            can_packet += "FF" * (8 - data_bytes)
            # Add end delimiter, for use by M2
            can_packet += "*"
            with self._lockM2:
                self._m2.write(can_packet.encode('utf-8'))

    def _sendMessageSocketCan(self, truckdevil_message):
        """
        Send message over socketcan to get pushed to the BUS.

        :param truckdevil_message: a J1939_Message to be sent on the BUS
        """
        data_bytes = truckdevil_message.total_bytes
        if data_bytes <= 8:
            can_id = ((truckdevil_message.priority * 4 << 24)
                      + (truckdevil_message.pgn << 8)
                      + truckdevil_message.src_addr
                      )
            if truckdevil_message.pgn < 0xF000:
                can_id += truckdevil_message.dst_addr << 8
            data_array = bytes.fromhex(truckdevil_message.data)
            socketcan_message = can.Message(arbitration_id=can_id, data=data_array, is_extended_id=True)
            self._socketcan_bus.send(socketcan_message)
        else:
            num_bytes = "%04X" % data_bytes
            num_packets = "%02X" % math.ceil(data_bytes / 7)
            pgn = hex(truckdevil_message.pgn)[2:].zfill(4).upper()
            can_id = ((truckdevil_message.priority * 4 << 24)
                      + (0xEC00 << 8)
                      + (truckdevil_message.dst_addr << 8)
                      + truckdevil_message.src_addr
                      )
            if truckdevil_message.dst_addr == 0xFF:
                # Send BAM message (ex: 20120003FFCAFE00)
                control_message = bytes.fromhex("20" + num_bytes[2:4] + num_bytes[0:2]
                                                + num_packets + "FF" + pgn[2:4] + pgn[0:2] + "00")
            else:
                # Send RTS message
                control_message = bytes.fromhex("10" + num_bytes[2:4] + num_bytes[0:2]
                                                + num_packets + "FF" + pgn[2:4] + pgn[0:2] + "00")
            # send BAM or RTS message
            socketcan_message = can.Message(arbitration_id=can_id, data=control_message, is_extended_id=True)
            self._socketcan_bus.send(socketcan_message)
            if truckdevil_message.dst_addr == 0xFF:
                # Sleep 100ms before transmitting next message as
                # stated in standard
                time.sleep(0.1)
            else:
                # Sleep 150ms before transmitting next message to
                # allow for CTS to come through
                time.sleep(0.15)

            # Next packet
            can_id = ((truckdevil_message.priority * 4 << 24)
                      + (0xEB00 << 8)
                      + (truckdevil_message.dst_addr << 8)
                      + truckdevil_message.src_addr
                      )
            for i in range(0, int(num_packets, 16)):
                # If a full 7 bytes is available
                if (i * 7) < data_bytes - data_bytes % 7:
                    seven_bytes = truckdevil_message.data[i * 14:(i * 14) + 14]
                # Pad remaining last packet with FF for data
                else:
                    seven_bytes = (truckdevil_message.data[i * 14:(i * 14) + ((data_bytes % 7) * 2)]
                                   + "FF" * (7 - (data_bytes % 7))
                                   )
                data_transfer = "%02X" % (i + 1)
                data_transfer += seven_bytes
                socketcan_message = can.Message(arbitration_id=can_id, data=bytes.fromhex(data_transfer),
                                                is_extended_id=True)
                self._socketcan_bus.send(socketcan_message)
                time.sleep(0.01)

    def sendMessage(self, message):
        if self._m2used:
            self._sendMessageM2(message)
        else:
            self._sendMessageSocketCan(message)

    def _setPrintMessagesTimeDone(self):
        """Used by internal timer for printMessages function."""
        self._printMessagesTimeDone = True

    def _setCollectionTimeDone(self):
        """Used by internal timer for _readMessage function."""
        self._collectionTimeDone = True

    def _readMessage(self, abstractTPM=True):
        """
        Read and store messages in the collectedMessages array.
        For internal function use.
        """
        while True:
            # Keep the thread from executing if not in collection state
            if not self._dataCollectionOccurring:
                break
            # Look for full multipacket message to return first,
            # if none found, receive from socket
            self._lockConversations.acquire()
            for i in range(0, len(self._conversations)):
                # Found one ready to send - return it
                if self._conversations[i].readyToSend:
                    message = self._conversations[i].completeMessage
                    del self._conversations[i]
                    with self._lockCollectedMessages:
                        # Add completed multipacket message to
                        # collectedMessages list
                        self._collectedMessages.append(message)
                    break
            self._lockConversations.release()

            # Look for full ISO-TP message to return next,
            # if none found, receive from socket
            self._lockUDSConversations.acquire()
            for i in range(0, len(self._UDSconversations)):
                # Found one ready to send - return it
                if self._UDSconversations[i].readyToSend:
                    message = self._UDSconversations[i].completeMessage
                    del self._UDSconversations[i]
                    with self._lockCollectedMessages:
                        # Add completed ISO-TP message to
                        # collectedMessages list
                        self._collectedMessages.append(message)
                    break
            self._lockUDSConversations.release()

            # Receive one CAN message from M2
            # (ex: 18EF0B00080102030405060708)
            can_packet = self._readOneMessage()

            # Source address is byte 4
            src_addr = int(can_packet[6:8], 16)

            # pgn is byte 2 and 3, where byte 2 is pdu_format
            # and byte 3 is pdu_specific
            pgn = can_packet[2:6]

            pdu_format = int(pgn[0:2], 16)
            pdu_specific = int(pgn[2:4], 16)

            # If pdu_format is 0-239 then pdu_specific is dst_addr,
            # otherwise it is group extension
            if pdu_format < 240:
                dst_addr = pdu_specific
                # Add 00 to pgn if destination specific
                # (ex: EC0B pgn becomes EC00 with dst_addr 0x0B)
                pgn = pgn[0:2] + "00"
            else:
                # Broadcast message
                dst_addr = 0xFF
            pgn = int(pgn, 16)

            # priority is bits 4-6 in byte 1 of message
            # (ex: byte 1 = 0x18, 0b00011000 = priority of 6)
            priority = int(int(can_packet[0:2], 16) / 4)

            # Data length (dlc) is byte 5
            dlc = int(can_packet[8:10], 16)

            # data is contained in bytes 6-13, in a hex string format
            data = can_packet[10:26]

            message = J1939Message(
                priority, pgn,
                dst_addr, src_addr,
                data, dlc
            )

            # Multipacket message received,
            # broadcasted or peer-to-peer request to send
            if (pgn == 0xec00 and
                    (data[0:2] == "20" or data[0:2] == "10")):
                mp_message = _J1939MultiPacketMessage(message)
                with self._lockConversations:
                    self._conversations.append(mp_message)
                # Break here if TPM messages are abstracted and
                # don't add this message to collectedMessages
                if abstractTPM == True:
                    continue

            # Multipacket data transfer message recieved
            if pgn == 0xeb00:
                # Find the correct conversation
                self._lockConversations.acquire()
                for i in range(0, len(self._conversations)):
                    # Correct conversation found
                    if (self._conversations[i].completeMessage.src_addr == src_addr and
                            self._conversations[i].completeMessage.dst_addr == dst_addr):
                        self._conversations[i].received_packets += 1
                        # Received all the packets
                        if self._conversations[i].complete():
                            bytes_left = (self._conversations[i].num_bytes
                                          - self._conversations[i].received_bytes)
                            self._conversations[i] \
                                .received_bytes += bytes_left
                            data_index = (bytes_left * 2) + 2
                            # Copy final bytes
                            self._conversations[i] \
                                .completeMessage.data += data[2:data_index]
                            # Ready to send next time a message is read
                            self._conversations[i].readyToSend = True
                            # More packets needed,
                        # add 7 bytes of data to stored message
                        else:
                            self._conversations[i].received_bytes += 7
                            # Skip first byte, this is counter
                            self._conversations[i] \
                                .completeMessage.data += data[2:16]
                        break
                self._lockConversations.release()
                # Break here if TPM messages are abstracted,
                # and don't add this message to collectedMessages
                if abstractTPM == True:
                    continue

            # UDS ISO-TP message received, first frame
            if (pgn == 0xda00 and
                    message.data[0:1] == '1'):
                iso_tp_message = _J1939ISOTPMessage(message)
                with self._lockUDSConversations:
                    self._UDSconversations.append(iso_tp_message)
                # Break here if TPM messages are abstracted,
                # and don't add this message to collectedMessages
                if abstractTPM == True:
                    continue
            # UDS ISO-TP message recieved, consecutive frame
            elif (pgn == 0xda00 and
                  message.data[0:1] == '2'):
                self._lockUDSConversations.acquire()
                for i in range(0, len(self._UDSconversations)):
                    # Correct UDS message
                    if (self._UDSconversations[i] \
                            .completeMessage.src_addr == src_addr and
                            self._UDSconversations[i] \
                                    .completeMessage.dst_addr == dst_addr):
                        # The index of this received message
                        indexByte = int(message.data[1:2], 16)
                        # Correct order of data received
                        if (indexByte == self._UDSconversations[i] \
                                .nextExpectedIndex):
                            # Received all data bytes (including the current packet)
                            if (self._UDSconversations[i] \
                                    .complete(curr_received=7)):
                                bytes_left = (
                                        self._UDSconversations[i].num_bytes -
                                        self._UDSconversations[i].received_bytes
                                )
                                self._UDSconversations[i] \
                                    .received_bytes += bytes_left
                                data_index = int((bytes_left * 2) + 2)
                                # Copy final bytes
                                self._UDSconversations[i].completeMessage \
                                    .data += data[2:data_index]
                                self._UDSconversations[i].completeMessage.total_bytes = (
                                        len(self._UDSconversations[i].completeMessage.data) / 2
                                )
                                # Ready to send next time a message is read
                                self._UDSconversations[i].readyToSend = True
                                # More packets needed, add 7 bytes of data
                            # to stored message
                            else:
                                self._UDSconversations[i].received_bytes += 7
                                self._UDSconversations[i].completeMessage \
                                    .data += data[2:16]
                                # If indexByte is 15, we start back over
                                # at 0 for next sequence number
                                if indexByte == 15:
                                    self._UDSconversations[i] \
                                        .nextExpectedIndex = 0
                                else:
                                    self._UDSconversations[i] \
                                        .nextExpectedIndex += 1
                            break
                            # Something happened, delete?
                        else:
                            del self._UDSconversations[i]
                self._lockUDSConversations.release()
                # Break here if TPM messages are abstracted,
                # and don't add this message to collectedMessages
                if abstractTPM == True:
                    continue
            # UDS ISO-TP message recieved, flow control frame
            elif (pgn == 0xda00 and
                  message.data[0:1] == '3'):
                # Break here if TPM messages are abstracted,
                # and don't add this message to collectedMessages
                if abstractTPM == True:
                    continue
            with self._lockCollectedMessages:
                # Add message to collectedMessages list
                self._collectedMessages.append(message)

    def _UDSDecode(self, message):
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
                    self._UDS_services_list[uds_data[0:2]]['service'] + '\n'
            )
            decoded += (
                    '        *response code: 0x' +
                    uds_data[2:4] + ' - ' +
                    self._UDS_NRC_list[uds_data[2:4]]['name'] + '\n'
            )
            decoded += (
                    '            description: ' +
                    self._UDS_NRC_list[uds_data[2:4]]['description'] + '\n'
            )
            return decoded
        try:
            service = copy.deepcopy(self._UDS_services_list[service_id])
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
            function = self._UDS_functions_list[func_name]
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

    @property
    def reserved_bit(self):
        return self._can_id >> 25 & 1

    @property
    def data_page_bit(self):
        return self._can_id >> 24 & 1

    @property
    def pgn(self):
        return self._can_id >> 8 & 0xFFFF

    @property
    def dst_addr(self):
        if self.pgn >= 0xF000:
            return 0xFF
        else:
            return self._can_id >> 8 & 0xFF

    @property
    def src_addr(self):
        return self._can_id & 0xFF

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
        return "  %02X %04X %02X --> %02X [%d]  %s" % (self.priority, self.pgn,
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

        priority = first_message.priority
        if int(first_message.data[12:14], 16) < 240:
            pgn = int(first_message.data[12:14] + "00", 16)
        else:
            pgn = int(first_message.data[12:14] + first_message.data[10:12], 16)
        dst_addr = first_message.dst_addr
        src_addr = first_message.src_addr
        total_bytes = self.num_bytes
        data = ""

        # Create new message with TP abstracted
        self.completeMessage = J1939Message(
            priority, pgn,
            dst_addr, src_addr,
            data, total_bytes
        )

        # Multipacket message not completed
        self.readyToSend = False

    def complete(self):
        # If all expected packets have been added to multipacket message
        if self.received_packets == self.num_packets:
            return True
        else:
            return False


class _J1939ISOTPMessage:
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
