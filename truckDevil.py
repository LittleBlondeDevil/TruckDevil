import struct
import serial
import threading
import time
import math
import copy
import json
import os
import binascii

class TruckDevil:
    """
    Contains various functions for handling J1939 messages

    :param port: serial port that M2 is connected on. Example: COMX, dev/ttyX
    :param serial_baud: baudrate to connect over serial to M2 (Default value = 115200)
    :param can_baud: baudrate on the CAN bus. Most common are 250000 and 500000. Use 0 for autobaud detection. (Default value = 0)
    """
    def __init__(self, port=None, serial_baud=115200, can_baud=0):
        if (port == None):
            raise Exception('No device port specified')
        self._m2 = serial.Serial(
            port=port, baudrate=serial_baud, 
            dsrdtr=True
        )
        self._m2.setDTR(True)
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
        with open(os.path.join('resources', 'pgn_list.json')) as pgn_file:
            self._pgn_list = json.load(pgn_file)
        
        self._spn_list = {}
        with open(os.path.join('resources', 'spn_list.json')) as spn_file:
            self._spn_list = json.load(spn_file)
            
        self._src_addr_list = {}
        with open(os.path.join('resources', 'src_addr_list.json')) \
                as src_addr_file:
            self._src_addr_list = json.load(src_addr_file)
            
        self._bit_decoding_list = {}
        with open(os.path.join('resources', 'dataBitDecoding.json')) \
                as bit_decoding_file:
            self._bit_decoding_list = json.load(bit_decoding_file)
            
        self._UDS_services_list = {}
        with open(os.path.join('resources', 'UDS_services.json')) \
                as UDS_services_file:
            self._UDS_services_list = json.load(UDS_services_file)
            
        self._UDS_functions_list = {}
        with open(os.path.join('resources', 'UDS_functions.json')) \
                as UDS_functions_file:
            self._UDS_functions_list = json.load(UDS_functions_file)
            
        self._UDS_NRC_list = {}
        with open(os.path.join('resources', 'UDS_NRC.json')) \
                as UDS_NRC_file:
            self._UDS_NRC_list = json.load(UDS_NRC_file)
            
        # Ensure that can_baud is filled to 7 digits
        baudToSend = str(can_baud).zfill(7) 
        self._m2.write(baudToSend.encode('utf-8'))
        
    
    def done(self):
        """Close the Serial connection to M2."""
        with self._lockM2:
            self._m2.close()
    
    def startDataCollection(self, abstractTPM=True):
        """
        Starts reading and storing messages

        :param abstractTPM: whether to abstract multipacket messages or instead to show all Transport Protocol messages (Default value = True)
        """
        if (self._dataCollectionOccurring == True):
            raise Exception('data collection already started')
        with self._lockCollectedMessages:
            self._collectedMessages = []
        if (self._collectionThread == None or 
                # If collectionThread hasn't been started before
                self._collectionThread.is_alive() == False): 
            self._collectionThread = threading.Thread(
                target=self._readMessage, args=(abstractTPM,), 
                daemon=True
            )
            self._collectionThread.start()
            
        self._dataCollectionOccurring = True
            
    
    def getCurrentCollectedData(self):
        """
        Gets all of the messages that have been collected

        :return: the collectedMessages list
        """
        with self._lockCollectedMessages:
            messages = self._collectedMessages
        return messages
        
    def stopDataCollection(self):
        """
        Stops reading and storing messages, resets all data

        :returns: the collectedMessages list
        """
        if (self._dataCollectionOccurring == False):
            raise Exception('data collection is already stopped')
        self._dataCollectionOccurring = False
        with self._lockConversations:
            self._conversations = []
        with self._lockUDSConversations:
            self._UDSconversations = []
        with self._lockCollectedMessages:
            dataCollected = self._collectedMessages
            self._collectedMessages = []
        return dataCollected
        
    
    def saveDataCollected(self, messages, 
                          fileName=None, verbose=False):
        """
        Save the collected messages to a file

        :param messages: the collected messages outputted from stopDataCollection
        :param fileName: the name of the file to save the data to. If not specified, defaults to: "m2_collected_data_[time]"
        :param verbose: whether or not to save the message in decoded form (Default value = False)
        """
        # If given messages list is empty
        if (len(messages) == 0): 
            raise Exception('messages list is empty')
        if (fileName == None):
            fileName = 'm2_collected_data_' + str(int(time.time()))
        f = open(fileName, "x")
        f.write("""Priority    PGN    Source --> Destination    [Num Bytes]    data""" + '\n')
        for m in messages:
            if (verbose == False):
                f.write(str(m) + '\n')
            else:
                f.write(self.getDecodedMessage(m) + '\n')
        f.close()    
    
    
    
    def importDataCollected(self, fileName):
        """
        Converts log file to list of J1939_Message objects

        :param fileName: the name of the file where the data is saved
        :returns: list of J1939_Message objects from log file
        """
        messages = []
        if (os.path.exists(fileName)):
            with open (fileName, 'r') as inFile:
                firstLine = True
                for line in inFile:
                    if (firstLine):
                        firstLine = False
                    else:
                        parts = line.split()
                        if (len(parts) == 7 and 
                                parts[3] == '-->' and 
                                '[' in line):
                            message = J1939_Message(
                                priority = int(parts[0]), 
                                pgn = int(parts[1], 16), 
                                dst_addr = int(parts[4], 16), 
                                src_addr = int(parts[2], 16), 
                                data = parts[6]
                            )
                            messages.append(message)
                return messages
        else:
            raise Exception('file name given does not exist.')
    
    
    def getDecodedMessage(self, message=None):
        """
        Decodes a J1939_Message object into human-readable string

        :param message: J1939_Message object to be decoded
        :returns: the decoded message as a string
        """
        if (isinstance(message, J1939_Message) == False or 
                message == None):
            raise Exception('Must include an instance of a J1939_Message')
        decoded = str(message) + '\n' 
        # Only include this portion if src and dest addrs are in list
        if ((str(message.src_addr) in self._src_addr_list) and 
                (str(message.dst_addr) in self._src_addr_list)): 
            decoded += (
                '    ' + self._src_addr_list[str(message.src_addr)] +
                " --> " + self._src_addr_list[str(message.dst_addr)] + 
                '\n'
            )
        # Only include this portion if the pgn of the message is in pgn_list
        if (str(message.pgn) in self._pgn_list): 
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
            if (message.pgn == 0xDA00):
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
                    == len(message.data)/2): 
                # For each spn that is part the given pgn
                for spn in self._pgn_list[str(message.pgn)]['spnList']: 
                    # Only include this portion if the spn is in the spn_list
                    if (str(spn) in self._spn_list): 
                        decoded += (
                            '      SPN(' + 
                            str(spn) + '): ' + 
                            self._spn_list[str(spn)]['spnName'] + 
                            '\n'
                        )
                        # Ensure it's not a variable length SPN
                        if (self._spn_list[str(spn)]['spnLength'] 
                                != "variable"): 
                            totalBits = self._spn_list[str(spn)]['spnLength']
                            startBit = self._spn_list[str(spn)]['bitPositionStart']
                            endBit = startBit + totalBits
                            
                            bin_data_total = bin(int(message.data, 16))[2:] \
                                .zfill(int((len(message.data)/2) * 8))
                            bin_data = bin_data_total[startBit:endBit]
                            extracted_data = int(bin_data, 2)
                            # Swap endianness if greater then 1 byte
                            if totalBits > 8 and totalBits <= 16: #(2 bytes)
                                extracted_data = int.from_bytes(extracted_data.to_bytes(2, byteorder='little'), byteorder='big', signed=False)
                            if totalBits > 16 and totalBits <= 24: #(3 bytes)
                                extracted_data = int.from_bytes(extracted_data.to_bytes(3, byteorder='little'), byteorder='big', signed=False)
                            if totalBits > 24 and totalBits <= 32: #(4 bytes)
                                extracted_data = int.from_bytes(extracted_data.to_bytes(4, byteorder='little'), byteorder='big', signed=False)
                            if totalBits > 32 and totalBits <= 40: #(5 bytes)
                                extracted_data = int.from_bytes(extracted_data.to_bytes(5, byteorder='little'), byteorder='big', signed=False)
                            if totalBits > 48 and totalBits <= 56: #(6 bytes)
                                extracted_data = int.from_bytes(extracted_data.to_bytes(6, byteorder='little'), byteorder='big', signed=False)
                            if totalBits > 56 and totalBits <= 64: #(7 bytes)
                                extracted_data = int.from_bytes(extracted_data.to_bytes(7, byteorder='little'), byteorder='big', signed=False)
                                
                            # If all 1's, don't care about value, don't add
                            if (extracted_data != int("1"*totalBits, 2) or totalBits == 1):
                                # If bit data type, use bit_decoding_list
                                if(self._spn_list[str(spn)]['units'] == 'bit' 
                                        and str(spn) 
                                        in self._bit_decoding_list): 
                                    decoded += (
                                        '        ' + str(int(bin_data, 2)) + 
                                        ' : ' + 
                                        self._bit_decoding_list[str(spn)][str(int(bin_data, 2))] + 
                                        '\n'
                                    )
                                #if ascii data type, convert 
                                elif(self._spn_list[str(spn)]['units'] == 'ASCII'):
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
                                    if (extracted_data.is_integer()): 
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
    
         
    def printMessages(self, abstractTPM=True, 
                      readTime=None, numMessages=None, 
                      verbose=False, logToFile=False):
        """
        Read and print all messages from M2. If readTime and numMessages are both specified, stop printing when whichever one is reached first.
        
        :param abstractTPM: whether to abstract multipacket messages or instead to show all Transport Protocol messages (Default value = True)
        :param readTime: the amount of time to print messages for. If not specified, it will not be limited
        :param numMessages: number of messages to print before stopping. If not specified, it will not be limited
        :param verbose: whether or not to print the message in decoded form (Default value = False)
        :param logToFile: whether or not to log the messages to a file (Default value = False)
        """
        # Only allow if data collection is not occurring
        if (self._dataCollectionOccurring == True): 
            raise Exception('stop data collection before proceeding with this function')
        # If optional readTime is utilized
        if (readTime != None): 
            self._printMessagesTimer = threading.Timer(
                readTime, self._setPrintMessagesTimeDone
            )
            self._printMessagesTimer.start()
        messagesPrinted = 0
        with self._lockConversations:
            self._conversations = []
        with self._lockUDSConversations:
            self._UDSconversations = []
        self._printMessagesTimeDone = False
        # Log to file
        if (logToFile): 
            fileName = 'm2_collected_data_' + str(int(time.time()))
            logFile = open(fileName, "x")
            logFile.write(
                """Priority    PGN    Source --> Destination
                [Num Bytes]    data""" + '\n'
            )
        # Keep printing while our timer isn't done or the number of 
        # messages to print hasn't been reached (whichever comes first). 
        # If neither are utilized, keep going forever
        while (self._printMessagesTimeDone == False and 
                (numMessages == None or messagesPrinted < numMessages)): 
            # Only allow if data collection is not occurring
            if (self._dataCollectionOccurring == True): 
                raise Exception(
                    """data collection began abruptly, stop data collection 
                    before proceeding with this function"""
                )
            # Look for full multipacket message to return first
            self._lockConversations.acquire()
            for i in range(0, len(self._conversations)): 
                # Found one ready to send - return it 
                if (self._conversations[i].readyToSend):
                    message = self._conversations[i].completeMessage
                    del self._conversations[i]
                    if (verbose == False):
                        # Print completed multipacket message
                        print(message) 
                        if (logToFile):
                            logFile.write(str(message) + '\n')
                    else:
                        # Print the completed multipacket message in decoded form
                        print(self.getDecodedMessage(message)) 
                        if (logToFile):
                            logFile.write(
                                self.getDecodedMessage(message) + 
                                '\n'
                            )
                    messagesPrinted = messagesPrinted + 1
                    break
            self._lockConversations.release()
            
            # Look for full ISO-TP message to return next
            self._lockUDSConversations.acquire()
            for i in range(0, len(self._UDSconversations)):
                # Found one ready to send - return it 
                if (self._UDSconversations[i].readyToSend):
                    message = self._UDSconversations[i].completeMessage
                    del self._UDSconversations[i]
                    if (verbose == False):
                        # Print the completed ISO-TP message
                        print(message) 
                        if (logToFile):
                            logFile.write(
                                str(message) + 
                                '\n'
                            )
                    else:
                        # Print the completed ISO-TP message in decoded form
                        print(self.getDecodedMessage(message)) 
                        if (logToFile):
                            logFile.write(
                                self.getDecodedMessage(message) + 
                                '\n'
                            )
                    messagesPrinted = messagesPrinted + 1
                    break
            self._lockUDSConversations.release()
        
            # Get one CAN message from M2 (ex: 18EF0B00080102030405060708)
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
            if (pdu_format < 240):
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
            priority = int(bin(int(can_packet[0:2], 16))[2:5], 2)
            
            # dlc (data length) is byte 5
            dlc = int(can_packet[8:10], 16)
            
            # data is contained in bytes 6-13, in hex string format
            data = can_packet[10:26]
            
            message = J1939_Message(
                priority, pgn, 
                dst_addr, src_addr, 
                data, dlc
            )
            
            # Multipacket message received, broadcasted or 
            # peer-to-peer request to send
            if (pgn == 0xec00 and 
                    (data[0:2] == "20" or 
                    data[0:2] == "10" )):
                mp_message = _J1939_MultiPacketMessage(message)
                with self._lockConversations:
                    self._conversations.append(mp_message)
                # If abstractTPM is True, break and don't print this message
                if (abstractTPM==True): 
                    continue
                
            # Multipacket data transfer message recieved
            if (pgn == 0xeb00):
                # Find the correct conversation 
                self._lockConversations.acquire()
                for i in range(0, len(self._conversations)): 
                    # Correct conversation found
                    if (self._conversations[i] \
                            .completeMessage.src_addr == src_addr and 
                            self._conversations[i] \
                            .completeMessage.dst_addr == dst_addr):
                        self._conversations[i].received_packets += 1
                        # Received all the packets
                        if (self._conversations[i].complete()): 
                            bytes_left = (
                                self._conversations[i].num_bytes - 
                                self._conversations[i].received_bytes
                            )
                            self._conversations[i] \
                                .received_bytes += bytes_left
                            data_index = (bytes_left*2) + 2
                            # Copy final bytes
                            self._conversations[i] \
                                .completeMessage.data += data[2:data_index]
                            # Ready to send next time a message is read
                            self._conversations[i].readyToSend = True 
                        # More packets needed, add 7 bytes of data to stored message
                        else: 
                            self._conversations[i].received_bytes += 7
                            # Skip first byte, this is counter    
                            self._conversations[i] \
                                .completeMessage.data += data[2:16]
                        break
                self._lockConversations.release() 
                # If abstractTPM is True, continue and don't print this message
                if (abstractTPM==True):
                    continue
            # UDS ISO-TP message received, first frame
            if (pgn == 0xda00 and 
                    message.data[0:1] == '1'):
                iso_tp_message = _J1939_ISO_TP_Message(message)
                with self._lockUDSConversations:
                    self._UDSconversations.append(iso_tp_message)
                # If abstractTPM is True, break and don't print this message
                if (abstractTPM==True): 
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
                                data_index = int((bytes_left*2) + 2)
                                # Copy final bytes
                                self._UDSconversations[i].completeMessage \
                                    .data += data[2:data_index]
                                self._UDSconversations[i].completeMessage.total_bytes = (
                                    len(self._UDSconversations[i].completeMessage.data)/2
                                )
                                # Ready to send next time a message is read
                                self._UDSconversations[i].readyToSend = True 
                            # More packets needed, add 7 bytes of data 
                            # to stored message
                            else: 
                                self._UDSconversations[i].received_bytes += 7
                                self._UDSconversations[i] .completeMessage \
                                    .data += data[2:16]
                                # If indexByte is 15, we start back over
                                # at 0 for next sequence number
                                if (indexByte == 15): 
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
                # If abstractTPM is True, break and don't print this message
                if (abstractTPM==True): 
                    continue
            # UDS ISO-TP message recieved, flow control frame
            elif (pgn == 0xda00 and 
                    message.data[0:1] == '3'):
                # If abstractTPM is True, break and don't print this message
                if (abstractTPM==True): 
                    continue
            # Print/log the message
            if (verbose == False):
                print(message) 
                if (logToFile):
                    logFile.write(str(message) + '\n')
            else:
                print(self.getDecodedMessage(message))
                if (logToFile):
                    logFile.write(self.getDecodedMessage(message) + '\n')
            messagesPrinted = messagesPrinted + 1
        # Close the log file before exiting
        if (logToFile):
            logFile.close()
        if (readTime != None):
            self._printMessagesTimer.cancel()
    
    def readMessagesUntil(self, dataContains=None, 
                          target_src_addr=None, target_dst_addr=None, 
                          target_pgn=None):
        """
        Read all messages from M2 until a specific message is found, atleast one parameter should be specified to look for.

        :param dataContains: if specified, the message must contain this hex string in the data portion, ex: "010203"
        :param target_src_addr: if specified, the message must have a src_addr of this parameter, ex: 0xF9
        :param target_dst_addr: if specified, the message must have a dst_addr of this parameter, ex: 0x0B
        :param target_pgn: if specified, the message must have a pgn of this parameter, ex: 0xF004
        :returns: both the message that matched the specified parameters, and the list of messages that were collected while searching
        """
        if (dataContains==None and 
                target_src_addr==None and 
                target_dst_addr==None and 
                target_pgn==None):
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
                if (conversations[i].readyToSend):
                    message = conversations[i].completeMessage
                    del conversations[i]
                    # Add completed multipacket message to collectedMessages list
                    collectedMessages.append(message) 
                    if ((dataContains==None or dataContains in message.data) and 
                            (target_src_addr==None or message.src_addr==target_src_addr) and 
                            (target_dst_addr==None or message.dst_addr==target_dst_addr) and 
                            (target_pgn==None or message.pgn==target_pgn)):
                        return message, collectedMessages
                    break
                    
            # Look for full ISO-TP message to return next,
            # if none found, receive from socket
            for i in range(0, len(UDS_conversations)):
                # Found one ready to send - return it 
                if (UDS_conversations[i].readyToSend):
                    message = UDS_conversations[i].completeMessage
                    del UDS_conversations[i]
                    # Add completed ISO-TP message to collectedMessages list
                    collectedMessages.append(message)
                    if ((dataContains==None or dataContains in message.data) and 
                            (target_src_addr==None or message.src_addr==target_src_addr) and 
                            (target_dst_addr==None or message.dst_addr==target_dst_addr) and 
                            (target_pgn==None or message.pgn==target_pgn)):
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
            if (pdu_format < 240):
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
            priority = int(bin(int(can_packet[0:2], 16))[2:5], 2)
            
            # dlc (data length) is byte 5
            dlc = int(can_packet[8:10], 16)
            
            # data is contained in bytes 6-13, in hex string format
            data = can_packet[10:26]
            message = J1939_Message(
                priority, pgn, 
                dst_addr, src_addr, 
                data, dlc
            )
            
            # Multipacket message received, broadcasted or 
            # peer-to-peer request to send
            if (pgn == 0xec00 and 
                    (data[0:2] == "20" or data[0:2] == "10" )):
                mp_message = _J1939_MultiPacketMessage(message)
                conversations.append(mp_message)
                
            # Multipacket data transfer message recieved
            if (pgn == 0xeb00):
                # Find the correct conversation 
                for i in range(0, len(conversations)): 
                    # Found correct conversation
                    if (conversations[i].completeMessage.src_addr == src_addr and 
                            conversations[i].completeMessage.dst_addr == dst_addr):
                        conversations[i].received_packets += 1
                        # Received all the packets
                        if (conversations[i].complete()): 
                            bytes_left = (
                                conversations[i].num_bytes 
                                - conversations[i].received_bytes
                            )
                            conversations[i].received_bytes += bytes_left
                            data_index = (bytes_left*2) + 2
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
                iso_tp_message = _J1939_ISO_TP_Message(message)
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
                        if (indexByte == UDS_conversations[i].nextExpectedIndex):
                            # Received all data bytes (including the current packet)
                            if (UDS_conversations[i].complete(curr_received=7)): 
                                bytes_left = (
                                    UDS_conversations[i].num_bytes - 
                                    UDS_conversations[i].received_bytes
                                )
                                UDS_conversations[i].received_bytes += bytes_left
                                data_index = int((bytes_left*2) + 2)
                                # Copy final bytes
                                UDS_conversations[i].completeMessage \
                                    .data += data[2:data_index]
                                UDS_conversations[i].completeMessage.total_bytes = (
                                    len(UDS_conversations[i].completeMessage.data)/2
                                )
                                # Ready to send next time a message is read
                                UDS_conversations[i].readyToSend = True 
                            # More packets needed, add 7 bytes of data 
                            # to stored message
                            else: 
                                UDS_conversations[i].received_bytes += 7
                                UDS_conversations[i] .completeMessage \
                                    .data += data[2:16]
                                # If indexByte is 15, we start back over
                                # at 0 for next sequence number
                                if (indexByte == 15): 
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
            if ((dataContains==None or dataContains in message.data) and 
                    (target_src_addr==None or message.src_addr==target_src_addr) and 
                    (target_dst_addr==None or message.dst_addr==target_dst_addr) and 
                    (target_pgn==None or message.pgn==target_pgn)):
                return message, collectedMessages
        
    
    def sendMessage(self, message):
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
        data_bytes = int(len(message.data)/2) 
        
        dst_addr = hex(message.dst_addr)[2:].zfill(2).upper()
        pgn = hex(message.pgn)[2:].zfill(4).upper()
        src_addr = hex(message.src_addr)[2:].zfill(2).upper()
        dlc = hex(data_bytes)[2:].zfill(2)
        data = message.data.upper()
        
        # Sending multipacket message - if number of bytes to send is 
        # more than 8 (ex: 1CECFF000820120003FFCAFE00)
        if(data_bytes > 8):
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
            
            if (message.dst_addr == 0xFF):
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
            if (message.dst_addr == 0xFF): 
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
                if ((i*7) < data_bytes - data_bytes % 7): 
                    seven_bytes = data[i*14:(i*14)+14]
                # Pad remaining last packet with FF for data
                else: 
                    seven_bytes = (data[i*14:(i*14)+((data_bytes%7)*2)] 
                        + "FF"*(7-(data_bytes%7))
                    )
                data_transfer = "%02X" % (i+1) 
                data_transfer += seven_bytes
                with self._lockM2:
                    # Adds end delimiter
                    self._m2.write((can_packet + data_transfer + '*') \
                        .encode('utf-8')) 
                
        # Sending non-multipacket message - 
        # if number of bytes to send is less than or equal to 8
        else:
            # The first half of pgn is pdu_format (byte 2)
            can_packet += pgn[0:2]
            
            # If a destination specific message, pdu_specific (byte 3) 
            # will be destination address, otherwise it is the last half of pgn
            if (message.dst_addr != 0xff):
                can_packet += dst_addr
            else:
                can_packet += pgn[2:]
            
            # Source address is byte 4
            can_packet += src_addr
            
            # dlc (data length) is byte 5 
            can_packet += dlc
            
            # data is in bytes 6-13, padded with FF's if less than 8 bytes
            can_packet += data
            can_packet += "FF"*(8-data_bytes)
            # Add end delimiter, for use by M2
            can_packet += "*" 
            with self._lockM2:
                self._m2.write(can_packet.encode('utf-8'))
            
    
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
            if (self._dataCollectionOccurring == True): 
                # Look for full multipacket message to return first, 
                # if none found, receive from socket
                self._lockConversations.acquire()
                for i in range(0, len(self._conversations)): 
                    # Found one ready to send - return it 
                    if (self._conversations[i].readyToSend):
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
                    if (self._UDSconversations[i].readyToSend):
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
                if (pdu_format < 240):
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
                priority = int(bin(int(can_packet[0:2], 16))[2:5], 2)
                
                # Data length (dlc) is byte 5
                dlc = int(can_packet[8:10], 16)
                
                # data is contained in bytes 6-13, in a hex string format
                data = can_packet[10:26]
                
                message = J1939_Message(
                    priority, pgn, 
                    dst_addr, src_addr, 
                    data, dlc
                )
                
                # Multipacket message received, 
                # broadcasted or peer-to-peer request to send
                if (pgn == 0xec00 and 
                        (data[0:2] == "20" or data[0:2] == "10" )):
                    mp_message = _J1939_MultiPacketMessage(message)
                    with self._lockConversations:
                        self._conversations.append(mp_message)
                    # Break here if TPM messages are abstracted and 
                    # don't add this message to collectedMessages
                    if (abstractTPM==True): 
                        continue
                    
                # Multipacket data transfer message recieved
                if (pgn == 0xeb00):
                    # Find the correct conversation 
                    self._lockConversations.acquire()
                    for i in range(0, len(self._conversations)): 
                        # Correct conversation found
                        if (self._conversations[i].completeMessage.src_addr == src_addr and 
                                self._conversations[i].completeMessage.dst_addr == dst_addr):
                            self._conversations[i].received_packets += 1
                            # Received all the packets
                            if (self._conversations[i].complete()): 
                                bytes_left = (self._conversations[i].num_bytes 
                                    - self._conversations[i].received_bytes)
                                self._conversations[i] \
                                    .received_bytes += bytes_left
                                data_index = (bytes_left*2) + 2
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
                    if (abstractTPM==True): 
                        continue
                        
                # UDS ISO-TP message received, first frame
                if (pgn == 0xda00 and 
                        message.data[0:1] == '1'):
                    iso_tp_message = _J1939_ISO_TP_Message(message)
                    with self._lockUDSConversations:
                        self._UDSconversations.append(iso_tp_message)
                    # Break here if TPM messages are abstracted,
                    # and don't add this message to collectedMessages
                    if (abstractTPM==True): 
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
                                    data_index = int((bytes_left*2) + 2)
                                    # Copy final bytes
                                    self._UDSconversations[i].completeMessage \
                                        .data += data[2:data_index]
                                    self._UDSconversations[i].completeMessage.total_bytes = (
                                        len(self._UDSconversations[i].completeMessage.data)/2
                                    )
                                    # Ready to send next time a message is read
                                    self._UDSconversations[i].readyToSend = True 
                                # More packets needed, add 7 bytes of data 
                                # to stored message
                                else: 
                                    self._UDSconversations[i].received_bytes += 7
                                    self._UDSconversations[i] .completeMessage \
                                        .data += data[2:16]
                                    # If indexByte is 15, we start back over
                                    # at 0 for next sequence number
                                    if (indexByte == 15): 
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
                    if (abstractTPM==True): 
                        continue
                # UDS ISO-TP message recieved, flow control frame
                elif (pgn == 0xda00 and 
                        message.data[0:1] == '3'):
                    # Break here if TPM messages are abstracted,
                    # and don't add this message to collectedMessages
                    if (abstractTPM==True): 
                        continue        
                
                with self._lockCollectedMessages:   
                    # Add message to collectedMessages list
                    self._collectedMessages.append(message) 
        
    def _readOneMessage(self):
        """
        Reads one message from M2 and returns it 
        For internal function use.
        hex string format ex: 18EF0B00080102030405060708
        """
        response = ""
        startReading = False
        while True:
            with self._lockM2:
                # Receive next character from M2
                if (self._m2.inWaiting() > 0):
                    char = self._m2.read().decode("utf-8")
                else:
                    time.sleep(0.01)
                    continue
            # Denotes start of CAN message
            if (startReading == False and char == '$'):
                response = '$'
                startReading = True
            # Reading contents of CAN message, appending to response
            elif (startReading == True and char != '*'): 
                response += char
            # Denotes end of CAN message - return response
            elif (startReading == True and len(response) > 0 and 
                    response[0] == '$' and char == '*' and 
                    response.count("$") == 1):
                return response[1:]
            # If the serial buffer gets flushed during reading
            elif (response.count("$") > 1):
                response = ""
                startReading = False
    
    def _UDSDecode(self, message):
        """
        Takes in J1939_message and return the decoded string
        For internal function use.
        """
        decoded = ''
        # Frame type is first nibble
        frame_type = message.data[0:1] 
        # 0 is single frame
        if (frame_type == '0'): 
            # Size is between 0 and 7 bytes
            size = int(message.data[1:2], 16) 
            serviceID = message.data[2:4].upper()
            uds_data = message.data[4:2+(size*2)].upper()
        # 1 is first frame - don't decode data
        elif (frame_type == '1'): 
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
        elif (frame_type == '2'): 
            # Index is between 0 and 15 
            dataIndex = int(message.data[1:2], 16) 
            decoded += (
                '      Type: Consecutive frame, indicating this is index ' + 
                str(dataIndex) + 
                '\n'
            )
            return decoded
        # 3 is flow control frame - don't decode data
        elif (frame_type == '3'): 
            #0 (continue), 1 (wait), 2 (overflow/abort)
            FCFlag = int(message.data[1:2], 16) 
            FCFlag_code = ''
            if (FCFlag == 0):
                FCFlag_code = 'continue to send'
            elif (FCFlag == 1):
                FCFlag_code = 'wait'
            elif (FCFlag == 2):
                FCFlag_code = 'overflow/abort'
            else:
                FCFlag_code = 'unknown error'
            # 0: remaining frames sent without flow control or delay, 
            # >0: send number of frames before waiting for the next 
            # flow control frame
            blockSize = int(message.data[2:4],16) 
            blockSize_code = ''
            if (blockSize == 0):
                blockSize_code = 'remaining frames to be sent without flow control or delay'
            else:
                blockSize_code = 'send number of frames before waiting for the next flow control frame'
            # <=127 (separation time in m), 
            # 241-249 (100-900 microseconds) 
            separationTime = int(message.data[4:6], 16) 
            separationTime_code = ''
            if (separationTime <= 127):
                separationTime_code = 'milliseconds'
            elif (separationTime >= 241 and separationTime <= 249):
                separationTime = int(hex(separationTime)[3:4], 16)*100
                separationTime_code = 'microseconds'
            else:
                separationTime_code = 'unknown error'
            decoded += '      Type: Flow control frame, with the following characteristics:\n'
            decoded += (
                '          FC Flag: ' + 
                str(FCFlag) + ' - ' + 
                FCFlag_code + '\n'
            )
            decoded += (
                '          Block size: ' + 
                str(blockSize) + ' - ' + 
                blockSize_code + '\n'
            )
            decoded += (
                '          Separation Time: ' + 
                str(separationTime) + ' - ' + 
                separationTime_code + '\n'
            )
            return decoded
        # Frame put back together by TruckDevil
        else: 
            size = int((len(message.data)- 2)/2)
            serviceID = message.data[2:4].upper()
            uds_data = message.data[4:].upper()
        if (int(serviceID, 16) == 0x7F):
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
            service = copy.deepcopy(self._UDS_services_list[serviceID])
        except KeyError:
            return decoded + '      UDS Service ID ' + str(serviceID) + ' does not exist\n'
            
        decoded += '      PGNDataLength: ' + str(size + 1) + '\n'
        decoded += '      UDS service: ' + service['service']
        if (service['type'] == 'request' or service['type'] == 'response'):
            decoded += ' - ' + service['type'] + '\n'
            data_bytes = service['data_bytes']
        elif (service['type'] == 'multiRequest' or 
                service['type'] == 'multiResponse'):
            if (service['type'] == 'multiRequest'):
                decoded += ' - ' + 'request' + '\n'
            else:
                decoded += ' - ' + 'response' + '\n'
            controller_byte = str(int(uds_data[0:2], 16))
            if (controller_byte in service['parameters'].keys()):
                data_bytes = service['parameters'][controller_byte]['data_bytes']
            elif ('others' in service['parameters'].keys()):
                data_bytes = service['parameters']['others']['data_bytes']
            else:
                return decoded
        subfunction = None
        if (service['subfunction_supported'] == True):
            suppressPos = int(bin(int(uds_data[0:2], 16))[2:].zfill(8)[0:1],2)
            subfunction = int(bin(int(uds_data[0:2], 16))[2:].zfill(8)[1:],2)
            decoded += (
                '      suppress positive response? : ' + 
                str(bool(suppressPos)) + '\n'
            )
        data_index = 0   
        tempLengthOfMemoryAddress = -1
        tempLengthOfMemorySize = -1
        tempScalingByteDataType = -1
        tempLengthScalingByte = -1
        tempRoutineIdentifier = -1
        tempLengthFilePathAndName = -1
        tempModeOfOperation = -1
        tempLengthFileSizeParameter = -1
        tempLengthMaxNumberOfBlockLength = -1
        tempLengthEventTypeRecord = -1
        for func_name in data_bytes:
            if (data_index >= len(uds_data)/2):
                break
            if ("*" in func_name):
                data_bytes.append(func_name)
                func_name = func_name.replace("*", "")

            # Odd functions that need special care
            if (func_name == 'dataFormatIdentifier2' and 
                    (tempModeOfOperation == 'deleteFile' 
                        or tempModeOfOperation == 'readDir')):
                continue
            elif (func_name == 'fileSizeParameterLength' and 
                    (tempModeOfOperation == 'deleteFile' 
                        or tempModeOfOperation == 'readFile' 
                        or tempModeOfOperation == 'readDir')):
                continue

            decoded += '        *' + func_name + '\n'
            function = self._UDS_functions_list[func_name]
            decoded += (
                '            description: ' + 
                function['description'] + '\n'
            )
            if (function['type'] == 'bit' and 
                    function['numBytes'] != 'variable'):
                if (subfunction != None and 
                        data_bytes.index(func_name) == 0):
                    val = function['parameters'][str(subfunction)]
                else:
                    func_data = (uds_data[data_index*2:function['numBytes']*2 
                                + data_index*2])
                    try:
                        val = function['parameters'][str(int(func_data, 16))]
                    except KeyError:
                        val = 'cannot decode value (out of range)'
                decoded += '            value: ' + val + '\n'
                if (func_name == 'modeOfOperation'):
                    tempModeOfOperation = val
                data_index += function['numBytes']
            elif (function['type'] == 'list' and 
                    function['numBytes'] != 'variable'):
                func_data = (uds_data[data_index*2:function['numBytes']*2 
                    + data_index*2])
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
                    if (function['parameters'][param]['units'] == 'list'):
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
                            startPosition = function['parameters'][param]['startPosition']
                            startNestedPosition = (
                                startPosition + 
                                function['parameters'][param]['parameters'][nestedParam]['startPosition']
                            )
                            totalLen = function['parameters'][param]['parameters'][nestedParam]['totalLen']
                            inner_func_data = bin_data[startNestedPosition : startNestedPosition+totalLen]
                            val = (
                                str(int(inner_func_data, 2) 
                                * int(function['parameters'][param]['parameters'][nestedParam]['resolution']))
                            )
                            if (function['parameters'][param]['parameters'][nestedParam]['units'] == 'bit'):
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
                        startPosition = function['parameters'][param]['startPosition']
                        totalLen = function['parameters'][param]['totalLen']
                        inner_func_data = bin_data[startPosition:startPosition+totalLen]
                        val = (
                            str(int(inner_func_data, 2) 
                            * int(function['parameters'][param]['resolution']))
                        )
                        
                        if (function['parameters'][param]['name'] == 'dataType'):
                                tempScalingByteDataType = int(val)
                        elif (function['parameters'][param]['name'] == "LengthOfMemoryAddress"):
                                tempLengthOfMemoryAddress = int(inner_func_data, 2)
                        elif (function['parameters'][param]['name'] == "LengthOfMemorySize"):
                                tempLengthOfMemorySize = int(inner_func_data, 2)
                        elif (function['parameters'][param]['name'] == "numBytes"):
                                tempLengthScalingByte = int(val)
                        elif (function['parameters'][param]['name'] == "lengthMaxNumberOfBlockLength"):
                                tempLengthMaxNumberOfBlockLength = int(val)
                        elif (function['parameters'][param]['name'] == "eventType"):
                                eventType = int(val)
                                if (eventType == 1 or eventType == 2):
                                    tempLengthEventTypeRecord = 1
                                elif (eventType == 3):
                                    tempLengthEventTypeRecord = 2
                                elif (eventType == 7):
                                    tempLengthEventTypeRecord = 10
                                else:
                                    tempLengthEventTypeRecord = 0
                        
                        if (function['parameters'][param]['units'] == 'bit'):
                            decoded += (
                                '              value: ' + 
                                function['parameters'][param]['bitDecoding'][val] + 
                                '\n'
                            ) 
                        elif (function['parameters'][param]['units'] == 'hexValue'):
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
                    uds_data[data_index*2:function['numBytes']*2 
                    + data_index*2]
                )
                val = int(func_data, 16) * function['resolution']
                decoded += (
                    '            value: ' + 
                    str(val) + ' ' + 
                    function['units'] + 
                    '\n'
                )
                if (func_name == 'filePathAndNameLength'):
                    tempLengthFilePathAndName = val
                if (func_name == 'fileSizeParameterLength'):
                    tempLengthFileSizeParameter = val
                data_index += function['numBytes']
            elif (function['type'] == 'hexValue' and 
                    function['numBytes'] != 'variable'):
                func_data = (
                    uds_data[data_index*2:function['numBytes']*2 
                    + data_index*2]
                )
                if (func_name == 'periodicDataIdentifier'):
                    decoded += '            value: 0xF2' + func_data + '\n'
                else:
                    decoded += '            value: 0x' + func_data + '\n'
                data_index += function['numBytes']
            elif (function['type'] == 'largeBit' and 
                    function['numBytes'] != 'variable'):
                if (func_name == 'routineInfo'):
                    decoded += '            optional value - not used' + '\n'
                    continue
                func_data = (
                    uds_data[data_index*2:function['numBytes']*2 
                    + data_index*2]
                )
                val = str(int(func_data, 16))
                for param in function['parameters']:
                    range_nums = param.split('-')
                    if (len(range_nums) == 1):
                        if (val == range_nums[0]):
                            # Found it
                            param_name = function['parameters'][param]
                    else:
                        if (val >= range_nums[0] and val <= range_nums[1]):
                            param_name = function['parameters'][param]
                decoded += (
                    '            value: ' + val + 
                    ' - ' + param_name + '\n'
                )
                if (func_name == 'routineIdentifier'):
                    tempRoutineIdentifier = param_name
                data_index += function['numBytes']
            elif (function['type'] == 'optional' and 
                    function['numBytes'] == 'variable'):
                if (func_name == 'scalingByteExtension' and 
                        tempScalingByteDataType in function['dependentOnValues']):
                    func_data = (
                        uds_data[data_index*2:tempLengthScalingByte*2 
                        + data_index*2]
                    )
                    decoded += '            value: 0x' + func_data +'\n'
                    data_index += tempLengthScalingByte
                else:
                    decoded += '            optional value - not used' + '\n'
                    continue
            elif (function['type'] == 'NA' and 
                    function['numBytes'] == 'variable'):
                if func_name == 'memoryAddress':
                    func_data = (
                        uds_data[data_index*2:tempLengthOfMemoryAddress*2 
                        + data_index*2]
                    )
                    decoded += '            value: 0x' + func_data + '\n'
                    data_index += tempLengthOfMemoryAddress
                elif (func_name == 'memorySize' and 
                        service['service'] == 'DynamicallyDefineDataIdentifier' and 
                        subfunction == 1):
                    func_data = uds_data[data_index*2:1*2 + data_index*2]
                    decoded += (
                        '            value: ' + 
                        str(int(func_data,16)) + 
                        ' bytes\n'
                    )
                    data_index += 1
                elif func_name == 'memorySize':
                    func_data = (
                        uds_data[data_index*2:tempLengthOfMemorySize*2 
                        + data_index*2]
                    )
                    decoded += (
                        '            value: ' + 
                        str(int(func_data,16)) + 
                        ' bytes\n'
                    )
                    data_index += tempLengthOfMemorySize
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
                    func_data = uds_data[data_index*2:]
                    decoded += '            value: 0x' + func_data + '\n'
                    data_index = len(uds_data)/2 + 1
                elif func_name == 'filePathAndName':
                    func_data = (
                        uds_data[data_index*2:tempLengthFilePathAndName*2 
                        + data_index*2]
                    )
                    bytes_object = bytes.fromhex(func_data)
                    decoded += (
                        '            value: ' + 
                        bytes_object.decode("ASCII") + 
                        '\n'
                    )
                    data_index += tempLengthFilePathAndName
                elif (func_name == 'fileSizeUncompressed' or 
                        func_name == 'fileSizeCompressed'):
                    func_data = (
                        uds_data[data_index*2:tempLengthFileSizeParameter*2 
                        + data_index*2]
                    )
                    decoded += (
                        '            value: ' + 
                        str(int(int(func_data,16)/1000)) + 
                        ' Kbyte\n'
                    )
                    data_index += tempLengthFileSizeParameter
                elif func_name == 'maxNumberOfBlockLength':
                    func_data = (
                        uds_data[data_index*2:tempLengthMaxNumberOfBlockLength*2 
                        + data_index*2]
                    )
                    decoded += (
                        '            value: ' + 
                        str(int(int(func_data,16))) + 
                        ' bytes\n'
                    )
                    data_index += tempLengthMaxNumberOfBlockLength
                elif func_name == 'eventTypeRecord':
                    func_data = (
                        uds_data[data_index*2:tempLengthEventTypeRecord*2 
                        + data_index*2]
                    )
                    decoded += '            value: 0x' + func_data + '\n'
                    data_index += tempLengthEventTypeRecord
                else:
                    decoded += '            length is variable' + '\n'
                    data_index = len(uds_data)/2 + 1
        return decoded
    
                
class J1939_Message:
    """
    Data object for storing the contents of a single J1939 message

    :param priority:       0x00-0x07 (Default value = 0x00)
    :param pgn:            0x0000-0xFFFF (Default value = 0x0000)
    :param dst_addr:       0x00-0xFF, 0xFF is for broadcast (Default value = 0xFF)
    :param src_addr:       0x00-0xFF (Default value = 0x00)
    :param total_bytes:    >= 0
    :param data:           hex string, eg: "0102030405060708" (Default value = "0000000000000000")
    """
    def __init__(self, priority=0x00, 
                 pgn=0x0000, dst_addr=0xFF, 
                 src_addr=0x00, data="0000000000000000", 
                 total_bytes=None):
        if (total_bytes==None):
            total_bytes = len(data)/2
        # Make sure the given values are acceptable
        if (priority < 0x00 or 
                priority > 0x07):
            raise ValueError('Priority given is outside of acceptable value')
        if (pgn < 0x00 or 
                pgn > 0xffff):
            raise ValueError('PGN given is outside of acceptable value')
        if (dst_addr < 0x00 or 
                dst_addr > 0xff):
            raise ValueError('Destination Address given is outside of acceptable value')
        if (src_addr < 0x00 or 
                src_addr > 0xff):
            raise ValueError('Source Address given is outside of acceptable value')
        if (total_bytes < 0x00):
            raise ValueError('DLC given is outside of acceptable value')
        try:
            if (len(data) > 0):
                int(data, 16)
        except ValueError:
            raise ValueError('Data must be in hexadecimal format')
        if (len(data) % 2 != 0 or 
                len(data) > 3570):
            raise ValueError('Length of data must be an even number and shorter than 1785 bytes')
        
        # pgn is only 2 hex digits
        if (pgn <= 0xFF): 
            pgn = 0 
        # pgn is only 3 hex digits
        elif (pgn > 0xFF and 
                pgn <= 0xFFF): 
            # Only use the first nibble
            pgn = int(hex(pgn)[2:3] + '00',16) 
        # If in the destination specific range
        elif (pgn > 0xFFF and 
                pgn < 0xF000): 
            # Only use the first byte
            pgn = int(hex(pgn)[2:4] + '00',16) 
        elif (pgn >= 0xF000):
            dst_addr = 0xff

        self.priority = priority
        self.pgn = pgn
        self.dst_addr = dst_addr
        self.src_addr = src_addr
        self.total_bytes = total_bytes
        self.data = data
        
    def __str__(self):
        """
        Overrides default str method to return the parsed message
        example: "priority  pgn  src_addr --> dst_addr  [total_bytes]  data"
        """
        return "  %02X %04X %02X --> %02X [%d]  %s" % (self.priority, self.pgn, 
               self.src_addr, self.dst_addr, 
               self.total_bytes, self.data.upper())
        
          
class _J1939_MultiPacketMessage:
    """
    Creates a new multipacket message - for internal use only to deal with Transport Protocol

    :param first_message: a J1939_Message object to initialize the multipacket message
    """
    def __init__(self, first_message=None):
        if (isinstance(first_message, J1939_Message)==False or 
                first_message == None):
            raise Exception('Must include an instance of a J1939_Message')
            
        self.num_bytes = int(first_message.data[4:6] + first_message.data[2:4], 16)
        self.num_packets = int(first_message.data[6:8], 16)
        self.received_packets = 0
        self.received_bytes = 0
        
        priority = first_message.priority
        if (int(first_message.data[12:14], 16) < 240):
            pgn = int(first_message.data[12:14] + "00", 16)
        else:
            pgn = int(first_message.data[12:14] + first_message.data[10:12], 16)
        dst_addr = first_message.dst_addr
        src_addr = first_message.src_addr
        total_bytes = self.num_bytes
        data = ""
        
        # Create new message with TP abstracted
        self.completeMessage = J1939_Message(
            priority, pgn, 
            dst_addr, src_addr, 
            data, total_bytes
        ) 
        
        # Multipacket message not completed
        self.readyToSend = False 
        
    def complete(self):
        # If all expected packets have been added to multipacket message
        if (self.received_packets == self.num_packets): 
            return True
        else:
            return False


class _J1939_ISO_TP_Message:
    """
    Creates a new ISO-TP (ISO 15765-2) message - for internal use only to deal with long UDS messages

    :param first_message: a J1939_Message object to initialize the ISO-TP message
    """
    def __init__(self, first_message=None):
        if (isinstance(first_message, J1939_Message)==False or 
                first_message == None):
            raise Exception('Must include an instance of a J1939_Message')
        
        # Between 8 and 4095 bytes
        self.num_bytes = int(first_message.data[1:4], 16) 
        
        priority = first_message.priority
        pgn = 0xDA00
        dst_addr = first_message.dst_addr
        src_addr = first_message.src_addr
        # Add 40 for TruckDevil decoder to know this is a created ISO-TP 
        # message, not a properly formatted one
        data = '40' + first_message.data[4:] 
        
        self.received_bytes = (len(data)-2)/2
        
        self.nextExpectedIndex = 1
        
        # Create new message
        self.completeMessage = J1939_Message(
            priority, pgn, 
            dst_addr, src_addr, 
            data
        ) 
        
        # ISO TP message not ready to send
        self.readyToSend = False 
        
    def complete(self, curr_received = 0):
        # If all expected data has been received
        if (self.received_bytes + curr_received >= self.num_bytes): 
            return True
        else:
            return False