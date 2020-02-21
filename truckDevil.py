import struct
import serial
import threading
import time
import math
import json
import os

class TruckDevil:
    def __init__(self, port=None, serial_baud=115200, can_baud=0):
        if (port == None):
            raise Exception('No device port specified')
        self._m2 = serial.Serial(port=port, baudrate=serial_baud, dsrdtr=True)
        self._m2.setDTR(True)
        self._lockM2 = threading.RLock()
        
        self._conversations = []
        self._lockConversations = threading.RLock()
        
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
        with open(os.path.join('resources', 'src_addr_list.json')) as src_addr_file:
            self._src_addr_list = json.load(src_addr_file)
            
        self._bit_decoding_list = {}
        with open(os.path.join('resources', 'dataBitDecoding.json')) as bit_decoding_file:
            self._bit_decoding_list = json.load(bit_decoding_file)
        
        baudToSend = str(can_baud).zfill(7) #ensure that can_baud is filled to 7 digits
        self._m2.write(baudToSend.encode('utf-8'))
        
    '''
    Close the Serial connection to M2.
    '''
    def done(self):
        with self._lockM2:
            self._m2.close()
    '''    
    starts reading and storing messages
    abstractTPM: whether to abstract multipacket messages or instead to show all Transport Protocol messages(default is True)
    '''
    def startDataCollection(self, abstractTPM=True):
        if (self._dataCollectionOccurring == True):
            raise Exception('data collection already started')
        with self._lockCollectedMessages:
            self._collectedMessages = []
        if (self._collectionThread == None or self._collectionThread.is_alive() == False): #if collectionThread hasn't been started before
            self._collectionThread = threading.Thread(target=self._readMessage, args=(abstractTPM,), daemon=True)
            self._collectionThread.start()
            
        self._dataCollectionOccurring = True
            
    '''
    Return the collectedMessages list
    '''
    def getCurrentCollectedData(self):
        with self._lockCollectedMessages:
            messages = self._collectedMessages
        return messages
        
    '''
    stops reading and storing messages, resets all data
    returns the collectedMessages list
    '''
    def stopDataCollection(self):
        if (self._dataCollectionOccurring == False):
            raise Exception('data collection is already stopped')
        self._dataCollectionOccurring = False
        with self._lockConversations:
            self._conversations = []
        with self._lockCollectedMessages:
            dataCollected = self._collectedMessages
            self._collectedMessages = []
        return dataCollected
        
    '''
    save the collected messages to a text file
    messages: the collected messages outputted from stopDataCollection
    fileName: optional, the name of the file to save the data to
    verbose: optional, true in order to save the message in decoded form
    '''
    def saveDataCollected(self, messages, fileName=None, verbose=False):
        if (len(messages) == 0): #if given messages list is empty
            raise Exception('messages list is empty')
        if (fileName == None):
            fileName = 'm2_collected_data_' + str(int(time.time()))
        f = open(fileName, "x")
        f.write('Priority    PGN    Source --> Destination    [Num Bytes]    data' + '\n')
        for m in messages:
            if (verbose == False):
                f.write(str(m) + '\n')
            else:
                f.write(self.getDecodedMessage(m) + '\n')
        f.close()    
    
    '''
    takes a J1939_Message object and returns a string containing the 
    decoded version of the message
    message: J1939_Message object to be decoded, required
    returns decodedMessage
    '''
    def getDecodedMessage(self, message=None):
        if isinstance(message, J1939_Message)==False or message == None:
            raise Exception('Must include an instance of a J1939_Message')
        decoded = str(message) + '\n' 
        if (str(message.src_addr) in self._src_addr_list) and (str(message.dst_addr) in self._src_addr_list): #only include this portion if src and dest addrs are in list
            decoded += '    ' + self._src_addr_list[str(message.src_addr)] + " --> " + self._src_addr_list[str(message.dst_addr)] + '\n'
        if (str(message.pgn) in self._pgn_list): #only include this portion if the pgn of the message is in the pgn_list
            decoded += '    PGN(' + str(message.pgn) + '): ' + self._pgn_list[str(message.pgn)]['acronym'] + '\n'
            decoded += '      Label: ' + self._pgn_list[str(message.pgn)]['parameterGroupLabel'] + '\n'
            decoded += '      PGNDataLength: ' + str(self._pgn_list[str(message.pgn)]['pgnDataLength']) + '\n'
            decoded += '      TransmissionRate: ' + self._pgn_list[str(message.pgn)]['transmissionRate'] + '\n'
            for spn in self._pgn_list[str(message.pgn)]['spnList']: #for each spn that is part the given pgn
                if (str(spn) in self._spn_list): #only include this portion if the spn is in the spn_list
                    decoded += '      SPN(' + str(spn) + '): ' + self._spn_list[str(spn)]['spnName'] + '\n'
                    if (self._spn_list[str(spn)]['spnLength'] != "variable"): #ensure it's not a variable length SPN
                        totalBits = self._spn_list[str(spn)]['spnLength']
                        startBit = self._spn_list[str(spn)]['bitPositionStart']
                        endBit = startBit + totalBits
                        
                        bin_data = bin(int(message.data, 16))[2:].zfill(int((len(message.data)/2) * 8))
                        start = len(bin_data) - endBit
                        end = start + totalBits - 1
                        extracted_data = int(bin_data[start:end+1], 2) 
                        if (extracted_data != int("1"*totalBits, 2)):#if it's all 1's, means we don't care about the value, don't add
                            if(self._spn_list[str(spn)]['units'] == 'bit' and str(spn) in self._bit_decoding_list): #if it's a bit data type, use the bit_decoding_list
                                decoded += '        ' + str(extracted_data) + ' : ' + self._bit_decoding_list[str(spn)][str(extracted_data)] + '\n'    
                            else: #if the type is anything but 'bit', get the value using the resolution and offset and unit
                                extracted_data = (extracted_data * (self._spn_list[str(spn)]['resolutionNumerator'] / self._spn_list[str(spn)]['resolutionDenominator'])) + self._spn_list[str(spn)]['offset'] #multiply by the resolution and add offset to get appropriate range
                                if (extracted_data.is_integer()): 
                                    extracted_data = str(int(extracted_data))
                                else:
                                    extracted_data = "%.2f" % extracted_data
                                decoded += '        ' + str(extracted_data) + ' ' + self._spn_list[str(spn)]['units'] + '\n'                        
        return decoded
    
         
    '''
    read and print all messages from M2. If readTime and numMessages are both specified, stop printing when whichever one is reached first.
    abstractTPM: whether to abstract multipacket messages or instead to show all Transport Protocol messages(default is True)
    readTime: optional argument, the amount of time to print messages for. If not specified, it will not be limited
    numMessages: number of messages to print before stopping. If not specified, it will not be limited
    verbose: optional, true in order to print the message in decoded form (uses getDecodedMessage)
    '''
    def printMessages(self, abstractTPM=True, readTime=None, numMessages=None, verbose=False):
        if (self._dataCollectionOccurring == True): #Only allow if data collection is not occurring
                raise Exception('stop data collection before proceeding with this function')
        if (readTime != None): #if optional readTime is utilized
            self._printMessagesTimer = threading.Timer(readTime, self._setPrintMessagesTimeDone)
            self._printMessagesTimer.start()
        messagesPrinted = 0
        with self._lockConversations:
            self._conversations = []
        self._printMessagesTimeDone = False
        #keep printing while our timer isn't done or the number of messages to print hasn't been reached (whichever comes first) - if neither are utilized, keep going forever
        while self._printMessagesTimeDone == False and (numMessages == None or messagesPrinted < numMessages): 
            if (self._dataCollectionOccurring == True): #Only allow if data collection is not occurring
                raise Exception('data collection began abruptly, stop data collection before proceeding with this function')
            #look for full multipacket message to return first, if none found, receive from socket
            self._lockConversations.acquire()
            for i in range(0, len(self._conversations)): 
                #found one ready to send - return it 
                if (self._conversations[i].readyToSend):
                    message = self._conversations[i].completeMessage
                    del self._conversations[i]
                    if (verbose == False):
                        print(message) #print completed multipacket message
                    else:
                        print(self.getDecodedMessage(message))
                    messagesPrinted = messagesPrinted + 1
                    break
            self._lockConversations.release()
        
            #get one CAN message from M2 (ex: 18EF0B00080102030405060708)
            can_packet = self._readOneMessage()
            
            #src addr is byte 4
            src_addr = int(can_packet[6:8], 16)
            
            '''pgn is byte 2 and 3, where byte 2 is pdu_format
            and byte 3 is pdu_specific'''
            pgn = can_packet[2:6]
            
            pdu_format = int(pgn[0:2], 16)
            pdu_specific = int(pgn[2:4], 16)
            
            '''if pdu_format is 0-239 
            then pdu_specific is dst_addr, 
            otherwise it is group extension'''
            if (pdu_format < 240):
                dst_addr = pdu_specific
                pgn = pgn[0:2] + "00" #add 00 to pgn if destination specific (ex: EC0B pgn becomes EC00 with dst_addr 0x0B)
            else:
                dst_addr = 0xFF #broadcast message
            pgn = int(pgn, 16)
            
            #priority is bits 4-6 in byte 1 of message (ex: byte 1 = 0x18, 0b00011000 = priority of 6)
            priority = int(bin(int(can_packet[0:2], 16))[2:5], 2)
            
            #data length is byte 5
            dlc = int(can_packet[8:10], 16)
            
            #data is contained in bytes 6-13, in a hex string format
            data = can_packet[10:26]
            
            message = J1939_Message(priority, pgn, dst_addr, src_addr, data, dlc)
            
            #Multipacket message received, broadcasted or peer-to-peer request to send
            if (pgn == 0xec00 and (data[0:2] == "20" or data[0:2] == "10" )):
                mp_message = J1939_MultiPacketMessage(message)
                with self._lockConversations:
                    self._conversations.append(mp_message)
                if (abstractTPM==True): #if abstractTPM is True, break here and don't print this message
                    continue
                
            #Multipacket data transfer message recieved
            if (pgn == 0xeb00):
                #find the correct conversation 
                self._lockConversations.acquire()
                for i in range(0, len(self._conversations)): 
                    #correct conversation
                    if (self._conversations[i].completeMessage.src_addr == src_addr and self._conversations[i].completeMessage.dst_addr == dst_addr):
                        self._conversations[i].received_packets += 1
                        if (self._conversations[i].complete()): #received all the packets
                            bytes_left = self._conversations[i].num_bytes - self._conversations[i].received_bytes
                            self._conversations[i].received_bytes += bytes_left
                            data_index = (bytes_left*2) + 2
                            self._conversations[i].completeMessage.data += data[2:data_index] #copy final bytes
                            self._conversations[i].readyToSend = True #ready to send next time a message is read
                        else: #more packets needed, add 7 bytes of data to stored message
                            self._conversations[i].received_bytes += 7
                            self._conversations[i].completeMessage.data += data[2:16] #skip first byte, this is counter    
                        break
                self._lockConversations.release()        
                if (abstractTPM==True): #if abstractTPM is True, break here and don't print this message
                    continue
            if (verbose == False):
                print(message) #print it
            else:
                print(self.getDecodedMessage(message))
            messagesPrinted = messagesPrinted + 1          

    '''
    send message to M2 to get pushed to the BUS.
    message: a J1939_Message to be sent on the BUS
    '''
    def sendMessage(self, message):
        #can_packet = "$18EF0B00080102030405060708*"
        can_packet = "$" #add start delimiter
        #priority is bits 4-6 in byte 1 of message (ex: byte 1 = 0x18, 0b00011000 = priority of 6)
        pri = hex(int('000' + bin(message.priority)[2:].zfill(3) + '00', 2))[2:4].zfill(2).upper()
        can_packet += pri
        
        data_bytes = int(len(message.data)/2) #get total number of bytes to send
        
        dst_addr = hex(message.dst_addr)[2:].zfill(2).upper()
        pgn = hex(message.pgn)[2:].zfill(4).upper()
        src_addr = hex(message.src_addr)[2:].zfill(2).upper()
        dlc = hex(data_bytes)[2:].zfill(2)
        data = message.data.upper()
        
        #sending multipacket message - if number of bytes to send is more than 8 (ex: 1CECFF000820120003FFCAFE00)
        if(data_bytes > 8):
            can_packet += 'EC' #EC is byte 2
            
            num_bytes = "%04X" % data_bytes #change int to 4 character hex string
            num_packets = "%02X" % math.ceil(data_bytes / 7)
             
            can_packet += dst_addr #destination address is byte 3         
            can_packet += src_addr #src addr is byte 4
            can_packet += '08' #dlc is byte 5 (multipacket messages are always 8 bytes each)
            
            if (message.dst_addr == 0xFF):
                #send BAM message (ex: 20120003FFCAFE00)
                control_message = "20" + num_bytes[2:4] + num_bytes[0:2] + num_packets + "FF" + pgn[2:4] + pgn[0:2] + "00"
            else:
                #send RTS message
                control_message = "10" + num_bytes[2:4] + num_bytes[0:2] + num_packets + "FF" + pgn[2:4] + pgn[0:2] + "00"
            
            can_packet += control_message #bytes 6-13 is the control message
            can_packet += "*" #add end delimiter
            with self._lockM2:
                self._m2.write(can_packet.encode('utf-8')) #send bam or rts message
            if(message.dst_addr == 0xFF): 
                time.sleep(0.1)#sleep 100ms before transmitting next message as stated in standard
            else:
                time.sleep(0.15)#sleep 150ms before transmitting next message to allow for CTS to come through
                
            can_packet = "$" #new packet
            can_packet += pri #byte 1 is priority
            can_packet += 'EB' #EB is byte 2 for data transfer packet
            can_packet += dst_addr #destination address is byte 3         
            can_packet += src_addr #src addr is byte 4
            can_packet += '08' #dlc is byte 5 (multipacket messages are always 8 bytes each)
            
            for i in range(0, int(num_packets, 16)):
                if ((i*7) < data_bytes - data_bytes % 7): #if a full 7 bytes is available
                    seven_bytes = data[i*14:(i*14)+14]
                else: #pad remaining last packet with FF for data
                    seven_bytes = data[i*14:(i*14)+((data_bytes%7)*2)] + "FF"*(7-(data_bytes%7))
                data_transfer = "%02X" % (i+1) 
                data_transfer += seven_bytes
                with self._lockM2:
                    self._m2.write((can_packet + data_transfer + '*').encode('utf-8')) #adds end delimiter
                #time.sleep(0.1)#sleep 100ms before transmitting messages as stated in standard   
                
        #sending non-multipacket message - if number of bytes to send is less than or equal to 8
        else:
            #the first half of pgn is pdu_format (byte 2)
            can_packet += pgn[0:2]
            
            '''if a destination specific message, pdu_specific (byte 3) 
            will be destination address, otherwise it is the last half of pgn'''
            if (message.dst_addr != 0xff): #destination specific
                can_packet += dst_addr
            else:
                can_packet += pgn[2:]
            
            #src addr is byte 4
            can_packet += src_addr
            
            #the data length is byte 5 
            can_packet += dlc
            
            #data is in bytes 6-13, padded with FF's if less than 8 bytes
            can_packet += data
            can_packet += "FF"*(8-data_bytes)
            
            can_packet += "*" #add end delimiter
            with self._lockM2:
                self._m2.write(can_packet.encode('utf-8'))
            
    #used with internal timer for printMessages function
    def _setPrintMessagesTimeDone(self):
        self._printMessagesTimeDone = True
        
    #used with internal timer for _readMessage function
    def _setCollectionTimeDone(self):
        self._collectionTimeDone = True
      
    #read and store messages in the collectedMessages array  
    def _readMessage(self, abstractTPM=True):
        #keep collection while our timer isn't done or the number of messages to collect hasn't been reached (whichever comes first) - if neither are utilized, keep going forever
        while True: 
            if (self._dataCollectionOccurring == True): #keep the thread from executing if not in collection state
                #look for full multipacket message to return first, if none found, receive from socket
                self._lockConversations.acquire()
                for i in range(0, len(self._conversations)): 
                    #found one ready to send - return it 
                    if (self._conversations[i].readyToSend):
                        message = self._conversations[i].completeMessage
                        del self._conversations[i]
                        with self._lockCollectedMessages:
                            self._collectedMessages.append(message) #add completed multipacket message to collectedMessages list
                        break
                self._lockConversations.release()
            
                #get one CAN message from M2 (ex: 18EF0B00080102030405060708)
                can_packet = self._readOneMessage()
                
                #src addr is byte 4
                src_addr = int(can_packet[6:8], 16)
                
                '''pgn is byte 2 and 3, where byte 2 is pdu_format
                and byte 3 is pdu_specific'''
                pgn = can_packet[2:6]
                
                pdu_format = int(pgn[0:2], 16)
                pdu_specific = int(pgn[2:4], 16)
                
                '''if pdu_format is 0-239 
                then pdu_specific is dst_addr, 
                otherwise it is group extension'''
                if (pdu_format < 240):
                    dst_addr = pdu_specific
                    pgn = pgn[0:2] + "00" #add 00 to pgn if destination specific (ex: EC0B pgn becomes EC00 with dst_addr 0x0B)
                else:
                    dst_addr = 0xFF #broadcast message
                pgn = int(pgn, 16)
                
                #priority is bits 4-6 in byte 1 of message (ex: byte 1 = 0x18, 0b00011000 = priority of 6)
                priority = int(bin(int(can_packet[0:2], 16))[2:5], 2)
                
                #data length is byte 5
                dlc = int(can_packet[8:10], 16)
                
                #data is contained in bytes 6-13, in a hex string format
                data = can_packet[10:26]
                
                message = J1939_Message(priority, pgn, dst_addr, src_addr, data, dlc)
                
                #Multipacket message received, broadcasted or peer-to-peer request to send
                if (pgn == 0xec00 and (data[0:2] == "20" or data[0:2] == "10" )):
                    mp_message = J1939_MultiPacketMessage(message)
                    with self._lockConversations:
                        self._conversations.append(mp_message)
                    if (abstractTPM==True): #if abstractTPM is True, break here and don't add this message to collectedMessages
                        continue
                    
                #Multipacket data transfer message recieved
                if (pgn == 0xeb00):
                    #find the correct conversation 
                    self._lockConversations.acquire()
                    for i in range(0, len(self._conversations)): 
                        #correct conversation
                        if (self._conversations[i].completeMessage.src_addr == src_addr and self._conversations[i].completeMessage.dst_addr == dst_addr):
                            self._conversations[i].received_packets += 1
                            if (self._conversations[i].complete()): #received all the packets
                                bytes_left = self._conversations[i].num_bytes - self._conversations[i].received_bytes
                                self._conversations[i].received_bytes += bytes_left
                                data_index = (bytes_left*2) + 2
                                self._conversations[i].completeMessage.data += data[2:data_index] #copy final bytes
                                self._conversations[i].readyToSend = True #ready to send next time a message is read
                            else: #more packets needed, add 7 bytes of data to stored message
                                self._conversations[i].received_bytes += 7
                                self._conversations[i].completeMessage.data += data[2:16] #skip first byte, this is counter
                            break
                    self._lockConversations.release()        
                    if (abstractTPM==True): #if abstractTPM is True, break here and don't add this message to collectedMessages
                        continue
                with self._lockCollectedMessages:        
                    self._collectedMessages.append(message) #add message to collectedMessages list
        
    #reads one message from M2 and returns it 
    #(hex string format ex: 18EF0B00080102030405060708)   
    def _readOneMessage(self):
        response = ""
        startReading = False
        while True:
            with self._lockM2:
                char = self._m2.read().decode("utf-8") #get next character from M2
            if (startReading == False and char == '$'): #denotes start of CAN message
                startReading = True
            elif (startReading == True and char != '*'): #reading contents of CAN message, appending to response
                response += char
            elif (startReading == True and char == '*'): #denotes end of CAN message - return response
                return response
                
                
'''        
takes all long values except data (a string of hex characters)
priority:       0x00-0x07
pgn:            0x0000-0xFFFF
dst_addr:       0x00-0xFF, 0xFF is for broadcast
src_addr:       0x00-0xFF
total_bytes:    >= 0
data:           hex string, eg: "0102030405060708"  
'''
class J1939_Message:
    def __init__(self, priority=0x00, pgn=0x0000, dst_addr=0xFF, src_addr=0x00, data="0000000000000000", total_bytes=None):
        if (total_bytes==None):
            total_bytes = len(data)/2
        #Make sure the given values are acceptable
        if (priority < 0x00 or priority > 0x07):
            raise ValueError('Priority given is outside of acceptable value')
        if (pgn < 0x00 or pgn > 0xffff):
            raise ValueError('PGN given is outside of acceptable value')
        if (dst_addr < 0x00 or dst_addr > 0xff):
            raise ValueError('Destination Address given is outside of acceptable value')
        if (src_addr < 0x00 or src_addr > 0xff):
            raise ValueError('Source Address given is outside of acceptable value')
        if (total_bytes < 0x00):
            raise ValueError('DLC given is outside of acceptable value')
        try:
            if (len(data) > 0):
                int(data, 16)
        except ValueError:
            raise ValueError('Data must be in hexadecimal format')
        if (len(data) % 2 != 0 or len(data) > 3570):
            raise ValueError('Length of data must be an even number and shorter than 1785 bytes')

        self.priority = priority
        self.pgn = pgn
        self.dst_addr = dst_addr
        self.src_addr = src_addr
        self.total_bytes = total_bytes
        self.data = data
        
    #overrides default str method to return the parsed message
    #"priority  pgn  src_addr  dst_addr  [len]  data"
    def __str__(self):
        return "  %02X %04X %02X --> %02X [%d]  %s" % (self.priority, self.pgn, 
        self.src_addr, self.dst_addr, self.total_bytes, self.data.upper())
        
        
'''
Creates a new multipacket message
first_message: a J1939_Message object to initialize the multipacket message
'''    
class J1939_MultiPacketMessage:
    def __init__(self, first_message=None):
    
        if isinstance(first_message, J1939_Message)==False or first_message == None:
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
        
        self.completeMessage = J1939_Message(priority, pgn, dst_addr, src_addr, data,total_bytes) #create new message with TP abstracted
        
        self.readyToSend = False #multipacket message not completed
        
    def complete(self):
        if (self.received_packets == self.num_packets): #if all expected packets have been added to multipacket message
            return True
        else:
            return False
        