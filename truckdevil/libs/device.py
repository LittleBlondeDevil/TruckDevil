from can import interface, Message
import serial
import time


class Device:
    def __init__(self, device_type="m2", serial_port=None, channel='can0', can_baud=0):
        """
        Defines a new hardware device

        :param device_type: either "m2" or "socketcan" (Default value = "m2").
        :param serial_port: serial port that the M2 is connected to, if used. For example: COM7 or /dev/ttyX. 0 if not using M2."
        :param channel: CAN channel to send/receive on. For example: can0, can1, or vcan0. (Default value = 'can0')
        :param can_baud: baudrate on the CAN bus. Most common are 250000 and 500000. Use 0 for autobaud detection. (Default value = 0)
        """
        self._device_type = device_type
        self._serial_port = serial_port
        self._channel = channel
        self._can_baud = can_baud
        if device_type.lower() == "m2":
            if serial_port is None:
                raise ValueError("If using M2, serial port must be specified")
            self._m2 = serial.Serial(
                port=serial_port, baudrate=115200,
                dsrdtr=True
            )
            # self._m2.setDTR(True)
            # self._lockM2 = threading.RLock()
            # Ensure that can_baud is filled to 7 digits

            self._m2used = True
        else:
            self._can_bus = interface.Bus(bustype=device_type, channel=channel, bitrate=can_baud)
            self._m2used = False

    def __str__(self):
        device_str = "\n***** CAN Device Info *****" + "\nDevice Type: " + self._device_type
        if self._serial_port is not None:
            device_str += "\nSerial Port: " + self._serial_port
        device_str += "\nCAN Channel: " + self._channel + "\nBaud Rate: " + str(self._can_baud)
        return device_str

    @property
    def m2_used(self):
        return self._m2used

    @property
    def m2(self):
        return self._m2

    @property
    def can_bus(self):
        return self._can_bus

    def init_m2(self, can_baud: int, channel: str):
        """
        Send command to M2 to set the CAN baud rate and channel that will be used

        :param can_baud: baudrate on the CAN bus. Most common are 250000 and 500000. Use 0 for autobaud detection.
        :param channel: CAN channel to send/receive on. For example: can0, can1, or vcan0.
        """
        baud_to_send = '#' + str(can_baud).zfill(7)
        if channel == "can0" or channel == "can1":
            baud_to_send += channel
        else:
            baud_to_send += "can0"
        self.m2.write(baud_to_send.encode('utf-8'))

    def read(self) -> Message:
        """
        Reads one message from device, creates python-can Message, and returns it
        """
        if self.m2_used:
            response = ""
            start_reading = False
            char = ''
            while True:
                # Receive next character from M2
                if self._m2.inWaiting() > 0:
                    # TODO: change back
                    # b = self._m2.read()
                    # try:
                    #    char = b.decode("utf-8")
                    # except:
                    #    print("failed: " + str(b))
                    #    continue
                    char = self._m2.read().decode("utf-8")
                else:
                    time.sleep(0.01)
                    continue
                # Denotes start of CAN message
                if start_reading is False and char == '$':
                    response = '$'
                    start_reading = True
                # Reading contents of CAN message, appending to response
                elif start_reading is True and char != '*':
                    response += char
                # Denotes end of CAN message - return response
                elif (start_reading is True and len(response) > 0 and
                      response[0] == '$' and char == '*' and
                      response.count('$') == 1):
                    str_frame = response[1:]
                    can_id = int(str_frame[0:8], 16)
                    dlc = int(str_frame[8:10], 16)
                    data = bytes.fromhex(str_frame[10:])
                    return Message(arbitration_id=can_id, channel=self._channel, dlc=dlc, data=data,
                                   is_extended_id=True, timestamp=time.time())
                # If the serial buffer gets flushed during reading
                elif response.count('$') > 1:
                    response = ""
                    start_reading = False
                    char = ''
        else:
            msg = None
            while msg is None:
                msg = self._can_bus.recv(0.01)
            return msg

    def send(self, msg: Message):
        if self.m2_used:
            # convert from Message to 1CECFF000820120003FFCAFE00 format
            can_id = hex(msg.arbitration_id)[2:].zfill(8)
            dlc = hex(msg.dlc)[2:].zfill(2)
            data = ''.join('{:02x}'.format(x) for x in msg.data)
            self.m2.write("{}{}{}".format(can_id, dlc, data).encode('utf-8'))
        else:
            self._can_bus.send(msg)
