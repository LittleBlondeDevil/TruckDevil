import can
from can import interface, Message
import serial
import time
import threading
import socket


class Device:
    def __init__(self, device_type="m2", tcp_ip=None, port=None, channel='can0', can_baud=0):
        """
        Defines a new hardware device

        :param device_type: either "m2" or "socketcan" (Default value = "m2").
        :param tcp_ip: IP address of the M2 if using TCP, e.g. 192.168.7.2.
        :param port: serial port that the M2 is connected to, if used. For example: COM7 or /dev/ttyX. 
                     If using M2 encoder over TCP, this is the TCP port. For example: 1234.
        :param channel: CAN channel to send/receive on. For example: can0, can1, or vcan0. (Default value = 'can0').
        :param can_baud: baudrate on the CAN bus. Most common are 250000 and 500000. Use 0 for autobaud detection on the M2 only. (Default value = 0)
        """
        self._device_type = device_type.lower()
        self._tcp_ip = tcp_ip
        self._port = port
        self._channel = channel
        self._can_baud = int(can_baud)

        self.device_lock = threading.RLock()
        self._acknowledged_flush = True
        self._m2used  = False
        self._tcpused = False
        self._m2 = None
        self._socket = None
        self._can_bus = None

        if self._device_type == "m2": # m2
            if self._tcp_ip is not None: # over tcp
                self._tcpused = True
                if self._port is None:
                    raise ValueError("If using M2 over TCP, port must be specified")
                self._port = int(self._port)
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self._socket.connect((self._tcp_ip, self._port))
                self.init_m2(self._can_baud, self._channel)

            else: # over serial 
                if self._port is None:
                    raise ValueError("If using M2, serial port must be specified")
                self._m2 = serial.Serial(
                    port=self._port, baudrate=115200,
                    dsrdtr=True
                )
                self._m2.setDTR(True)
                # self._lockM2 = threading.RLock()
                # Ensure that can_baud is filled to 7 digits
                self._m2used = True
                self.init_m2(self._can_baud, self._channel)

        else: # python-can
            # TODO: test other devices
            self._can_bus = interface.Bus(bustype=self._device_type, channel=self._channel, bitrate=self._can_baud)
            self._m2used = False

    def __str__(self):
        device_str = "\n***** CAN Device Info *****"
        device_str += "\nDevice Type: " + str(self._device_type) + (" encoder" if self._tcp_ip else "")
        if self._tcp_ip:
            device_str += "\nTCP IP: " + str(self._tcp_ip)
        if self._port:
            device_str += "\nPort: " + str(self._port)
        device_str += "\nCAN Channel: " + str(self._channel)
        device_str += "\nBaud Rate: " + str(self._can_baud)
        return device_str

    @property
    def m2_used(self):
        return self._m2used

    def init_m2(self, can_baud: int, channel: str):
        """
        Send command to M2 to set the CAN baud rate and channel that will be used
        """
        baud_to_send = '#' + str(can_baud).zfill(7)
        if self._channel == "can0" or self._channel == "can1":
            baud_to_send += self._channel
        else:
            baud_to_send += "can0"
            self._channel = "can0"
        self._write_raw(baud_to_send.encode('utf-8'))

    def flush_m2(self):
        """
        Clears out any partial frames waiting in the buffer.
        """
        self._acknowledged_flush = False
        if self._m2used:
            self._m2.reset_input_buffer()
        elif self._tcpused:
            pass

    def read(self, timeout=0.1) -> Message:
        """
        Reads one message from device, creates python-can Message, and returns it.
        If optional timeout occurs, return None.
        """
        if self._m2used or self._tcpused:
            return self._read_m2_common(timeout)
        else:
            # For python-can
            return self._can_bus.recv(timeout=timeout)

    def send(self, msg: Message):
        """
        Sends a python-can Message to the underlying device.
        """
        if self._m2used or self._tcpused:
            # Convert from python-can Message to $1CECFF000820120003FFCAFE00* format
            can_id = hex(msg.arbitration_id)[2:].zfill(8)
            dlc = hex(msg.dlc)[2:].zfill(2)
            data = ''.join('{:02x}'.format(x) for x in msg.data)
            frame = "${}{}{}*".format(can_id, dlc, data)
            self._write_raw(frame.encode('utf-8'))
        else:
            sleeptime = 0.0
            while True:
                try:
                    self._can_bus.send(msg)
                    time.sleep(sleeptime)
                except can.CanOperationError as e:
                    if sleeptime == 0.0:
                        sleeptime = 0.001
                    else:
                        sleeptime = sleeptime * 10
                    print(f'error: {e} backing off delay to {sleeptime:d}')
                except Exception as e:
                    print(f'error: {e} aborting.')
                    return
                finally:
                    return

    ### internal helper methods ###            
    def _write_raw(self, raw_bytes: bytes):
        """ Helper that writes raw bytes either to serial or TCP socket. """
        if self._m2used:
            self._m2.write(raw_bytes)
        elif self._tcpused:
            self._socket.sendall(raw_bytes)

    def _read_m2_common(self, timeout=0.1) -> Message:
        """
        Single method that reads data from either the serial port or the TCP socket,
        using the same framing as the original M2 logic.
        """
        response = ""
        start_reading = False

        # set up a read timeout for whichever underlying I/O we have
        if self._m2used:
            self._m2.timeout = timeout
        elif self._tcpused:
            self._socket.settimeout(timeout)

        while True:
            if not self._acknowledged_flush:
                response = ""
                start_reading = False
                self._acknowledged_flush = True
            # Receive next character from M2
            if self._m2used:
                chunk = self._m2.read(1)  # 1 byte
                if len(chunk) == 0:
                    # timeout or EOF
                    self._m2.timeout = None
                    continue
                char = chunk.decode("utf-8", errors="replace")

            else:  # self._tcpused
                try:
                    chunk = self._socket.recv(1)
                    if len(chunk) == 0:
                        continue
                    char = chunk.decode("utf-8", errors="replace")
                except socket.timeout:
                    continue

            # Denotes start of CAN message
            if not start_reading and char == '$':
                response = '$'
                start_reading = True
            # Reading contents of CAN message
            elif start_reading and char != '*':
                response += char
            # Denotes end of CAN message
            elif start_reading and char == '*' and response.startswith('$'):
                try:
                    str_frame = response[1:]  # strip off leading $
                    if len(str_frame) < 10:
                        raise ValueError("str_frame too short")

                    can_id = int(str_frame[0:8], 16)
                    dlc = int(str_frame[8:10], 16)
                    data_hex = str_frame[10:]
                    # TODO: remove print, or add check to ensure data is not more than 8 bytes long bc some error
                    #  occurred
                    data = bytes.fromhex(data_hex)
                    return Message(
                        arbitration_id=can_id,
                        channel=self._channel,
                        dlc=dlc,
                        data=data,
                        is_extended_id=True,
                        timestamp=time.time()
                    )
                except ValueError as e:
                    print(f"error in creating Message in device read: {e}")
                    print(f"str_frame: {response}")
                    continue

            # If the buffer gets flushed during reading
            if response.count('$') > 1:
                response = ""
                start_reading = False
