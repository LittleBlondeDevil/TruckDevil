import socket
import threading
import time
import can
from can import Message, interface
import serial


class Device:
    def __init__(
        self,
        device_type="m2",
        serial_port=None,
        channel="can0",
        can_baud=0,
        tcp_ip=None,
        port=None,
    ):
        """
        Defines a new hardware device

        :param device_type: either "m2" or "socketcan" (Default value = "m2").
        :param serial_port: serial port that the M2 is connected to, if used. For example: COM7 or /dev/ttyX.
        :param channel: CAN channel to send/receive on. For example: can0, can1, or vcan0. (Default value = 'can0')
        :param can_baud: baudrate on the CAN bus. Most common are 250000 and
            500000. Use 0 for autobaud detection. (Default value = 0)
        :param tcp_ip: IP address of the M2 device over TCP (Default value = None).
        :param port: TCP port or alias for serial_port (Default value = None).
        """
        self._device_type = device_type.lower()
        self._tcp_ip = tcp_ip
        # Support port alias or serial_port
        if port is not None and serial_port is None:
            self._port = port
            self._serial_port = port
        elif serial_port is not None:
            self._serial_port = serial_port
            self._port = serial_port
        else:
            self._serial_port = None
            self._port = None

        self._channel = channel
        self._can_baud = int(can_baud)
        self.device_lock = threading.RLock()
        self._acknowledged_flush = True
        self._m2used = False
        self._tcpused = False
        self._m2 = None
        self._socket = None
        self._can_bus = None

        if self._device_type == "m2":
            if self._tcp_ip is not None:
                self._tcpused = True
                if self._port is None:
                    raise ValueError("If using M2 over TCP, port must be specified")
                self._port = int(self._port)
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                self._socket.connect((self._tcp_ip, self._port))
                self.init_m2(self._can_baud, self._channel)
            else:
                if self._serial_port is None:
                    raise ValueError("If using M2, serial port must be specified")
                self._m2 = serial.Serial(port=self._serial_port, baudrate=115200, dsrdtr=True)
                self._m2.setDTR(True)
                # self._lockM2 = threading.RLock()
                # Ensure that can_baud is filled to 7 digits
                self._m2used = True
                self.init_m2(self._can_baud, self._channel)
        else:
            # TODO: test other devices
            self._can_bus = interface.Bus(
                interface=device_type, channel=channel, bitrate=self._can_baud
            )
            self._m2used = False

    def __str__(self):
        device_str = (
            "\n***** CAN Device Info *****"
            + "\nDevice Type: "
            + str(self._device_type)
            + (" encoder" if self._tcp_ip else "")
        )
        if self._tcp_ip:
            device_str += "\nTCP IP: " + str(self._tcp_ip)
        if self._port is not None:
            if self._tcp_ip:
                device_str += "\nPort: " + str(self._port)
            else:
                device_str += "\nSerial Port: " + str(self._port)
        device_str += (
            "\nCAN Channel: " + str(self._channel) + "\nBaud Rate: " + str(self._can_baud)
        )
        return device_str

    @property
    def m2_used(self):
        return self._m2used or self._tcpused

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
        baud_to_send = "#" + str(can_baud).zfill(7)
        if channel == "can0" or channel == "can1":
            baud_to_send += channel
        else:
            baud_to_send += "can0"
            self._channel = "can0"
        self._write_raw(baud_to_send.encode("utf-8"))

    def flush_m2(self):
        """
        Clears out any partial frames waiting in the buffer.
        """
        self._acknowledged_flush = False
        if self._m2used:
            self._m2.reset_input_buffer()
        elif self._tcpused and self._socket:
            try:
                prev_timeout = self._socket.gettimeout()
                self._socket.settimeout(0.0)
                try:
                    while True:
                        chunk = self._socket.recv(4096)
                        if not chunk:
                            break
                except (BlockingIOError, socket.timeout, TimeoutError):
                    pass
                finally:
                    self._socket.settimeout(prev_timeout)
            except Exception:
                pass

    def read(self, timeout=None) -> Message:
        """
        Reads one message from device, creates python-can Message, and returns it.
        If optional timeout occurs, return None.
        """
        if self._m2used or self._tcpused:
            return self._read_m2_common(timeout)
        else:
            return self._can_bus.recv(timeout=timeout)

    def send(self, msg: Message):
        """
        Sends a python-can Message to the underlying device.
        """
        if self._m2used or self._tcpused:
            # Convert from python-can Message to $1CECFF000820120003FFCAFE00* format
            can_id = hex(msg.arbitration_id)[2:].zfill(8)
            dlc = hex(msg.dlc)[2:].zfill(2)
            data = "".join("{:02x}".format(x) for x in msg.data)
            frame = "${}{}{}*".format(can_id, dlc, data)
            self._write_raw(frame.encode("utf-8"))
        else:
            sleeptime = 0.0
            while True:
                try:
                    self._can_bus.send(msg)
                    time.sleep(sleeptime)
                    return
                except can.CanOperationError as e:
                    if sleeptime == 0.0:
                        sleeptime = 0.001
                    else:
                        sleeptime = sleeptime * 10
                    print(f"error: {e} backing off delay to {sleeptime}")
                except Exception as e:
                    print(f"error: {e} aborting.")
                    return

    def _write_raw(self, raw_bytes: bytes):
        """Helper that writes raw bytes either to serial or TCP socket."""
        if self._m2used:
            self._m2.write(raw_bytes)
        elif self._tcpused:
            self._socket.sendall(raw_bytes)

    def _read_m2_common(self, timeout=None) -> Message:  # noqa: C901
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
                chunk = self._m2.read(1)
                if len(chunk) == 0:
                    self._m2.timeout = None
                    return None
                char = chunk.decode("utf-8", errors="replace")
            else:  # self._tcpused
                try:
                    chunk = self._socket.recv(1)
                    if len(chunk) == 0:
                        return None
                    char = chunk.decode("utf-8", errors="replace")
                except (socket.timeout, TimeoutError):
                    return None

            # Denotes start of CAN message
            if not start_reading and char == "$":
                response = "$"
                start_reading = True
            # Reading contents of CAN message
            elif start_reading and char != "*":
                response += char
            # Denotes end of CAN message
            elif start_reading and char == "*" and response.startswith("$"):
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
                        timestamp=time.time(),
                    )
                except ValueError as e:
                    print(f"error in creating Message in device read: {e}")
                    print(f"str_frame: {response}")
                    continue

            # If the buffer gets flushed during reading
            if response.count("$") > 1:
                response = ""
                start_reading = False
