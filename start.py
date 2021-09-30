import truckDevil as td
import importlib
from sys import exit


class CANConnection:
    def __init__(self):
        """
        print("Start by defining the CAN device in use, '?' for info")
        # TODO: add read from/save to file for device info, use JSON
        self.device = input("Select hardware device (m2, socketcan): ")
        if self.device.lower() == "m2":
            self.serial_port = input("Select serial port (e.g. COM3, /dev/ttyACM0): ")
        self.can_channel = input("Select CAN channel (e.g. can0, can1, vcan0): ")
        self.can_baud = input("Select CAN baud (e.g. 250000, 500000, 0 for autobaud): ")
        # TODO: add type checks for these and ? responses for each
        """
        self.device = "m2"
        self.serial_port = "COM5"
        self.can_channel = "can0"
        self.can_baud = "250000"
    def __str__(self):
        device_str = "\n***** CAN Device Info *****" + "\nDevice Type: " + self.device
        if self.serial_port is not None:
            device_str += "\nSerial Port: " + self.serial_port
        device_str += "\nCAN Channel: " + self.can_channel + "\nBaud Rate: " + self.can_baud
        return device_str


def main_menu(connection, devil):
    print("\n***** Main Menu *****\n"
          "  1) Read messages\n"
          "  2) Send message\n"
          "  3) Fuzzer\n"
          "  4) Discovery modules\n"
          "  5) Attack modules\n"
          "  6) DIY modules\n"
          "  7) List CAN device info\n"
          "  8) Modify CAN device info")
    while True:
        main_select = input("\nSelect an option (? for help, q to quit): ")
        if main_select == "1":
            mod = importlib.import_module("readMessages")
            try:
                mod.main_mod(devil)
                # TODO: create filtering mechanism in readMessages built-in
            except KeyboardInterrupt as e:
                continue
            except Exception as e:
                print(e)
                continue
        elif main_select == "2":
            mod = importlib.import_module("sendMessage")
            try:
                mod.main_mod(devil)
            except KeyboardInterrupt as e:
                continue
            except Exception as e:
                print(e)
                continue
        elif main_select == "3":
            mod = importlib.import_module("j1939_fuzzer")
            try:
                mod.main_mod(devil)
            except KeyboardInterrupt as e:
                continue
            #except Exception as e:
            #    print(e)
            #    continue
        elif main_select == "7":
            print(str(connection))
        elif main_select == "8":
            connection = CANConnection()
            devil.done()
            devil = td.TruckDevil(connection.device, connection.serial_port, connection.can_channel,
                                  connection.can_baud)
        elif main_select == "?":
            print("\n***** Main Menu *****\n"
                  "  1) Read messages\n"
                  "  2) Send message\n"
                  "  3) Fuzzer\n"
                  "  4) Discovery modules\n"
                  "  5) Attack modules\n"
                  "  6) DIY modules\n"
                  "  7) List CAN device info\n"
                  "  8) Modify CAN device info")
        elif main_select == "q" or main_select == "quit" or main_select == "exit":
            exit(0)


if __name__ == "__main__":
    connection = CANConnection()
    devil = td.TruckDevil(connection.device, connection.serial_port, connection.can_channel, connection.can_baud)
    main_menu(connection, devil)
    devil.done()
