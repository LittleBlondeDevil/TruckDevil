import argparse
import cmd

from j1939.j1939 import J1939Interface, J1939Message


class Sender:
    def __init__(self, device):
        self.devil = J1939Interface(device)


class SendCommands(cmd.Cmd):
    intro = "Welcome to the Send Messages tool."
    prompt = "(truckdevil.send_messages) "

    def __init__(self, argv, device):
        super().__init__()
        self.sender = Sender(device)

    def do_send(self, arg):
        """
        Send message to CAN device to get pushed to the BUS.
        Transport protocol will automatically be applied for data longer
        than 8 bytes.

        usage: send <can_id> <data> [-vv]

        Arguments:
            can_id      29-bit identifier
            data        hex string
        Optional:
            -v          Don't send, just print the message
            -vv         Don't send, just print the decoded form of the message

        examples:
        send 0x18EFF900 112233445566AABBCCDDEEFF
        send 0x18EF00F9 FFFF12FCFFFFFFFF
        send 0x0CEA000B ECFE00
        """
        argv = arg.split()
        if len(argv) < 2:
            print("arguments not found, see 'help send'")
            return
        can_id = argv[0]
        if can_id.startswith("0x"):
            can_id = int(can_id, 16)
        else:
            can_id = int(can_id)
        data = argv[1]

        message = J1939Message(can_id, data)
        if len(argv) == 3:
            if argv[2] == '-v' or argv[2] == '-V':
                print(str(message))
            elif argv[2] == '-vv' or argv[2] == '-VV':
                print(self.sender.devil.get_decoded_message(message))
            else:
                print("third argument invalid, see 'help send'")
            return
        self.sender.devil.send_message(message)
        print("message sent.")


def main_mod(argv, device=None):
    scli = SendCommands(argv, device)
    scli.cmdloop()
