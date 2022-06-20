from j1939.j1939 import J1939Interface, J1939Message
from libs.command import Command


class SendCommands(Command):
    intro = "Welcome to the Send Messages tool."
    prompt = "(truckdevil.send_messages) "

    def __init__(self, device):
        super().__init__()
        self.devil = J1939Interface(device)

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
            verbose = argv[2][1:].lower()
            if verbose == 'v':
                print(str(message))
            elif verbose == 'vv':
                print(self.devil.get_decoded_message(message))
            else:
                print("third argument invalid, see 'help send'")
            return
        self.devil.send_message(message)
        print("message sent.")

    @staticmethod
    def do_back(self, arg=None):
        """
        Return to the main menu
        """
        return True

def main_mod(argv, device):
    scli = SendCommands(device)
    if len(argv) > 0:
        scli.run_commands(argv)
    else:
        scli.cmdloop()
