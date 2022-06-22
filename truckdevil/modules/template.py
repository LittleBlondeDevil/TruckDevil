from j1939.j1939 import J1939Interface, J1939Message
from libs.command import Command


class TemplateCommands(Command):
    intro = "Welcome to the template module."
    # Change the prompt to your module name for example "(truckdevil.super_cool_custom_module) "
    prompt = "(truckdevil.template) "

    def __init__(self, device):
        super().__init__()
        self.devil = J1939Interface(device)

    def do_custom_send(self, arg):
        """
        [Description]
        Describe your command here. Truckdevil will parse these comments into the help for the command.

        [Usage] 
        Describe the usage and arguments for your custom command. Here is an example for a command called 'send'

        [EXAMPLE]
        ====================
        Send message to CAN device to get pushed to the BUS.
        Transport protocol will automatically be applied for data longer
        than 8 bytes.

        usage: custom_send <can_id> <data> [-vv]
        Arguments:
            can_id      29-bit identifier
            data        hex string
        Optional:
            -v          Don't send, just print the message
            -vv         Don't send, just print the decoded form of the message
        examples:
        custom_send 0x18EFF900 112233445566AABBCCDDEEFF
        custom_send 0x18EF00F9 FFFF12FCFFFFFFFF
        custom_send 0x0CEA000B ECFE00
        ====================
        """
        
        # Parse your input arguments, this example command takes two arguments
        argv = arg.split()
        if len(argv) < 2:
            print("This example takes 2 arguments")
            self.do_help("custom_send")
            return


        # Parse out the can_id from the first argument
        can_id = argv[0]

        # Support for base 16 (hex) or base 10
        if can_id.startswith("0x"):
            can_id = int(can_id, 16)
        else:
            can_id = int(can_id)

        # Put second argument into a data buffer
        data = argv[1]

        # Create a message out of our variables
        message = J1939Message(can_id, data)


        # Support extra argument flags for 'verbose' mode
        # It is best to do work inside a try-catch block.
        try:
            if len(argv) == 3:
                verbose = argv[2][1:].lower()
                if verbose == 'v':
                    print(str(message))
                elif verbose == 'vv':
                    print(self.devil.get_decoded_message(message))
                else:
                    print("third argument invalid, let me RTFM that for you!")
                    self.do_help("custom_send")
                    return
        except:
            print("something went wrong before sending message, let me RTFM that for you!")
            self.do_help("custom_send")
            return

        try:
            self.devil.send_message(message)
        except:
            print("something went wrong, let me RTFM that for you!")
            self.do_help("custom_send")
            return

        print("message sent.")

    # You can create new commands by simply defining them
    def do_minimal_template(self, arg):
        """
        Document your command here
        """
        try:
            # Do some things
            print("Do Something Useful")
        except:
            # Handle Errors
            print("Something Useful")
            return
        
    # This static method allows going back to other modules
    @staticmethod
    def do_back(self, arg=None):
        """
        Return to the main menu
        """
        return True

def main_mod(argv, device):
    # You will need to change this to "MyNewCommandCommands(device)"
    scli = TemplateCommands(device)
    if len(argv) > 0:
        scli.run_commands(argv)
    else:
        scli.cmdloop()
