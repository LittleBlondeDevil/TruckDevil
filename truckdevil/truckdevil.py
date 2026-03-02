import cmd
import importlib
import os
import sys
from pkgutil import iter_modules

from libs.device import Device
from __init__ import __version__


class FrameworkCommands(cmd.Cmd):
    intro = "Welcome to the truckdevil framework v{}. Type 'help or ?' for a list of commands.".format(__version__)
    prompt = '(truckdevil) '

    def __init__(self):
        super().__init__()
        self._device = None
        module_path = os.path.join(os.path.dirname(__file__), 'modules')
        self.module_names = [name for _, name, _ in iter_modules([module_path])]

    @property
    def device(self):
        return self._device

    @device.setter
    def device(self, new_device):
        self._device = new_device

    @property
    def device_added(self):
        if self._device is not None:
            return True
        return False

    def do_list_device(self, args):
        """
        List the current CAN device
        """
        print(str(self.device))

    def do_add_device(self, args):
        """
        Add a new hardware device. If one exists, replace it.

        usage: add_device <interface> <channel> <can_baud> [serial_port]

        Arguments:
            interface       The CAN interface to use. e.g. m2 or one supported by python-can
                            https://python-can.readthedocs.io/en/master/interfaces.html
            channel         CAN channel to send/receive on. e.g. can0, can1, vcan0
            can_baud        Baudrate on the CAN bus. Most common are 250000 and 500000. Use 0 for autobaud detection.
            serial_port     Serial port that the M2 is connected to, if used. For example: COM7 or /dev/ttyX.

        examples:
        add_device m2 can0 250000 COM5
        add_device socketcan vcan0 500000
        add_device pcan PCAN_USBBUS1 500000
        """
        argv = args.split()
        if len(argv) < 3:
            print("Error: expected device details")
            self.do_help("add_device")
            return
        interface = argv[0]
        channel = argv[1]
        can_baud = argv[2]
        serial_port = None
        if len(argv) >= 4:
            serial_port = argv[3]
        self.device = Device(interface, serial_port, channel, can_baud)

    def do_list_modules(self, args):
        """
        List all available modules
        """
        for name in self.module_names:
            print(name)

    def do_ls(self, args):
        """
        alias 'ls' to 'list_modules'
        """
        self.do_list_modules(args) 

    def do_run_module(self, args):
        """
        Run a module from the 'modules' directory that contains
        a 'main_mod()' function

        usage: run_module <MODULE_NAME> [MODULE_ARGS]

        example:
        run_module read_messages
        """
        argv = args.split()
        if len(argv) == 0:
            print("Error: expected module name")
            self.do_help("run_module")
            return
        module_name = argv[0]
        if module_name in self.module_names:
            mod = importlib.import_module("modules.{}".format(module_name))
            mod.main_mod(argv[1:], self.device)
        else:
            print("Error: module not found")
            self.do_help("run_module")


    def do_use(self, args):
        """
        alias 'use' to 'run_module'
        """
        self.do_run_module(args) 

    def do_quit(self, args):
        """
        Quit TruckDevil immediately, regardless of the current module state.
        Unlike 'back', which returns to the parent menu, 'quit' will exit
        the entire TruckDevil REPL immediately.
        """
        sys.exit("Exiting TruckDevil")
            
    def complete_add_device(self, text, line, begidx, endidx):
        import can
        interfaces = ['m2']
        if hasattr(can, 'VALID_INTERFACES'):
            interfaces.extend(can.VALID_INTERFACES)
        elif hasattr(can.interface, 'VALID_INTERFACES'):
            interfaces.extend(can.interface.VALID_INTERFACES)

        interfaces = sorted(list(set(interfaces)))

        parts = line[:begidx].split()
        if len(parts) == 1:
            if not text:
                return interfaces
            return [i for i in interfaces if i.startswith(text)]
        return []

    def complete_run_module(self, text, line, begidx, endidx):
        parts = line[:begidx].split()
        if len(parts) == 1:
            if not text:
                completions = self.module_names[:]
            else:
                completions = [ f
                                for f in self.module_names
                                if f.startswith(text)
                                ]
            return completions
        return []

    def complete_use(self, text, line, begidx, endidx):
        return self.complete_run_module(text, line, begidx, endidx)

if __name__ == "__main__":
    if "--version" in sys.argv or "-V" in sys.argv:
        print("truckdevil {}".format(__version__))
        sys.exit(0)

    try:
        import readline
    except ImportError:
        if sys.platform == 'win32':
            print("Warning: readline not found. Tab-completion may not work.")
            print("Try: pip install pyreadline3")

    fc = FrameworkCommands()
    if len(sys.argv) > 1:
        if sys.argv[1] == "add_device" and "run_module" in sys.argv:
            module_index = sys.argv[1:].index("run_module")
            device_args = sys.argv[1:][:module_index]
            module_args = sys.argv[module_index + 1:]
            fc.onecmd(' '.join(device_args))
            fc.onecmd(' '.join(module_args))
        elif sys.argv[1] == "add_device" and not "run_module" in sys.argv:
            fc.onecmd(' '.join(sys.argv[1:6]))
            fc.onecmd(' '.join(sys.argv[6:]))
            fc.cmdloop()
        else:
            fc.onecmd(' '.join(sys.argv[1:]))
    else:
        fc.cmdloop()
