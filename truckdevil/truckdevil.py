import cmd
import importlib
import sys
from pkgutil import iter_modules

from j1939.j1939 import J1939Interface
from libs.device import Device


class FrameworkCommands(cmd.Cmd):
    intro = "Welcome to the truckdevil framework"
    prompt = '(truckdevil)'

    def __init__(self):
        super().__init__()
        self._device = None
        self.module_names = [name for _, name, _ in iter_modules(['modules'])]

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
        """
        argv = args.split()
        if len(argv) == 0:
            print("expected device details, see 'help add_device'")
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

    def do_run_module(self, args):
        """
        Run a module from the 'modules' directory that contains
        a 'main_mod()' function

        usage: run_module <MODULE_NAME> [MODULE_ARGS]

        """
        argv = args.split()
        if len(argv) == 0:
            print("expected module name, see 'help run_module'")
            return
        module_name = argv[0]
        if module_name in self.module_names:
            mod = importlib.import_module("modules.{}".format(module_name))
            mod.main_mod(argv[1:], self.device)
        print("module not found, run 'list_modules'")


if __name__ == "__main__":
    fc = FrameworkCommands()
    # TODO: have first arg be a filename, if exists - load settings/state info and pass to module, if doesn't exist,
    #  create and pass to modules to save to. Keeps info like ECU information that's been collected, settings
    if len(sys.argv) > 1:
        if sys.argv[1] == "add_device" and "run_module" in sys.argv:
            module_index = sys.argv[1:].index("run_module")
            device_args = sys.argv[1:][:module_index]
            module_args = sys.argv[module_index + 1:]
            fc.onecmd(' '.join(device_args))
            fc.onecmd(' '.join(module_args))
        else:
            fc.onecmd(' '.join(sys.argv[1:]))
    else:
        fc.cmdloop()
