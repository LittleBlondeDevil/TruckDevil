import cmd
import importlib
import importlib.metadata
import importlib.util
import ipaddress
import os
import sys
from pkgutil import iter_modules

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def _load_version():
    spec = importlib.util.spec_from_file_location(
        "truckdevil_init", os.path.join(os.path.dirname(__file__), "__init__.py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.__version__


__version__ = _load_version()


def _get_user_module_paths(cli_paths=None):
    if cli_paths:
        return cli_paths
    configured_path = os.environ.get("TRUCKDEVIL_MODULE_PATH")
    if configured_path:
        return [p for p in configured_path.split(os.pathsep) if p]
    return [os.path.expanduser("~/.config/truckdevil/modules")]


def _discover_builtin_modules():
    module_path = os.path.join(os.path.dirname(__file__), "modules")
    modules = {}
    for _, name, _ in iter_modules([module_path]):
        modules[name] = {
            "source": "builtin",
            "loader": lambda module_name=name: importlib.import_module(
                "truckdevil.modules.{}".format(module_name)
            ),
        }
    return modules


def _discover_user_modules(cli_paths=None):
    modules = {}
    for module_path in _get_user_module_paths(cli_paths):
        if not os.path.isdir(module_path):
            continue
        for _, name, _ in iter_modules([module_path]):
            file_path = os.path.join(module_path, "{}.py".format(name))
            modules[name] = {
                "source": "user",
                "loader": lambda module_name=name, module_file=file_path: (
                    _load_module_from_path(module_name, module_file)
                ),
            }
    return modules


def _iter_module_entry_points():
    entry_points = importlib.metadata.entry_points()
    if hasattr(entry_points, "select"):
        return entry_points.select(group="truckdevil.modules")
    return entry_points.get("truckdevil.modules", [])


def _discover_entry_point_modules():
    modules = {}
    for entry_point in _iter_module_entry_points():
        modules[entry_point.name] = {
            "source": "entry_point",
            "loader": lambda ep=entry_point: ep.load(),
        }
    return modules


def _discover_modules(cli_paths=None):
    modules = _discover_builtin_modules()
    for external_modules in (
        _discover_user_modules(cli_paths),
        _discover_entry_point_modules(),
    ):
        for name, metadata in external_modules.items():
            if name not in modules:
                modules[name] = metadata
    return modules


def _load_module_from_path(module_name, module_file):
    spec = importlib.util.spec_from_file_location(
        "truckdevil_user_module_{}".format(module_name), module_file
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_module_entry(module, argv, device):
    if hasattr(module, "main_mod"):
        module.main_mod(argv, device)
        return
    if callable(module):
        module(argv, device)
        return
    raise AttributeError(
        "module is missing main_mod: plugins must be either an entry-point "
        "callable accepting (argv, device), or an object/module exposing a "
        "main_mod(argv, device) function"
    )


def _parse_cli_args(argv):
    module_paths = []
    filtered_argv = []
    i = 0
    while i < len(argv):
        if argv[i] == "--module-path":
            if i + 1 >= len(argv):
                print("Error: expected path after --module-path")
                return None, None
            module_paths.append(argv[i + 1])
            i += 2
            continue
        filtered_argv.append(argv[i])
        i += 1
    return filtered_argv, module_paths


def _configure_readline():
    try:
        import readline

        # libedit (macOS / some BSDs) uses a different binding syntax;
        # GNU readline's "tab: complete" is silently ignored by libedit.
        # Setting the correct binding here ensures tab-completion works
        # regardless of the backend (cmd.Cmd.cmdloop only uses GNU syntax).
        if getattr(readline, "__doc__", None) and "libedit" in readline.__doc__:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
    except ImportError:
        print("Warning: readline not found. Tab-completion will not work.")
        if sys.platform == "win32":
            print("  Install it with:  pip install pyreadline3")
        else:
            print("  On Debian/Ubuntu:  sudo apt install libreadline-dev")
            print("  Then rebuild Python or:  pip install gnureadline")


def _run_cli_commands(fc, argv):
    if not argv:
        fc.cmdloop()
        return

    if argv[0] == "add_device" and "run_module" in argv:
        module_index = argv.index("run_module")
        device_args = argv[:module_index]
        module_args_start = module_index + 1
        module_args = argv[module_args_start:]
        fc.onecmd(" ".join(device_args))
        fc.onecmd(" ".join(module_args))
        return

    if argv[0] == "add_device" and "run_module" not in argv:
        fc.onecmd(" ".join(argv[:5]))
        fc.onecmd(" ".join(argv[5:]))
        fc.cmdloop()
        return

    fc.onecmd(" ".join(argv))


class FrameworkCommands(cmd.Cmd):
    intro = "Welcome to the truckdevil framework v{}. Type 'help or ?' for a list of commands.".format(
        __version__
    )
    prompt = "(truckdevil) "

    def __init__(self, module_paths=None):
        super().__init__()
        self._device = None
        self.modules = _discover_modules(module_paths)
        self.module_names = sorted(self.modules)

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
        if self.device is not None:
            print(str(self.device))
        else:
            print("No device configured.")

    def do_add_device(self, args):
        """
        Add a new hardware device. If one exists, replace it.

        usage: add_device <interface> <channel> <can_baud> [{serial,tcp}port]

        Arguments:
            interface       The CAN interface to use. e.g. m2 or one supported by python-can
                            https://python-can.readthedocs.io/en/master/interfaces.html.
                            To connect to a remote M2-over-TCP server (e.g. truckdevil-tcp),
                            specify 'm2:<ip_address>'.
            channel         CAN channel to send/receive on. e.g. can0, can1, vcan0.
            can_baud        Baudrate on the CAN bus. Most common are 250000 and 500000.
                            Use 0 for autobaud detection on supported hardware.
            port            Port that the M2 is connected to, if used. For example: COM7 or /dev/ttyX.
                            If using M2 encoder over TCP ('m2:<ip>'), this is the remote TCP port.

        examples:
            Local M2 over serial:
                add_device m2 can0 250000 COM5
                add_device m2 can0 250000 /dev/ttyACM0

            Remote M2 over TCP bridge (client session):
                add_device m2:192.168.7.2 can0 500000 1234

            Local SocketCAN / Virtual / Other python-can interfaces:
                add_device socketcan can0 500000
                add_device socketcan vcan0 500000
                add_device pcan PCAN_USBBUS1 500000
                add_device virtual test_ch 250000
        """
        argv = args.split()
        if len(argv) < 3:
            print("Error: expected device details")
            self.do_help("add_device")
            return
        interface = argv[0]
        tcp_ip = None
        if ":" in interface:
            itf = interface.split(":")
            interface = itf[0]
            try:
                ipaddress.ip_address(itf[1])
                tcp_ip = itf[1]
            except ValueError:
                print("Error: invalid IP address")
                self.do_help("add_device")
                return
        channel = argv[1]
        can_baud = argv[2]
        port = None
        if len(argv) >= 4:
            port = argv[3]
        from truckdevil.libs.device import Device

        self.device = Device(interface, port, channel, can_baud, tcp_ip=tcp_ip)

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
        if module_name not in self.modules:
            print("Error: module not found")
            self.do_help("run_module")
            return

        mod = self.modules[module_name]["loader"]()
        _run_module_entry(mod, argv[1:], self.device)

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

        interfaces = ["m2"]
        if hasattr(can, "VALID_INTERFACES"):
            interfaces.extend(can.VALID_INTERFACES)
        elif hasattr(can.interface, "VALID_INTERFACES"):
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
                completions = [f for f in self.module_names if f.startswith(text)]
            return completions
        return []

    def complete_use(self, text, line, begidx, endidx):
        return self.complete_run_module(text, line, begidx, endidx)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    argv, module_paths = _parse_cli_args(argv)
    if argv is None:
        return 1

    if "--version" in argv or "-V" in argv:
        print("truckdevil {}".format(__version__))
        return 0

    _configure_readline()
    fc = FrameworkCommands(module_paths=module_paths or None)
    _run_cli_commands(fc, argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
