from unittest.mock import MagicMock, patch

from truckdevil.truckdevil import FrameworkCommands

class MockFrameworkCommands(FrameworkCommands):
    def __init__(self):
        with patch('truckdevil.libs.command.PromptSession'), patch('truckdevil.libs.command.FileHistory'):
            super().__init__()

def test_framework_get_commands():
    fc = MockFrameworkCommands()
    commands = fc.get_commands()
    assert 'add_device' in commands
    assert 'run_module' in commands
    assert 'list_modules' in commands

def test_framework_get_completion_dict():
    fc = MockFrameworkCommands()
    # Mock module names
    fc.module_names = ['read_messages', 'send_messages']

    with patch('can.interface.VALID_INTERFACES', ['socketcan', 'pcan'], create=True):
        completions = fc.get_completion_dict()

    # Check module completion
    assert 'run_module' in completions
    assert 'read_messages' in completions['run_module']
    assert 'send_messages' in completions['run_module']

    # Check device completion
    assert 'add_device' in completions
    assert 'socketcan' in completions['add_device']
    assert 'm2' in completions['add_device']

def test_do_ls():
    fc = MockFrameworkCommands()
    fc.do_list_modules = MagicMock()
    fc.do_ls("some args")
    fc.do_list_modules.assert_called_once_with("some args")

def test_do_use():
    fc = MockFrameworkCommands()
    fc.do_run_module = MagicMock()
    fc.do_use("read_messages")
    fc.do_run_module.assert_called_once_with("read_messages")
