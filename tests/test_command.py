from unittest.mock import MagicMock, patch

from truckdevil.libs.command import Command
from truckdevil.libs.settings import Setting, SettingsManager

class MockCommand(Command):
    """Subclass of Command for testing purposes."""
    def __init__(self, sm=None):
        # Avoid prompt_toolkit console initialization
        with patch('truckdevil.libs.command.PromptSession'), patch('truckdevil.libs.command.FileHistory'):
            super().__init__(sm)
        self.test_called = False
        self.test_args = None

    def do_test(self, arg):
        """Test command doc."""
        self.test_called = True
        self.test_args = arg
        return False

    def do_exit(self, arg):
        """Exit command."""
        return True

def test_get_commands():
    cmd = MockCommand()
    commands = cmd.get_commands()
    assert 'test' in commands
    assert 'exit' in commands
    assert 'help' in commands
    assert 'quit' in commands
def test_get_completion_dict():
    cmd = MockCommand()
    completions = cmd.get_completion_dict()
    assert 'test' in completions
    assert 'exit' in completions
    assert 'help' in completions

def test_get_completion_dict_with_settings():
    sm = SettingsManager()
    sm.add_setting(Setting("baudrate", 250000))
    class SettingsMockCommand(MockCommand):
        def do_set(self, arg): pass
        def do_unset(self, arg): pass

    cmd = SettingsMockCommand(sm=sm)
    completions = cmd.get_completion_dict()
    assert 'set' in completions
    assert 'baudrate' in completions['set']
    assert 'unset' in completions
    assert 'baudrate' in completions['unset']


def test_onecmd_dispatch():
    cmd = MockCommand()
    cmd.onecmd("test hello world")
    assert cmd.test_called is True
    assert cmd.test_args == "hello world"

def test_onecmd_unknown(capsys):
    cmd = MockCommand()
    cmd.onecmd("unknown_command")
    captured = capsys.readouterr()
    assert "*** Unknown syntax: unknown_command" in captured.out

def test_do_help(capsys):
    cmd = MockCommand()
    cmd.do_help("test")
    captured = capsys.readouterr()
    assert "Test command doc." in captured.out

def test_do_help_list(capsys):
    cmd = MockCommand()
    cmd.do_help("")
    captured = capsys.readouterr()
    assert "Documented commands" in captured.out
    assert "test" in captured.out
    assert "help" in captured.out

@patch('truckdevil.libs.command.patch_stdout')
def test_cmdloop_exit(mock_patch):
    cmd = MockCommand()
    # Mock the session's prompt method
    cmd.session.prompt = MagicMock(side_effect=['test my_arg', 'exit'])

    cmd.cmdloop()

    assert cmd.test_called is True
    assert cmd.test_args == 'my_arg'
    assert cmd.session.prompt.call_count == 2

@patch('truckdevil.libs.command.patch_stdout')
def test_cmdloop_eof(mock_patch):
    cmd = MockCommand()
    cmd.session.prompt = MagicMock(side_effect=EOFError())

    cmd.cmdloop()
    assert cmd.session.prompt.call_count == 1

@patch('truckdevil.libs.command.patch_stdout')
def test_cmdloop_keyboard_interrupt(mock_patch):
    cmd = MockCommand()
    # First call raises KeyboardInterrupt, second returns 'exit'
    cmd.session.prompt = MagicMock(side_effect=[KeyboardInterrupt(), 'exit'])

    cmd.cmdloop()
    assert cmd.session.prompt.call_count == 2


def test_complete_hook_adaptation():
    from prompt_toolkit.document import Document

    class HookCommand(MockCommand):
        def do_target(self, arg): pass
        def complete_target(self, text, line, begidx, endidx):
            verbs = ["add", "modify", "remove"]
            if not text:
                return verbs
            return [v for v in verbs if v.startswith(text)]

    cmd = HookCommand()
    completer = cmd.get_completer()

    # Complete after "target "
    doc = Document("target ")
    completions = [c.text for c in completer.get_completions(doc, None)]
    assert completions == ["add", "modify", "remove"]

    # Complete after "target a"
    doc2 = Document("target a")
    completions2 = [c.text for c in completer.get_completions(doc2, None)]
    assert completions2 == ["add"]
