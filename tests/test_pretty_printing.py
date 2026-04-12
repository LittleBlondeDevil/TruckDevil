import unittest
import os
import sys
from unittest.mock import patch, MagicMock

# Ensure the truckdevil directory is in sys.path
_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_DIR = os.path.dirname(_TESTS_DIR)
sys.path.append(_REPO_DIR)
sys.path.append(os.path.join(_REPO_DIR, 'truckdevil'))

from truckdevil.j1939.j1939 import J1939Interface, J1939Message

class PrettyPrintingTest(unittest.TestCase):
    """Tests for pretty printing functionality."""

    def test_print_ansi_uses_prompt_toolkit(self):
        """PrettyShim.print_ansi should use print_formatted_text and ANSI wrapper."""
        from truckdevil.libs.pretty_shim import PrettyShim
        text = "\x1b[31mRed Text\x1b[0m"
        
        with patch('prompt_toolkit.shortcuts.print_formatted_text') as mock_print:
            with patch('prompt_toolkit.formatted_text.ANSI') as mock_ansi:
                PrettyShim.print_ansi(text)
                mock_ansi.assert_called_once_with(text)
                mock_print.assert_called_once()

    def test_print_messages_pretty_uses_print_ansi(self):
        """print_messages with pretty=True should call PrettyShim.print_ansi."""
        class MockDevice:
            def __init__(self): self.m2_used = False
            def read(self, timeout=None): return None
            def send(self, msg): pass
            def flush_m2(self): pass

        iface = J1939Interface(MockDevice())
        msg = J1939Message(0x18EA00FF, "0011223344556677")
        iface.read_one_message = MagicMock(side_effect=[msg, None])
        
        # Mock get_pretty_output to return a colored string
        colored_output = '\x1b[38;2;255;126;219m"PGN"\x1b[0m'
        iface.pretty_shim.get_pretty_output = MagicMock(return_value=colored_output)
        iface.pretty_shim.print_summary = MagicMock()
        
        with patch.object(iface.pretty_shim, 'print_ansi') as mock_print_ansi:
            # We use num_messages=1 to avoid indefinite loop
            # and because read_one_message returns None after the first call
            iface.print_messages(num_messages=1, pretty=True)
            mock_print_ansi.assert_any_call(colored_output)

    def test_print_summary_uses_print_ansi(self):
        """PrettyShim.print_summary should call print_ansi for the summary output."""
        from truckdevil.libs.pretty_shim import PrettyShim
        # Use MagicMock for the td_interface since we're just testing the shim in isolation
        shim = PrettyShim(MagicMock(), "", "")
        shim.describer = MagicMock()
        shim.renderer = MagicMock()
        
        # Scenario 1: Summary is a dict with "Summary" key (Mermaid)
        shim.describer.get_summary.return_value = {"Summary": "graph LR; A-->B"}
        with patch.object(shim, 'print_ansi') as mock_print_ansi:
            shim.print_summary()
            mock_print_ansi.assert_called_with("graph LR; A-->B")
            
        # Scenario 2: Summary is rendered by the renderer
        shim.describer.get_summary.return_value = {"Other": "Data"}
        shim.renderer.render_summary.return_value = "\x1b[32mRendered Summary\x1b[0m"
        with patch.object(shim, 'print_ansi') as mock_print_ansi:
            shim.print_summary()
            mock_print_ansi.assert_called_with("\x1b[32mRendered Summary\x1b[0m")

if __name__ == '__main__':
    unittest.main()
