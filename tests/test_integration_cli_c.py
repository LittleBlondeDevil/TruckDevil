import subprocess
import sys
import os
import pytest
import uuid

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TRUCKDEVIL_PY = os.path.join(_REPO_ROOT, "truckdevil", "truckdevil.py")

@pytest.fixture
def shared_channel():
    return f"integration-{uuid.uuid4().hex}"

def test_cli_c_multiple_commands_with_virtual_device(shared_channel):
    """
    Integration test for -c option:
    1. Add a virtual device
    2. List the device to verify it was added
    3. Run a module (read_messages) for a short duration if possible, 
       or just verify the help/listing of modules works via -c.
    """
    # We use a semicolon-separated list of commands
    commands = f"add_device virtual {shared_channel} 250000; list_device; ls"
    
    result = subprocess.run(
        [sys.executable, _TRUCKDEVIL_PY, "-c", commands],
        capture_output=True,
        text=True,
        timeout=15,
        cwd=_REPO_ROOT
    )
    
    assert result.returncode == 0
    # Verify list_device output
    assert "virtual" in result.stdout
    assert shared_channel in result.stdout
    # Verify ls (list_modules) output
    assert "read_messages" in result.stdout
    assert "send_messages" in result.stdout
    assert "ecu_discovery" in result.stdout

def test_cli_c_invalid_command():
    """Test that -c with an invalid command prints an error and exits."""
    result = subprocess.run(
        [sys.executable, _TRUCKDEVIL_PY, "-c", "non_existent_command"],
        capture_output=True,
        text=True,
        timeout=10,
        cwd=_REPO_ROOT
    )
    # The framework prints *** Unknown syntax
    assert "*** Unknown syntax: non_existent_command" in result.stdout
    assert result.returncode == 0 # It executes the command and then exits normally

def test_cli_c_version_command():
    """Test -c with a command that uses internal state like help."""
    result = subprocess.run(
        [sys.executable, _TRUCKDEVIL_PY, "-c", "help add_device"],
        capture_output=True,
        text=True,
        timeout=10,
        cwd=_REPO_ROOT
    )
    assert result.returncode == 0
    assert "usage: add_device" in result.stdout
    assert "interface" in result.stdout
