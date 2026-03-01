# TruckDevil tests

Test suite for TruckDevil using **pytest** and python-can’s **virtual** CAN interface. No hardware is required.

## Run tests

From the repo root:

```bash
pip install -r requirements.txt pytest
python -m pytest tests/ -v
```

## Layout

| File | Coverage |
|------|----------|
| `conftest.py` | Fixtures: virtual device, J1939 CWD, module env |
| `test_device_virtual.py` | Device (virtual only): create, send/recv, timeout, M2 validation |
| `test_j1939_units.py` | J1939 helpers, `J1939Message` properties & setters, PGN, `__str__` |
| `test_j1939_integration.py` | `J1939Interface`: send/recv, filters, data collection, multipacket TP (BAM/RTS), ISO-TP, UDS decode, save/import, read_messages_until, print_messages (filters, verbose, candump, log, read_time) |
| `test_ecu.py` | `ECU` class: creation, address_claimed, prop_messages |
| `test_fuzzer_target.py` | `J1939Fuzzer.Target`, target management (add/remove/modify), mutate, generate |
| `test_module_read_messages.py` | read_messages: set/print_messages, settings, save/load |
| `test_module_send_messages.py` | send_messages: send, verbose, invalid args |
| `test_module_ecu_discovery.py` | ecu_discovery: view_ecus, passive/active_scan, find_proprietary, find_uds, request_pgn, `ECUDiscovery` class, `input_to_int`, save/load, missing args |
| `test_module_j1939_fuzzer.py` | j1939_fuzzer: baseline, generate, start_fuzzer, settings, target CLI, save/load |
| `test_framework_cli.py` | CLI: add_device, list_device, run_module, list_modules, ls/use aliases, quit, tab completion, error handling |
| `test_settings.py` | `Setting` and `SettingsManager`: constructor, value/setter, constraints, description, `__str__`, `__getitem__`, unset |

Integration tests that use `J1939Interface` or the modules run with CWD set to the `truckdevil` package directory so `resources/json_files/` is found.
