from unittest.mock import patch, MagicMock
from truckdevil.libs.device import Device
import truckdevil.modules.ecu_discovery as ecu_discovery


def test_ecu_discovery_scan_interval_setting(virtual_channel):
    """Verify that scan_interval setting exists and affects passive_scan and signal_summary."""
    device = Device("virtual", None, virtual_channel, 250000)
    try:
        cmd = ecu_discovery.DiscoveryCommands(device)

        # 1. Verify setting exists and has default value
        # SettingsManager uses __getattr__ to return the value of a setting
        assert cmd.sm.scan_interval == 10

        # 2. Verify passive_scan uses the setting
        with patch("truckdevil.modules.ecu_discovery.time.sleep") as mock_sleep:
            cmd.do_passive_scan("")
            mock_sleep.assert_called_with(10)

            # Change setting and verify it's used
            cmd.sm.set("scan_interval", 5)
            assert cmd.sm.scan_interval == 5
            cmd.do_passive_scan("")
            mock_sleep.assert_called_with(5)

        # 3. Verify signal_summary uses the setting
        # Mock PRETTY_AVAILABLE to be True so we can test the logic.
        with patch("truckdevil.libs.pretty_shim.PRETTY_AVAILABLE", True):
            with patch("truckdevil.modules.ecu_discovery.time.sleep") as mock_sleep:
                cmd.sm.set("scan_interval", 3)
                # We need to mock start_data_collection and stop_data_collection
                cmd.devil.start_data_collection = MagicMock()
                cmd.devil.stop_data_collection = MagicMock(return_value=[])

                cmd.do_signal_summary("")
                mock_sleep.assert_called_with(3)

    finally:
        if device.can_bus is not None:
            device.can_bus.shutdown()
