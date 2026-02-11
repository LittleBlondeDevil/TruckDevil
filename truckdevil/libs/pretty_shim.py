import os
import json
import shlex
import bitstring

try:
    import pretty_j1939.describe
    import pretty_j1939.render
    import pretty_j1939.__main__

    PRETTY_AVAILABLE = True
except ImportError:
    PRETTY_AVAILABLE = False

# Constants for pretty_j1939 integration
DEFAULT_PRETTY_ARGS = "--no-format --theme synthwave --summary --bytes"
MAGIC_TRUCKDEVIL = "<truckdevil>"
MAGIC_DEFAULT = ""


class PrettyShim:
    """
    Shim class to handle integration with the pretty_j1939 library.
    Encapsulates initialization, database conversion, and rendering.
    """

    def __init__(self, td_interface, arg_string, da_json_source):
        self.td = td_interface
        self.describer = None
        self.renderer = None
        self.indent = False
        if PRETTY_AVAILABLE:
            self.update_settings(arg_string, da_json_source)

    @staticmethod
    def is_available():
        return PRETTY_AVAILABLE

    def update_settings(self, arg_string, da_json_source):
        if not PRETTY_AVAILABLE:
            return

        parser = pretty_j1939.__main__.get_parser()
        # Parse arguments, ignoring unknown ones
        args, _ = parser.parse_known_args(shlex.split(arg_string))

        da_json = None
        if da_json_source == "<truckdevil>":
            da_json = self._prepare_pretty_db()
        elif da_json_source == "":
            da_json = None
        else:
            da_json = da_json_source

        self.describer = pretty_j1939.describe.get_describer(
            da_json=da_json,
            describe_pgns=args.pgn,
            describe_spns=args.spn,
            describe_link_layer=args.link,
            describe_transport_layer=args.transport,
            real_time=args.real_time,
            include_na=args.include_na,
            include_raw_data=args.include_raw_data,
            enable_isotp=args.enable_isotp,
        )

        self.renderer = pretty_j1939.render.HighPerformanceRenderer(
            theme_dict=args.theme,
            color_system=None if args.color == "never" else "truecolor",
            da_describer=self.describer.da_describer,
        )
        self.indent = args.format

    def _prepare_pretty_db(self):
        """
        Converts truckdevil in-memory data structures into a consolidated dict
        suitable for pretty_j1939.describe.get_describer(da_json=...).
        """
        new_db = {
            "J1939SATabledb": self.td.src_addr_list,
            "SATableMetadata": {},
            "J1939PGNdb": {},
            "J1939SPNdb": {},
            "J1939BitDecodings": self.td.bit_decoding_list,
        }

        # Convert SPNs
        for spn_id, obj in self.td.spn_list.items():
            if not spn_id:
                continue
            s_id = str(spn_id)

            res = 1.0
            if "resolutionNumerator" in obj and "resolutionDenominator" in obj:
                try:
                    res = float(obj["resolutionNumerator"]) / float(
                        obj["resolutionDenominator"]
                    )
                except (ZeroDivisionError, TypeError, ValueError):
                    res = 1.0

            new_db["J1939SPNdb"][s_id] = {
                "Name": obj.get("spnName", "Unknown"),
                "Resolution": res,
                "Offset": (
                    float(obj.get("offset", 0.0))
                    if obj.get("offset") not in ("", None)
                    else 0.0
                ),
                "Units": obj.get("units", ""),
                "SPNLength": (
                    int(obj.get("spnLength", 8))
                    if str(obj.get("spnLength")).isdigit()
                    else 8
                ),
                "OperationalLow": (
                    float(obj.get("OperationalLow", -1e12))
                    if obj.get("OperationalLow") not in ("", None)
                    else -1e12
                ),
                "OperationalHigh": (
                    float(obj.get("OperationalHigh", 1e12))
                    if obj.get("OperationalHigh") not in ("", None)
                    else 1e12
                ),
            }

        # Convert PGNs
        for pgn_id, obj in self.td.pgn_list.items():
            if not pgn_id:
                continue
            p_id = str(pgn_id)
            spn_ids = obj.get("spnList", [])
            start_bits = []

            for sid in spn_ids:
                spn_obj = self.td.spn_list.get(str(sid))
                if spn_obj:
                    try:
                        val = spn_obj.get("bitPositionStart", 0)
                        start_bits.append(int(val) if str(val).isdigit() else 0)
                    except (ValueError, TypeError):
                        start_bits.append(0)
                else:
                    start_bits.append(0)

            new_db["J1939PGNdb"][p_id] = {
                "Label": obj.get("parameterGroupLabel", ""),
                "Name": obj.get("acronym", ""),
                "SPNs": spn_ids,
                "SPNStartBits": start_bits,
            }

        return new_db

    def get_pretty_output(self, j1939_message, highlight=False):
        if not self.describer or not self.renderer:
            return "pretty_j1939 not initialized or available."

        try:
            bits_data = bitstring.Bits(hex=j1939_message.data)
            description = self.describer(bits_data, j1939_message.can_id)
            return self.renderer.render(
                description, indent=self.indent, highlight=highlight
            )
        except Exception as e:
            return f"Error pretty printing: {e}"

    def print_summary(self):
        if not self.describer or not self.renderer:
            return

        try:
            summary_data = self.describer.get_summary()
            if not summary_data:
                return
            print(self.renderer.render_summary(summary_data, indent=self.indent))
        except Exception as e:
            print(f"Error printing summary: {e}")
