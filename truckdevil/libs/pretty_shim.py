import shlex
import re

try:
    import bitstring
    import pretty_j1939.describe
    import pretty_j1939.render
    import pretty_j1939.__main__

    PRETTY_AVAILABLE = True
except ImportError:
    PRETTY_AVAILABLE = False

# Constants for pretty_j1939 integration
# Changed --no-format to --format to leverage library-side formatting
DEFAULT_PRETTY_ARGS = "--format --theme synthwave --bytes"
MAGIC_TRUCKDEVIL = "<truckdevil>"
MAGIC_DEFAULT = ""


def strip_ansi(text):
    """
    Strips ANSI escape sequences from a string.
    """
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def extract_original_segment(original, clean, clean_start, clean_end):
    """
    Given an original string with ANSI codes and its cleaned version,
    extract the segment from the original string that corresponds to
    the range [clean_start, clean_end) in the cleaned version.
    """
    orig_idx = 0
    clean_idx = 0

    seg_start = -1
    seg_end = -1

    while orig_idx < len(original):
        if clean_idx == clean_start and seg_start == -1:
            seg_start = orig_idx

        if clean_idx == clean_end and seg_end == -1:
            seg_end = orig_idx
            break

        # Check for ANSI escape sequence
        if original[orig_idx : orig_idx + 2] == "\x1b[":
            end_ansi = original.find("m", orig_idx)
            if end_ansi != -1:
                orig_idx = end_ansi + 1
                continue

        # Regular character
        orig_idx += 1
        clean_idx += 1

    if seg_end == -1:
        seg_end = len(original)

    if seg_start == -1:
        return ""

    return original[seg_start:seg_end]


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
            real_time=False,
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

    def _prepare_pretty_db(self):  # noqa: C901
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

    @staticmethod
    def print_ansi(text):
        """
        Prints text containing ANSI escape sequences using prompt_toolkit
        if available, falling back to standard print.
        """
        try:
            from prompt_toolkit.shortcuts import print_formatted_text
            from prompt_toolkit.formatted_text import ANSI

            print_formatted_text(ANSI(text))
        except ImportError:
            print(text)

    def print_summary(self):
        if not self.describer or not self.renderer:
            return

        try:
            summary_data = self.describer.get_summary()
            if not summary_data:
                return

            # If it's a JSON string, parse it
            if isinstance(summary_data, str) and summary_data.startswith("{"):
                try:
                    import importlib

                    json_mod = importlib.import_module("json")
                    summary_data = json_mod.loads(summary_data)
                except Exception:
                    pass

            # If the summary contains a Mermaid graph, it might already be formatted if self.indent is True
            if isinstance(summary_data, dict) and "Summary" in summary_data:
                self.print_ansi(summary_data["Summary"])
            else:
                rendered = self.renderer.render_summary(summary_data, indent=self.indent)

                # Extract Mermaid graph from colored JSON-like string if necessary
                stripped_rendered = rendered.strip()
                clean_stripped = strip_ansi(stripped_rendered)
                match = re.search(
                    r"['\"]Summary['\"]\s*:\s*['\"](graph LR;.*)['\"]\s*}$",
                    clean_stripped,
                )
                if match:
                    start_clean = match.start(1)
                    end_clean = match.end(1)
                    mermaid_colored = extract_original_segment(
                        stripped_rendered, clean_stripped, start_clean, end_clean
                    )
                    self.print_ansi(mermaid_colored)
                    return

                self.print_ansi(rendered)
        except Exception as e:
            print(f"Error printing summary: {e}")
