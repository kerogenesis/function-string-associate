import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_auto
import ida_kernwin
import time
import re
from PyQt5 import QtWidgets

MAX_LINE_STRING_COUNT = 10
MAX_LABEL_STRING = 60
MAX_COMMENT_SIZE = 764
MIN_STRING_SIZE = 4

PLUGIN_NAME = "Function String Associate Extra"
PLUGIN_HOTKEY = ""

g_replace_comments = False

def filter_whitespace(input_string: str) -> str:
    """
    Replaces all non-printable ASCII characters with a space and trims result.
    """
    return "".join(ch if " " <= ch <= "~" else " " for ch in input_string).strip()

def extract_function_strings(function_start_ea: int) -> list:
    """
    Extract strings that are referenced from the instructions inside the function.
    Returns a list of [string_value, reference_count].
    """
    function = ida_funcs.get_func(function_start_ea)
    if not function or function.size() < 8:
        return []

    found_strings = []
    for item_ea in idautils.FuncItems(function_start_ea):
        for xref in idautils.XrefsFrom(item_ea, idaapi.XREF_DATA):
            max_length = ida_bytes.get_max_strlit_length(xref.to, 0)
            if max_length > MIN_STRING_SIZE:
                raw_string_bytes = ida_bytes.get_strlit_contents(xref.to, max_length, 0)
                if raw_string_bytes:
                    try:
                        string_value = raw_string_bytes.decode("ascii", errors="replace")
                    except Exception:
                        string_value = str(raw_string_bytes)
                    string_value = filter_whitespace(string_value)
                    if len(string_value) >= MIN_STRING_SIZE:
                        found = False
                        for string_entry in found_strings:
                            if string_entry[0] == string_value:
                                string_entry[1] += 1
                                found = True
                                break
                        if not found:
                            if len(found_strings) < MAX_LINE_STRING_COUNT:
                                found_strings.append([string_value, 1])
                            if len(found_strings) >= MAX_LINE_STRING_COUNT:
                                break
        if len(found_strings) >= MAX_LINE_STRING_COUNT:
            break
    return found_strings

def generate_str_comment(function_strings: list) -> str:
    """
    Formats a #STR: comment given list of [string, ref_count].
    """
    if not function_strings:
        return ""
    function_strings.sort(key=lambda x: x[1])
    comment_text = "#STR: "
    for index, (string_value, ref_count) in enumerate(function_strings):
        available_size = MAX_COMMENT_SIZE - len(comment_text) - 1
        required_size = len(string_value) + 2  # for quotes
        if available_size < required_size:
            break
        comment_text += f"\"{string_value}\""
        if index + 1 < len(function_strings):
            available_size = MAX_COMMENT_SIZE - len(comment_text) - 1
            if available_size > 2:
                comment_text += ", "
            else:
                break
    return comment_text

def update_function_comment(function_ea: int, comment_text: str) -> None:
    """
    Updates the repeatable comment of the function. Mode append/replace is global.
    """
    if not comment_text:
        return
    if not g_replace_comments:
        current_comment = idc.get_func_cmt(function_ea, repeatable=True) \
            or idc.get_func_cmt(function_ea, repeatable=False) or ""
        if current_comment:
            combined_comment = current_comment + "\n" + comment_text
        else:
            combined_comment = comment_text
        idc.set_func_cmt(function_ea, combined_comment, repeatable=True)
    else:
        idc.set_func_cmt(function_ea, comment_text, repeatable=True)

def process_function_add_comments(function_ea: int) -> bool:
    """
    Extracts strings and updates function's repeatable comment.
    Returns True if a comment was actually added.
    """
    function_strings = extract_function_strings(function_ea)
    if function_strings:
        comment_text = generate_str_comment(function_strings)
        update_function_comment(function_ea, comment_text)
        return True
    return False

def is_valid_ida_func_name(function_name: str) -> bool:
    """
    Checks if the function name matches a valid C++ style name.
    """
    if len(function_name) > 128:
        return False
    return bool(re.match(r'^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)+$', function_name))

def extract_candidate_function_names(comment_text: str) -> list:
    """
    Finds all possible function names of form Class::Method in the #STR-comment block.
    Returns a list of valid function names.
    """
    if not comment_text:
        return []
    candidate_names = []
    str_comment_match = re.search(r'#STR:(.+)', comment_text)
    if str_comment_match:
        str_content = str_comment_match.group(1)
        quoted_strings = re.findall(r'"(.*?)"', str_content)
        for quoted_string in quoted_strings:
            if re.match(r'^[A-Za-z_]\w*::[A-Za-z_]\w*$', quoted_string):
                if is_valid_ida_func_name(quoted_string):
                    candidate_names.append(quoted_string)
    return candidate_names

def is_autogen_func_name(function_name: str) -> bool:
    """
    Checks if the function name is autogenerated (sub_xxx or nullsub_xxx).
    """
    return re.fullmatch(r'(sub_|nullsub_)[0-9A-Fa-f]{6,}', function_name or "") is not None

def process_function_rename(function_ea: int) -> str:
    """
    Checks the #STR comment for a valid candidate, then renames function if needed.
    Returns one of: 'ok', 'warn', 'skip', 'err', 'none'.
    """
    comment_text = idc.get_func_cmt(function_ea, 1)
    if not comment_text:
        return 'none'
    candidate_names = extract_candidate_function_names(comment_text)
    if not candidate_names:
        return 'none'
    if len(candidate_names) > 1:
        print(f"[WARN] {hex(function_ea)}: Multiple function names found {candidate_names}. Skipping rename.")
        return 'warn'
    current_name = idc.get_func_name(function_ea)
    if not is_autogen_func_name(current_name):
        print(f"[SKIP] {hex(function_ea)}: Function already has a custom name: {current_name}")
        return 'skip'
    new_name = candidate_names[0]
    if not new_name or new_name == current_name:
        return 'none'
    if idc.get_name_ea_simple(new_name) != idc.BADADDR:
        print(f"[WARN] {hex(function_ea)}: Name '{new_name}' already taken. Skipping.")
        return 'warn'
    if idc.set_name(function_ea, new_name, idc.SN_NOWARN):
        print(f"[OK]   {hex(function_ea)}: {current_name} -> {new_name}")
        return 'ok'
    else:
        print(f"[ERR]  {hex(function_ea)}: Failed to rename {current_name} -> {new_name}")
        return 'err'

class ReplaceOrAppendDialog(QtWidgets.QDialog):
    """
    Modal dialog for user to select comment mode (replace or append).
    """
    def __init__(self, function_count, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Function String Associate")
        self.setModal(True)
        layout = QtWidgets.QVBoxLayout()
        label = QtWidgets.QLabel(
            f"This will process all {function_count} functions.\n\n"
            "If you choose REPLACE, existing function comments will be overwritten.\n"
            "If unchecked, the plugin will APPEND to existing comments.\n"
        )
        layout.addWidget(label)
        self.checkbox = QtWidgets.QCheckBox("Replace existing comments?")
        layout.addWidget(self.checkbox)
        button_box = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        self.setLayout(layout)
    def should_replace(self):
        return self.checkbox.isChecked()

def show_qt_dialog(function_count):
    """
    Shows modal dialog, returns True for REPLACE, False for APPEND, None if cancelled.
    """
    dialog = ReplaceOrAppendDialog(function_count)
    result = dialog.exec_()
    if result == QtWidgets.QDialog.Accepted:
        return dialog.should_replace()
    else:
        return None

class FunctionStringAssociatePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Extracts strings from functions as comments then renames via #STR"
    help = comment
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self):
        print(f"[{PLUGIN_NAME}] Plugin loaded.")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        if not ida_auto.auto_is_ok():
            ida_kernwin.warning("Please wait until auto-analysis completes!")
            print("[WARN] Analysis not complete!")
            return
        all_functions = list(idautils.Functions())
        user_choice = show_qt_dialog(len(all_functions))
        if user_choice is None:
            print("[INFO] Cancelled by user.")
            return
        global g_replace_comments
        g_replace_comments = user_choice
        comment_mode = "REPLACE" if g_replace_comments else "APPEND"
        print(f"[{PLUGIN_NAME}] Starting in {comment_mode} mode.")
        start_time = time.time()
        ida_kernwin.show_wait_box("Function String Associate: adding comments...")
        comment_count = 0
        for idx, func_ea in enumerate(all_functions):
            if process_function_add_comments(func_ea):
                comment_count += 1
            if idx % 100 == 0:
                ida_kernwin.replace_wait_box(f"Processing comments: {idx+1}/{len(all_functions)}")
                if ida_kernwin.user_cancelled():
                    print("[INFO] Cancelled by user.")
                    ida_kernwin.hide_wait_box()
                    return
        # Now attempt renaming
        rename_stats = dict(ok=0, warn=0, skip=0, err=0)
        ida_kernwin.replace_wait_box("Renaming functions...")
        for idx, func_ea in enumerate(all_functions):
            status = process_function_rename(func_ea)
            if status in rename_stats:
                rename_stats[status] += 1
            if idx % 100 == 0:
                ida_kernwin.replace_wait_box(f"Renaming: {idx+1}/{len(all_functions)}")
                if ida_kernwin.user_cancelled():
                    print("[INFO] Cancelled by user.")
                    break
        ida_kernwin.hide_wait_box()
        elapsed = time.time() - start_time
        print(f"\n[{PLUGIN_NAME}]")
        print(f"--- Summary ---")
        print(f"Functions with new comments: {comment_count}")
        print(f"Renamed:                    {rename_stats['ok']}")
        print(f"Skipped (custom name):      {rename_stats['skip']}")
        print(f"Warnings:                   {rename_stats['warn']}")
        print(f"Errors:                     {rename_stats['err']}")
        print(f"Total time:                 {elapsed:.2f} sec")
        print("------------------------\n")
        idaapi.refresh_idaview_anyway()

    def term(self):
        print(f"[{PLUGIN_NAME}] Plugin exited.")

def PLUGIN_ENTRY():
    return FunctionStringAssociatePlugin()
