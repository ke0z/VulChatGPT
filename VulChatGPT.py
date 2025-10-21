import functools
import json
import os
import re
import textwrap
import threading
import urllib.request
import urllib.parse
import sys
import argparse

import idaapi
import ida_hexrays
import ida_kernwin
import idc
import idautils

# Memory management utilities for improving performance
import gc
import time
import psutil
from contextlib import contextmanager

# === Headless mode & CLI parsing helpers =====================================
def is_headless():
    """
    Best-effort detection of IDA headless/batch mode across versions.
    Returns True if no GUI is available (e.g., -A batch mode).
    """
    try:
        # IDA 7.4+ returns None when no GUI/viewer exists
        import ida_kernwin as _kk
        return _kk.get_current_viewer() is None
    except Exception:
        pass
    # Older SDKs sometimes expose cvar.batch / batch_mode
    try:
        if hasattr(idaapi, "cvar"):
            if hasattr(idaapi.cvar, "batch"):
                return bool(idaapi.cvar.batch)
            if hasattr(idaapi.cvar, "batch_mode"):
                return bool(idaapi.cvar.batch_mode)
    except Exception:
        pass
    # Fallback: look for IDA's -A flag in argv
    try:
        return any(a == "-A" for a in sys.argv)
    except Exception:
        return False

IS_HEADLESS = is_headless()

def parse_args():
    """
    Parse ONLY our plugin's command-line flags when running headless.
    Returns argparse.Namespace or None (if no relevant flags were provided).
    """
    if not IS_HEADLESS:
        return None

    parser = argparse.ArgumentParser(
        prog="VulChatGPT",
        description="VulChatGPT headless controls (scan/decompile all)"
    )
    parser.add_argument("--scan-all", dest="scan_all", action="store_true",
                        help="Scan all functions for potential vulnerabilities")
    parser.add_argument("--decompile-all", dest="decompile_all", action="store_true",
                        help="Decompile all functions and optionally cache output")
    parser.add_argument("--batch-size", type=int, default=3,
                        help="How many functions to process per batch (default: 3)")
    parser.add_argument("--function-pause", type=int, default=5,
                        help="Seconds to pause between functions (default: 5)")
    parser.add_argument("--batch-pause", type=int, default=10,
                        help="Seconds to pause between batches (default: 10)")
    parser.add_argument("--output", type=str, default=None,
                        help="Path to JSON file for scan results")
    parser.add_argument("--cache-dir", type=str, default=None,
                        help="Directory to cache decompiled functions as .c files")

    # Ignore IDA's flags (e.g., -A, -S, -L, etc.)
    args, _unknown = parser.parse_known_args(sys.argv[1:])

    if not (args.scan_all or args.decompile_all):
        return None

    return args
# === end headless helpers =====================================================

# Function to get memory usage information
def get_memory_usage():
    process = psutil.Process()
    return process.memory_info().rss / (1024 * 1024)  # Convert to MB

# Context manager for memory-intensive operations
@contextmanager
def memory_managed_operation(threshold_mb=1000):
    start_mem = get_memory_usage()
    start_time = time.time()

    try:
        yield
    finally:
        # Force garbage collection
        gc.collect()

        # Log memory usage
        end_mem = get_memory_usage()
        end_time = time.time()
        print(f"Memory usage: {start_mem:.2f}MB -> {end_mem:.2f}MB (delta: {end_mem-start_mem:.2f}MB)")
        print(f"Operation took {end_time-start_time:.2f} seconds")

# CWE-699 Software Development categories for vulnerability classification
CWE_CATEGORIES = {
    "memory_buffer": {
        "name": "Memory Buffer Errors",
        "id": "CWE-1218",
        "description": "Weaknesses related to improper handling of memory buffers"
    },
    "numeric": {
        "name": "Numeric Errors",
        "id": "CWE-189",
        "description": "Weaknesses related to improper handling of numbers"
    },
    "resource_management": {
        "name": "Resource Management Errors",
        "id": "CWE-399",
        "description": "Weaknesses related to improper management of system resources"
    },
    "data_validation": {
        "name": "Data Validation Issues",
        "id": "CWE-1215",
        "description": "Weaknesses related to improper validation of data"
    },
    "authentication": {
        "name": "Authentication Errors",
        "id": "CWE-1211",
        "description": "Weaknesses related to authentication"
    },
    "authorization": {
        "name": "Authorization Errors",
        "id": "CWE-1212",
        "description": "Weaknesses related to authorization"
    },
    "cryptographic": {
        "name": "Cryptographic Issues",
        "id": "CWE-310",
        "description": "Weaknesses related to cryptography"
    },
    "information_leak": {
        "name": "Information Management Errors",
        "id": "CWE-199",
        "description": "Weaknesses that may lead to information leaks"
    },
    "error_handling": {
        "name": "Error Conditions, Return Values, Status Codes",
        "id": "CWE-389",
        "description": "Weaknesses related to error handling"
    },
    "initialization": {
        "name": "Initialization and Cleanup Errors",
        "id": "CWE-452",
        "description": "Weaknesses related to initialization and cleanup"
    }
}

# OpenAI compatibility layer (supports new SDK v1+ and legacy <1.0)
try:
    from openai import OpenAI as _OpenAIClient  # openai>=1.0
    _OPENAI_SDK = "v1"
except Exception:
    try:
        import openai as _openai_legacy  # type: ignore
        _OpenAIClient = None
        _OPENAI_SDK = "legacy"
    except Exception:
        _OpenAIClient = None
        _openai_legacy = None
        _OPENAI_SDK = None

_OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
_OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL")

# ----- Decompile All Handler --------------------------------------------------
class DecompileAllHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.is_running = False
        self.decompiled_count = 0
        self.total_count = 0
        self.batch_size = 3  # Reduced batch size to decrease memory pressure
        self.pause_seconds = 5  # Seconds to pause between functions
        self.batch_pause_seconds = 10  # Seconds to pause between batches
        self.cache_dir = None
        self.function_list = []

    def activate(self, ctx):
        if self.is_running:
            print("Decompilation is already in progress.")
            return 1

        # Check if hexrays is available
        if not ida_hexrays.init_hexrays_plugin():
            print("Hex-Rays decompiler is not available.")
            return 1

        # Ask user if they want to use a cache to avoid redecompilation in future runs
        use_cache = ida_kernwin.ask_yn(1, "Do you want to cache decompiled functions? (Recommended for large binaries)")

        # Ask user about processing settings
        if ida_kernwin.ask_yn(1, "Would you like to configure processing parameters? (Recommended to prevent hanging)"):
            # Get batch size
            batch_size_str = ida_kernwin.ask_str("3", 0, "Enter batch size (smaller = less memory pressure, try 1-5):")
            if batch_size_str and batch_size_str.isdigit() and 1 <= int(batch_size_str) <= 20:
                self.batch_size = int(batch_size_str)

            # Get pause duration
            pause_str = ida_kernwin.ask_str("5", 0, "Enter pause seconds between functions (try 5-10):")
            if pause_str and pause_str.isdigit() and 1 <= int(pause_str) <= 30:
                self.pause_seconds = int(pause_str)

            # Get batch pause duration
            batch_pause_str = ida_kernwin.ask_str("10", 0, "Enter pause seconds between batches (try 10-20):")
            if batch_pause_str and batch_pause_str.isdigit() and 1 <= int(batch_pause_str) <= 60:
                self.batch_pause_seconds = int(batch_pause_str)

            print(f"Using configuration: batch size={self.batch_size}, function pause={self.pause_seconds}s, batch pause={self.batch_pause_seconds}s")

        if use_cache:
            # Create cache directory based on IDB name
            idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
            if idb_path:
                idb_name = os.path.basename(idb_path).split('.')[0]
                self.cache_dir = os.path.join(os.path.dirname(idb_path), f"{idb_name}_decompiled_cache")

                if not os.path.exists(self.cache_dir):
                    try:
                        os.makedirs(self.cache_dir)
                    except Exception as e:
                        print(f"Could not create cache directory: {e}")
                        self.cache_dir = None

        # Show wait box
        ida_kernwin.show_wait_box("Preparing decompilation...")

        try:
            # Count total functions first
            self.total_count = 0
            self.function_list = []

            # Enumerate executable segments & collect function starts
            for seg_idx in range(idaapi.get_segm_qty()):
                seg = idaapi.getnseg(seg_idx)
                if seg and seg.perm & idaapi.SEGPERM_EXEC:
                    ea = seg.start_ea
                    while ea < seg.end_ea:
                        func = idaapi.get_func(ea)
                        if func:
                            self.function_list.append(func.start_ea)
                            self.total_count += 1
                            ea = func.end_ea
                        else:
                            ea = idc.next_head(ea, seg.end_ea)
                            if ea == idc.BADADDR:
                                break

            print(f"Found {self.total_count} functions to decompile")

            # Start decompilation in batches
            self.is_running = True
            self.decompiled_count = 0
            ida_kernwin.replace_wait_box(f"Decompiling functions: 0/{self.total_count}")

            # Start processing
            self._process_batch(0)
            return 1

        except Exception as e:
            ida_kernwin.hide_wait_box()
            print(f"Error preparing decompilation: {e}")
            return 1

    def _process_batch(self, start_idx):
        try:
            end_idx = min(start_idx + self.batch_size, len(self.function_list))

            # Process a batch of functions
            for i in range(start_idx, end_idx):
                func_ea = self.function_list[i]

                try:
                    # Check cache first if enabled
                    cached = False
                    if self.cache_dir:
                        cache_file = os.path.join(self.cache_dir, f"func_{func_ea:X}.c")
                        if os.path.exists(cache_file):
                            cached = True

                    # If not cached, decompile
                    if not cached:
                        with memory_managed_operation():
                            func = idaapi.get_func(func_ea)
                            if func:
                                ida_hexrays.decompile(func.start_ea)

                                # Cache the result if caching is enabled
                                if self.cache_dir:
                                    try:
                                        decompiled = ida_hexrays.decompile(func.start_ea)
                                        if decompiled:
                                            with open(os.path.join(self.cache_dir, f"func_{func_ea:X}.c"), "w") as f:
                                                f.write(str(decompiled))
                                    except Exception as e:
                                        print(f"Error caching function at {hex(func_ea)}: {e}")

                    self.decompiled_count += 1

                    # Update progress in the UI
                    if self.decompiled_count % 5 == 0 or self.decompiled_count == self.total_count:
                        percentage = (self.decompiled_count / self.total_count) * 100
                        ida_kernwin.replace_wait_box(f"Decompiling functions: {self.decompiled_count}/{self.total_count} ({percentage:.1f}%)")

                    # Pause after each function
                    time.sleep(5)
                    print(f"Paused for 5 seconds after processing function at {hex(func_ea)}")

                except Exception as e:
                    print(f"Error decompiling function at {hex(func_ea)}: {e}")
                    self.decompiled_count += 1

                # Force garbage collection after each function
                gc.collect()

                # Process UI events to keep IDA responsive
                try:
                    idaapi.process_ui_action("Refresh")
                except Exception:
                    pass

            # Pause between batches
            time.sleep(10)
            print(f"Paused for 10 seconds after processing batch {start_idx}-{end_idx-1}")

            # Continue with next batch if needed
            if end_idx < len(self.function_list):
                ida_kernwin.register_timer(1000, lambda: self._process_batch(end_idx) or -1)
            else:
                # All done
                self.is_running = False
                ida_kernwin.hide_wait_box()
                print(f"Decompilation complete. Processed {self.decompiled_count} functions.")

                # Suggest to free up memory
                gc.collect()
        except Exception as e:
            ida_kernwin.hide_wait_box()
            print(f"Error in batch processing: {e}")
            self.is_running = False

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# ----- Main Plugin ------------------------------------------------------------
class VulChatPlugin(idaapi.plugin_t):
    flags = 0
    wanted_name = "VulChat"
    wanted_hotkey = ""
    comment = "Uses GPT-5 to analyze the decompiler's output for vulnerabilities based on CWE"
    help = "Run from Edit/VulChat menu on pseudocode"

    # action ids & menu paths
    explain_action_name = "vulchat:explain_function"
    explain_menu_path = "Edit/Vulchat/Explain the following Code"

    rename_action_name = "vulchat:rename_function"
    rename_menu_path = "Edit/Vulchat/Rename Variables and Functions"

    vuln_action_name = "vulchat:vuln_function"
    vuln_menu_path = "Edit/VulChat/Find Possible Vulnerability"

    expl_action_name = "vulchat:expl_function"
    expl_menu_path = "Edit/Vulchat/Generate Safe Test Inputs"

    scan_all_action_name = "vulchat:scan_all_functions"
    scan_all_menu_path = "Edit/VulChat/Scan All Functions for Vulnerabilities"

    cwe_info_action_name = "vulchat:cwe_info"
    cwe_info_menu_path = "Edit/VulChat/CWE Reference Lookup"

    decompile_all_action_name = "vulchat:decompile_all"
    decompile_all_menu_path = "Edit/VulChat/Decompile All Functions"

    control_panel_action_name = "vulchat:control_panel"
    control_panel_menu_path = "Edit/VulChat/Control Panel"

    menu = None

    def init(self):
        # Ensure decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        # Register actions (IDA 7.5+ uses ida_kernwin.action_desc_t)
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.explain_action_name,
                "Explain function",
                ExplainHandler(),
                "Ctrl+Alt+G",
                "Use GPT-5 to explain the selected function",
                199,
            )
        )
        ida_kernwin.attach_action_to_menu(self.explain_menu_path, self.explain_action_name, ida_kernwin.SETMENU_APP)

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.rename_action_name,
                "Rename variables",
                RenameHandler(),
                "Ctrl+Alt+R",
                "Use GPT-5 to suggest better variable names",
                199,
            )
        )
        ida_kernwin.attach_action_to_menu(self.rename_menu_path, self.rename_action_name, ida_kernwin.SETMENU_APP)

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.vuln_action_name,
                "Find possible vulnerability in function",
                VulnHandler(),
                "Ctrl+Alt+V",
                "Use GPT-5 to identify potential vulnerabilities",
                199,
            )
        )
        ida_kernwin.attach_action_to_menu(self.vuln_menu_path, self.vuln_action_name, ida_kernwin.SETMENU_APP)

        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.expl_action_name,
                "Generate Safe Test Inputs",
                ExploitHandler(),
                "Ctrl+Alt+X",
                "Use GPT-5 to propose safe test inputs to validate behavior",
                199,
            )
        )
        ida_kernwin.attach_action_to_menu(self.expl_menu_path, self.expl_action_name, ida_kernwin.SETMENU_APP)

        # Register scan all functions action
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.scan_all_action_name,
                "Scan All Functions for Vulnerabilities",
                ScanAllHandler(),
                "Ctrl+Alt+S",
                "Use GPT-5 to scan all functions for potential vulnerabilities",
                199,
            )
        )
        ida_kernwin.attach_action_to_menu(self.scan_all_menu_path, self.scan_all_action_name, ida_kernwin.SETMENU_APP)

        # Register CWE reference lookup action
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.cwe_info_action_name,
                "CWE Reference Lookup",
                CweInfoHandler(),
                "Ctrl+Alt+W",
                "Look up information about a specific CWE",
                199,
            )
        )
        ida_kernwin.attach_action_to_menu(self.cwe_info_menu_path, self.cwe_info_action_name, ida_kernwin.SETMENU_APP)

        # Register decompile all functions action
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.decompile_all_action_name,
                "Decompile All Functions",
                DecompileAllHandler(),
                "Ctrl+F5",
                "Decompile all functions with memory management to avoid IDA hanging",
                199,
            )
        )
        ida_kernwin.attach_action_to_menu(self.decompile_all_menu_path, self.decompile_all_action_name, ida_kernwin.SETMENU_APP)

        # Register control panel action
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                self.control_panel_action_name,
                "Control Panel (Pause/Cancel Operations)",
                ControlPanelHandler(),
                "Ctrl+Alt+P",
                "Control long-running operations (pause, resume, cancel)",
                199,
            )
        )
        ida_kernwin.attach_action_to_menu(self.control_panel_menu_path, self.control_panel_action_name, ida_kernwin.SETMENU_APP)

        # Context menu hook for pseudocode view
        self.menu = ContextMenuHooks()
        self.menu.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        try:
            ida_kernwin.detach_action_from_menu(self.explain_menu_path, self.explain_action_name)
            ida_kernwin.detach_action_from_menu(self.rename_menu_path, self.rename_action_name)
            ida_kernwin.detach_action_from_menu(self.vuln_menu_path, self.vuln_action_name)
            ida_kernwin.detach_action_from_menu(self.expl_menu_path, self.expl_action_name)
            ida_kernwin.detach_action_from_menu(self.scan_all_menu_path, self.scan_all_action_name)
            ida_kernwin.detach_action_from_menu(self.cwe_info_menu_path, self.cwe_info_action_name)
            ida_kernwin.detach_action_from_menu(self.decompile_all_menu_path, self.decompile_all_action_name)
            ida_kernwin.detach_action_from_menu(self.control_panel_menu_path, self.control_panel_action_name)
        except Exception:
            pass
        if self.menu:
            self.menu.unhook()

# ----- Headless mode handlers -------------------------------------------------
class HeadlessScanHandler:
    """Handler for scanning functions in headless mode"""
    def __init__(self):
        self.batch_size = 3
        self.pause_seconds = 5
        self.batch_pause_seconds = 10
        self.output_file = None
        self.is_scanning = False
        self.processed_functions = 0
        self.total_functions = 0
        self.results = {}

    def run(self):
        self.is_scanning = True
        self.processed_functions = 0
        self.results = {}

        print("[+] Enumerating functions...")
        try:
            # Get all functions
            func_list = list(idautils.Functions())
            self.total_functions = len(func_list)
            print(f"[+] Found {self.total_functions} functions")

            # Process functions in batches
            batch_idx = 0
            while batch_idx < len(func_list):
                end_idx = min(batch_idx + self.batch_size, len(func_list))
                print(f"[+] Processing batch {batch_idx//self.batch_size + 1} ({batch_idx+1}-{end_idx} of {len(func_list)})")

                # Process each function in the batch
                for i in range(batch_idx, end_idx):
                    func_ea = func_list[i]
                    self._scan_function(func_ea)

                    # Pause after each function
                    time.sleep(self.pause_seconds)
                    print(f"[+] Paused for {self.pause_seconds}s after function at {hex(func_ea)}")

                # Pause after the batch
                if end_idx < len(func_list):
                    time.sleep(self.batch_pause_seconds)
                    print(f"[+] Paused for {self.batch_pause_seconds}s after batch")

                batch_idx = end_idx

            # Save results if output file specified
            if self.output_file:
                self._save_results()

            print(f"[+] Scan complete. Found {len(self.results)} potentially vulnerable functions.")
            self.is_scanning = False

        except Exception as e:
            print(f"[-] Error in headless scan: {e}")
            self.is_scanning = False

    def _scan_function(self, func_ea):
        func = idaapi.get_func(func_ea)
        if not func:
            self.processed_functions += 1
            return

        try:
            # Check memory and run garbage collection
            current_mem_usage = get_memory_usage()
            if current_mem_usage > 0 and current_mem_usage > 1500:
                print(f"[+] High memory usage: {current_mem_usage:.2f}MB. Running garbage collection...")
                gc.collect()
                time.sleep(2)

            # Decompile the function
            with memory_managed_operation():
                decompiled = ida_hexrays.decompile(func_ea)
                if not decompiled:
                    print(f"[-] Could not decompile function at {hex(func_ea)}")
                    self.processed_functions += 1
                    return

                # Convert to string to release the decompile object
                decompiled_str = str(decompiled)
                func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"

                # Truncate very large functions
                if len(decompiled_str) > 20000:
                    decompiled_str = decompiled_str[:20000] + "\n... [truncated due to size]\n"

                print(f"[+] Analyzing function {func_name} ({self.processed_functions+1}/{self.total_functions})")

                # Run simple static analysis for common vulnerabilities
                vulnerabilities = self._static_analyze(decompiled_str, func_ea)

                # Save results if vulnerabilities found
                if vulnerabilities:
                    self.results[func_ea] = {
                        "name": func_name,
                        "address": func_ea,
                        "vulnerabilities": vulnerabilities
                    }

                    # Add a comment to the function
                    comment = "POTENTIAL VULNERABILITIES:\n"
                    for i, vuln in enumerate(vulnerabilities, 1):
                        comment += f"{i}. {vuln['description']}\n"
                        comment += f"   CWE: {vuln['cwe_id']} | Severity: {vuln['severity']}\n\n"
                    idc.set_func_cmt(func_ea, comment, 0)

            self.processed_functions += 1
            print(f"[+] Progress: {self.processed_functions}/{self.total_functions} functions")

        except Exception as e:
            print(f"[-] Error analyzing function {hex(func_ea)}: {e}")
            self.processed_functions += 1

    def _static_analyze(self, decompiled_str, func_ea):
        """Simple static analysis to detect common vulnerabilities"""
        vulnerabilities = []

        # Check for common memory safety issues
        if re.search(r'\b(strcpy|strcat|gets|sprintf)\s*\(', decompiled_str):
            vulnerabilities.append({
                "description": "Potentially unsafe string function used (strcpy/strcat/gets/sprintf)",
                "cwe_id": "CWE-120",
                "category": "Memory Buffer",
                "severity": "High",
                "mitigation": "Replace with safer alternatives (strncpy, strncat, snprintf)"
            })

        # Check for pointer arithmetic with array/pointer dereference
        if re.search(r'\w+\s*\+\+\s*;|\+\+\s*\w+|\w+\s*\+=', decompiled_str) and \
           re.search(r'\w+\s*\[|\*\w+', decompiled_str):
            vulnerabilities.append({
                "description": "Pointer arithmetic detected, potential for buffer overrun",
                "cwe_id": "CWE-119",
                "category": "Memory Buffer",
                "severity": "Medium",
                "mitigation": "Validate array bounds and pointer operations"
            })

        # Check for malloc/free pairs
        if re.search(r'\bmalloc\s*\(', decompiled_str) and not re.search(r'\bfree\s*\(', decompiled_str):
            vulnerabilities.append({
                "description": "Memory allocated but no free detected; possible memory leak",
                "cwe_id": "CWE-401",
                "category": "Resource Management",
                "severity": "Medium",
                "mitigation": "Ensure all allocated memory is properly freed"
            })

        # Check for integer ops that could overflow
        if re.search(r'\b(int|long|short|char)\b.*=.*\+|\b(int|long|short|char)\b.*\+=', decompiled_str):
            vulnerabilities.append({
                "description": "Integer operations without overflow checks",
                "cwe_id": "CWE-190",
                "category": "Numeric",
                "severity": "Medium",
                "mitigation": "Add checks for integer overflow/underflow"
            })

        # Check for file operations without checks
        if re.search(r'\b(fopen|open)\s*\(', decompiled_str) and not re.search(r'if\s*\(.*\b(fopen|open)\b', decompiled_str):
            vulnerabilities.append({
                "description": "File operation without proper error checking",
                "cwe_id": "CWE-404",
                "category": "Resource Management",
                "severity": "Low",
                "mitigation": "Add proper error checking for file operations"
            })

        return vulnerabilities

    def _save_results(self):
        """Save scan results to output file"""
        if not self.output_file:
            return

        try:
            with open(self.output_file, 'w') as f:
                json.dump({
                    "scan_results": {
                        "total_functions": self.total_functions,
                        "vulnerable_functions": len(self.results),
                        "functions": [{
                            "name": data["name"],
                            "address": hex(addr),
                            "vulnerabilities": data["vulnerabilities"]
                        } for addr, data in self.results.items()]
                    }
                }, f, indent=2)
            print(f"[+] Results saved to {self.output_file}")
        except Exception as e:
            print(f"[-] Error saving results: {e}")

class HeadlessDecompileHandler:
    """Handler for decompiling functions in headless mode"""
    def __init__(self):
        self.batch_size = 3
        self.pause_seconds = 5
        self.batch_pause_seconds = 10
        self.cache_dir = None
        self.is_running = False
        self.decompiled_count = 0
        self.total_count = 0

    def run(self):
        self.is_running = True
        self.decompiled_count = 0

        print("[+] Enumerating functions...")
        try:
            # Get all functions
            func_list = list(idautils.Functions())
            self.total_count = len(func_list)
            print(f"[+] Found {self.total_count} functions")

            # Create default cache directory if none specified
            if not self.cache_dir:
                idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
                if idb_path:
                    idb_name = os.path.basename(idb_path).split('.')[0]
                    self.cache_dir = os.path.join(os.path.dirname(idb_path), f"{idb_name}_decompiled_cache")

                    if not os.path.exists(self.cache_dir):
                        try:
                            os.makedirs(self.cache_dir)
                        except Exception as e:
                            print(f"[-] Could not create cache directory: {e}")
                            self.cache_dir = None

            if self.cache_dir:
                print(f"[+] Using cache directory: {self.cache_dir}")

            # Process functions in batches
            batch_idx = 0
            while batch_idx < len(func_list):
                end_idx = min(batch_idx + self.batch_size, len(func_list))
                print(f"[+] Processing batch {batch_idx//self.batch_size + 1} ({batch_idx+1}-{end_idx} of {len(func_list)})")

                # Process each function in the batch
                for i in range(batch_idx, end_idx):
                    func_ea = func_list[i]

                    try:
                        # Check cache first if enabled
                        cached = False
                        if self.cache_dir:
                            cache_file = os.path.join(self.cache_dir, f"func_{func_ea:X}.c")
                            if os.path.exists(cache_file):
                                cached = True
                                print(f"[+] Using cached decompilation for {hex(func_ea)}")

                        # If not cached, decompile
                        if not cached:
                            # Check memory and run garbage collection
                            current_mem_usage = get_memory_usage()
                            if current_mem_usage > 0 and current_mem_usage > 1500:
                                print(f"[+] High memory usage: {current_mem_usage:.2f}MB. Running garbage collection...")
                                gc.collect()
                                time.sleep(2)

                            # Decompile the function
                            with memory_managed_operation():
                                func = idaapi.get_func(func_ea)
                                if func:
                                    print(f"[+] Decompiling function at {hex(func_ea)}")
                                    decompiled = ida_hexrays.decompile(func.start_ea)

                                    # Cache the result if caching is enabled
                                    if self.cache_dir and decompiled:
                                        try:
                                            with open(os.path.join(self.cache_dir, f"func_{func_ea:X}.c"), "w") as f:
                                                f.write(str(decompiled))
                                        except Exception as e:
                                            print(f"[-] Error caching function at {hex(func_ea)}: {e}")
                                else:
                                    print(f"[-] Invalid function at {hex(func_ea)}")

                        self.decompiled_count += 1
                        print(f"[+] Progress: {self.decompiled_count}/{self.total_count} functions")

                        # Pause after each function
                        time.sleep(self.pause_seconds)

                    except Exception as e:
                        print(f"[-] Error decompiling function at {hex(func_ea)}: {e}")
                        self.decompiled_count += 1

                    # Force garbage collection after each function
                    gc.collect()

                # Pause after the batch
                if end_idx < len(func_list):
                    time.sleep(self.batch_pause_seconds)
                    print(f"[+] Paused for {self.batch_pause_seconds}s after batch")

                batch_idx = end_idx

            print(f"[+] Decompilation complete. Processed {self.decompiled_count} functions.")
            self.is_running = False

        except Exception as e:
            print(f"[-] Error in headless decompilation: {e}")
            self.is_running = False

# ----- Control Panel ----------------------------------------------------------
class ControlPanelHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Check if any operation is running
        operations_running = False

        # Try to locate the decompile-all handler by action registry
        try:
            for action_name in ida_kernwin.get_registered_actions():
                if action_name == VulChatPlugin.decompile_all_action_name:
                    # There is no direct way to fetch handler instance from name in some IDA versions.
                    operations_running = True
                    break
        except Exception:
            pass

        if not operations_running:
            print("No operations currently running.")
            return 1

        options = ["Pause for 30 seconds", "Pause for 2 minutes", "Pause for 5 minutes", "Cancel current operation"]
        choice = ida_kernwin.ask_buttons("Pause 30s", "Pause 2m", "Pause 5m", 0, "VulChat Control Panel\nSelect an action:")

        if choice == 0:  # Cancel button
            return 1
        elif choice == 1:  # Pause for 30s
            print("Pausing operations for 30 seconds...")
            time.sleep(30)
            print("Resuming operations...")
        elif choice == 2:  # Pause for 2m
            print("Pausing operations for 2 minutes...")
            time.sleep(120)
            print("Resuming operations...")
        elif choice == 3:  # Pause for 5m
            print("Pausing operations for 5 minutes...")
            time.sleep(300)
            print("Resuming operations...")
        elif choice == -1:  # Cancel operation
            print("Operation cancellation requested (no universal cancel hook available).")

        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# ----- Context Menu Hooks -----------------------------------------------------
class ContextMenuHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        if ida_kernwin.get_widget_type(form) == ida_kernwin.BWN_PSEUDOCODE:
            ida_kernwin.attach_action_to_popup(form, popup, VulChatPlugin.vuln_action_name, "VulChat/")
            ida_kernwin.attach_action_to_popup(form, popup, VulChatPlugin.expl_action_name, "VulChat/Safe_Tests")
            ida_kernwin.attach_action_to_popup(form, popup, VulChatPlugin.explain_action_name, "VulChat/Explain")
            ida_kernwin.attach_action_to_popup(form, popup, VulChatPlugin.rename_action_name, "VulChat/Rename_Vars")
            ida_kernwin.attach_action_to_popup(form, popup, VulChatPlugin.scan_all_action_name, "VulChat/Scan_All")
            ida_kernwin.attach_action_to_popup(form, popup, VulChatPlugin.cwe_info_action_name, "VulChat/CWE_Info")
            ida_kernwin.attach_action_to_popup(form, popup, VulChatPlugin.decompile_all_action_name, "VulChat/Decompile_All")
            ida_kernwin.attach_action_to_popup(form, popup, VulChatPlugin.control_panel_action_name, "VulChat/Control_Panel")

# ----- Helpers ----------------------------------------------------------------
def comment_callback(address, view, response):
    # Wrap lines for readability
    response = "\n".join(textwrap.wrap(response or "", 80, replace_whitespace=False))
    idc.set_func_cmt(address, response, 0)
    if view:
        try:
            view.refresh_view(False)
        except Exception:
            pass
    print("GPT-5 query finished!")

class ExplainHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        decompiler_output = ida_hexrays.decompile(ea)
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async(
            "Can you explain what the following C function does and suggest a better name for it?\n"
            + str(decompiler_output),
            functools.partial(comment_callback, address=ea, view=v),
        )
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

def rename_callback(address, view, response):
    j = re.search(r"\{[^}]*?\}", response or "")
    if not j:
        print("Cannot extract valid JSON from the response. Asking the model to fix it...")
        query_model_async(
            "The JSON document provided in this response is invalid. Can you fix it?\n" + (response or ""),
            functools.partial(rename_callback, address=address, view=view),
        )
        return
    try:
        names = json.loads(j.group(0))
    except json.decoder.JSONDecodeError:
        print("The JSON document returned is invalid. Asking the model to fix it...")
        query_model_async(
            "Please fix the following JSON document:\n" + j.group(0),
            functools.partial(rename_callback, address=address, view=view),
        )
        return

    function_addr = idaapi.get_func(address).start_ea
    replaced = []
    for n in names:
        try:
            if ida_hexrays.rename_lvar(function_addr, n, names[n]):
                replaced.append(n)
        except Exception:
            pass

    # Update function comment occurrences
    comment = idc.get_func_cmt(address, 0)
    if comment and replaced:
        for n in replaced:
            comment = re.sub(r"\b%s\b" % re.escape(n), names[n], comment)
        idc.set_func_cmt(address, comment, 0)

    if view:
        try:
            view.refresh_view(True)
        except Exception:
            pass
    print(f"GPT-5 query finished! {len(replaced)} variable(s) renamed.")

class RenameHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        decompiler_output = ida_hexrays.decompile(ea)
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async(
            "Analyze the following C function:\n" + str(decompiler_output)
            + "\nSuggest better variable names, reply with a JSON object where keys are the original names and values are the proposed names. Do not explain anything, only print the JSON object.",
            functools.partial(rename_callback, address=ea, view=v),
        )
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class VulnHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        decompiler_output = ida_hexrays.decompile(ea)
        v = ida_hexrays.get_widget_vdui(ctx.widget)

        # Using a more structured prompt with CWE references
        query_model_async(
            "Analyze the following C function for potential security vulnerabilities:\n"
            + str(decompiler_output) + "\n\n"
            "For each vulnerability found, please provide:\n"
            "1. Brief description\n"
            "2. CWE ID (if applicable)\n"
            "3. Severity (High, Medium, Low)\n"
            "4. Suggested mitigation\n\n"
            "Focus on these categories from CWE-699:\n"
            "- Memory Buffer Errors (e.g., buffer overflow, use after free)\n"
            "- Numeric Errors (e.g., integer overflow)\n"
            "- Resource Management Errors\n"
            "- Data Validation Issues\n"
            "- Authentication/Authorization Errors\n"
            "- Cryptographic Issues\n"
            "- Error Handling Issues\n"
            "Format your response with clear headers for each vulnerability.",
            functools.partial(comment_callback, address=ea, view=v),
        )
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ExploitHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = ida_kernwin.get_screen_ea()
        decompiler_output = ida_hexrays.decompile(ea)
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async(
            "Analyze the following C function and propose safe test inputs or harness ideas to validate behavior (avoid exploit code):\n"
            + str(decompiler_output),
            functools.partial(comment_callback, address=ea, view=v),
        )
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class ScanAllHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.results = {}
        self.total_functions = 0
        self.processed_functions = 0
        self.is_scanning = False

    def activate(self, ctx):
        if self.is_scanning:
            print("Already scanning functions. Please wait for the current scan to complete.")
            return 1

        self.is_scanning = True
        self.results = {}
        self.processed_functions = 0
        self.total_functions = 0

        # Show wait box
        ida_kernwin.show_wait_box("Initializing vulnerability scan...")

        # First, count functions to get total (more memory efficient)
        print("Counting functions...")
        func_count = 0

        # Use a generator approach to avoid storing all functions in memory
        def function_generator():
            seg = idaapi.get_first_seg()
            while seg:
                start_ea = seg.start_ea
                end_ea = seg.end_ea
                ea = start_ea
                while ea < end_ea:
                    func = idaapi.get_func(ea)
                    if func:
                        yield func.start_ea
                        ea = func.end_ea
                    else:
                        ea = idc.next_head(ea, end_ea)
                        if ea == idc.BADADDR:
                            break
                seg = idaapi.get_next_seg(seg.start_ea)

        # Count functions first
        for _ in function_generator():
            func_count += 1

        self.total_functions = func_count
        print(f"Starting vulnerability scan of {self.total_functions} functions...")

        # Update wait box message
        ida_kernwin.replace_wait_box(f"Scanning {self.total_functions} functions for vulnerabilities...")

        # Start the process with our generator
        self._start_scanning(function_generator())
        return 1

    def _start_scanning(self, function_gen):
        self._process_next_batch(function_gen)

    def _process_next_batch(self, function_gen, batch_size=5):
        try:
            # Process a batch of functions
            for i in range(batch_size):
                try:
                    func_ea = next(function_gen)
                    self._scan_function(func_ea)

                    # Pause after each function (5 seconds)
                    time.sleep(5)
                    print(f"Paused for 5 seconds after scanning function at {hex(func_ea)}")

                    # Process UI events to keep IDA responsive
                    try:
                        idaapi.process_ui_action("Refresh")
                    except Exception:
                        pass

                except StopIteration:
                    # No more functions to process
                    self._display_final_results()
                    self.is_scanning = False
                    ida_kernwin.hide_wait_box()
                    return
                except Exception as e:
                    print(f"Error processing function: {str(e)}")
                    self.processed_functions += 1

            # Pause between batches
            time.sleep(10)
            print(f"Paused for 10 seconds after processing batch of {batch_size} functions")

            # Schedule next batch
            ida_kernwin.register_timer(1000, lambda: self._process_next_batch(function_gen, batch_size) or -1)

        except Exception as e:
            print(f"Error in batch processing: {str(e)}")
            self._display_final_results()
            self.is_scanning = False
            ida_kernwin.hide_wait_box()

    def _scan_function(self, func_ea):
        func = idaapi.get_func(func_ea)
        if not func:
            self.processed_functions += 1
            return

        try:
            current_mem_usage = get_memory_usage()
            if current_mem_usage > 1500:
                print(f"High memory usage detected ({current_mem_usage:.2f}MB). Forcing garbage collection...")
                gc.collect()

            with memory_managed_operation():
                decompiled = ida_hexrays.decompile(func_ea)
                if not decompiled:
                    print(f"Could not decompile function at {hex(func_ea)}")
                    self.processed_functions += 1
                    return

                decompiled_str = str(decompiled)

                func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
                print(f"Scanning function {func_name} ({self.processed_functions+1}/{self.total_functions})")

                if len(decompiled_str) > 20000:
                    print(f"Function {func_name} is very large ({len(decompiled_str)} chars). Truncating...")
                    decompiled_str = decompiled_str[:20000] + "\n... [truncated due to size]\n"

                query_model_async(
                    f"Scan this C function for security vulnerabilities:\n{decompiled_str}\n\n"
                    f"For each vulnerability found, return a JSON object with the following structure:\n"
                    f"{{\n"
                    f"  \"vulnerabilities\": [\n"
                    f"    {{\n"
                    f"      \"description\": \"Brief description\",\n"
                    f"      \"cwe_id\": \"CWE-XXX\",\n"
                    f"      \"category\": \"One of: Memory Buffer, Numeric, Resource Management, Data Validation, Authentication, Authorization, Cryptographic, Information Leak, Error Handling, Initialization\",\n"
                    f"      \"severity\": \"High/Medium/Low\",\n"
                    f"      \"mitigation\": \"Brief mitigation advice\"\n"
                    f"    }}\n"
                    f"  ]\n"
                    f"}}\n\n"
                    f"If no vulnerabilities are found, return {{\"vulnerabilities\": []}}. Ensure your response contains ONLY the JSON object.",
                    functools.partial(self._process_result, func_ea=func_ea, func_name=func_name)
                )
        except Exception as e:
            print(f"Error analyzing function {hex(func_ea)}: {str(e)}")
            self.processed_functions += 1

    def _process_result(self, response, func_ea, func_name):
        try:
            json_match = re.search(r'\{[\s\S]*?\}', response)
            if json_match:
                json_data = json.loads(json_match.group(0))
                vulnerabilities = json_data.get("vulnerabilities", [])

                if vulnerabilities:
                    self.results[func_ea] = {
                        "name": func_name,
                        "vulnerabilities": vulnerabilities
                    }
            elif response and "No vulnerabilities detected" not in response:
                self.results[func_ea] = {
                    "name": func_name,
                    "vulnerabilities": [{
                        "description": response,
                        "cwe_id": "Unknown",
                        "category": "Unknown",
                        "severity": "Unknown",
                        "mitigation": "See full description"
                    }]
                }
        except Exception as e:
            print(f"Error processing result for {func_name}: {str(e)}")
            if response and "No vulnerabilities detected" not in response:
                self.results[func_ea] = {
                    "name": func_name,
                    "vulnerabilities": [{
                        "description": response,
                        "cwe_id": "Error parsing response",
                        "category": "Unknown",
                        "severity": "Unknown",
                        "mitigation": "See full description"
                    }]
                }

        self.processed_functions += 1
        print(f"Progress: {self.processed_functions}/{self.total_functions} functions scanned")

        # Update progress in the UI periodically
        if self.processed_functions % 10 == 0 or self.processed_functions == self.total_functions:
            percentage = (self.processed_functions / self.total_functions) * 100
            ida_kernwin.replace_wait_box(f"Scanning functions: {percentage:.1f}% complete")

        if self.processed_functions >= self.total_functions:
            self._display_final_results()
            self.is_scanning = False
            ida_kernwin.hide_wait_box()

    def _display_final_results(self):
        if not self.results:
            print("Scan complete. No vulnerabilities found.")
            return

        print(f"\n{'='*80}\nVulnerability Scan Results\n{'='*80}")
        print(f"Found {len(self.results)} potentially vulnerable functions\n")

        category_stats = {}
        severity_stats = {"High": 0, "Medium": 0, "Low": 0, "Unknown": 0}

        for func_ea, data in self.results.items():
            print(f"Function: {data['name']} at {hex(func_ea)}")

            if isinstance(data['vulnerabilities'], list):
                for vuln in data['vulnerabilities']:
                    severity = vuln.get("severity", "Unknown")
                    category = vuln.get("category", "Unknown")
                    cwe_id = vuln.get("cwe_id", "Unknown")

                    print(f"- {vuln.get('description', 'Unknown issue')}")
                    print(f"  CWE: {cwe_id} | Category: {category} | Severity: {severity}")
                    print(f"  Mitigation: {vuln.get('mitigation', 'No mitigation provided')}")

                    if category not in category_stats:
                        category_stats[category] = 0
                    category_stats[category] += 1

                    if severity in severity_stats:
                        severity_stats[severity] += 1
                    else:
                        severity_stats["Unknown"] += 1

                # Add a formatted comment to the function
                comment = f"POTENTIAL VULNERABILITIES:\n"
                for i, vuln in enumerate(data['vulnerabilities'], 1):
                    comment += f"{i}. {vuln.get('description', 'Unknown issue')}\n"
                    comment += f"   CWE: {vuln.get('cwe_id', 'Unknown')} | Severity: {vuln.get('severity', 'Unknown')}\n"
                    comment += f"   Mitigation: {vuln.get('mitigation', 'No mitigation provided')}\n\n"
            else:
                print(f"Vulnerabilities:\n{data['vulnerabilities']}")
                comment = f"POTENTIAL VULNERABILITIES:\n{data['vulnerabilities']}"

            print("-" * 80)
            idc.set_func_cmt(func_ea, comment, 0)

        print(f"\n{'='*40}\nVulnerability Summary\n{'='*40}")
        print("By Category:")
        for category, count in sorted(category_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"- {category}: {count}")

        print("\nBy Severity:")
        for severity, count in severity_stats.items():
            if count > 0:
                print(f"- {severity}: {count}")

        print(f"\n{'='*80}\nScan complete. Results have been added as function comments.\n{'='*80}")

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# ---- OpenAI integration ------------------------------------------------------
def _get_openai_client():
    if _OPENAI_SDK == "v1" and _OpenAIClient is not None:
        try:
            kwargs = {}
            if _OPENAI_API_KEY:
                kwargs["api_key"] = _OPENAI_API_KEY
            if _OPENAI_BASE_URL:
                kwargs["base_url"] = _OPENAI_BASE_URL
            return "v1", _OpenAIClient(**kwargs)  # type: ignore
        except Exception as e:
            print(f"Failed to init OpenAI v1 client: {e}")
            return None, None
    if _OPENAI_SDK == "legacy" and '_openai_legacy' in globals():
        try:
            if _OPENAI_API_KEY:
                _openai_legacy.api_key = _OPENAI_API_KEY  # type: ignore
            if _OPENAI_BASE_URL:
                _openai_legacy.api_base = _OPENAI_BASE_URL  # type: ignore
            return "legacy", _openai_legacy
        except Exception as e:
            print(f"Failed to init legacy OpenAI client: {e}")
            return None, None
    return None, None

def query_model(query, cb, max_output_tokens=1500, model_name="gpt-5"):
    mode, client = _get_openai_client()
    if mode is None:
        print("OpenAI SDK not available. Install openai and set OPENAI_API_KEY.")
        return

    try:
        if mode == "v1":
            try:
                resp = client.chat.completions.create(  # type: ignore
                    model=model_name,
                    messages=[
                        {"role": "system", "content": "You are an expert vulnerability researcher, specializing in secure code review and vulnerability detection. You have extensive knowledge of the CWE (Common Weakness Enumeration) taxonomy, especially the CWE-699 Software Development categories. You are skilled at identifying memory safety issues, integer problems, error handling bugs, and other common security flaws in C/C++ code. Be specific with vulnerability descriptions, include precise CWE IDs when possible, and suggest concrete mitigations. Avoid unsafe instructions or exploits, but provide clear explanations of risk."},
                        {"role": "user", "content": query},
                    ],
                    max_tokens=max_output_tokens,
                )
                text = resp.choices[0].message.content if resp.choices else ""
            except Exception:
                resp = client.responses.create(  # type: ignore
                    model=model_name,
                    input=query,
                    max_output_tokens=max_output_tokens,
                )
                text = getattr(resp, "output_text", None) or getattr(resp, "content", "")
            ida_kernwin.execute_sync(functools.partial(cb, response=text), ida_kernwin.MFF_WRITE)
            return

        if mode == "legacy":
            resp = client.Completion.create(  # type: ignore
                model="text-davinci-003",
                prompt=query,
                temperature=0.4,
                max_tokens=max_output_tokens,
                top_p=1,
            )
            text = resp.choices[0].text if resp and resp.choices else ""
            ida_kernwin.execute_sync(functools.partial(cb, response=text), ida_kernwin.MFF_WRITE)
            return

    except Exception as e:
        m = re.search(r"maximum context length is (\d+) tokens, .*\((\d+) in your prompt;", str(e))
        if m:
            hard_limit, prompt_tokens = int(m.group(1)), int(m.group(2))
            new_max = max(0, hard_limit - prompt_tokens)
            if new_max >= 300:
                print(f"Context length exceeded. Retrying with max_output_tokens={new_max}...")
                query_model(query, cb, max_output_tokens=new_max, model_name=model_name)
                return
            print("Function too large for current API limits.")
            return
        print(f"OpenAI request failed: {e}")

def query_model_async(query, cb):
    """
    Function which sends a query to GPT-5 and calls a callback when the response is available.
    :param query: The request to send to GPT-5
    :param cb: Tu function to which the response will be passed to.
    """
    print("Request to GPT-5 sent...")
    t = threading.Thread(target=query_model, args=[query, cb])
    t.start()

# ---- CWE Reference -----------------------------------------------------------
def get_cwe_details(cwe_id):
    """
    Fetch details about a CWE from the MITRE website
    :param cwe_id: The CWE ID (format: CWE-XXX)
    :return: Dictionary with details or None if not found
    """
    if not cwe_id or not cwe_id.startswith("CWE-"):
        return None

    try:
        cwe_number = cwe_id.split("-")[1]
        url = f"https://cwe.mitre.org/data/definitions/{cwe_number}.html"

        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'IDA Pro Plugin - VulChat CWE Reference Tool'
            }
        )

        with urllib.request.urlopen(req, timeout=5) as response:
            html = response.read().decode('utf-8')

            name_match = re.search(r'<h2>CWE-\d+: ([^<]+)</h2>', html)
            desc_match = re.search(r'<div class="indent" id="Description">([\s\S]*?)</div>', html)

            if name_match:
                name = name_match.group(1).strip()

                description = ""
                if desc_match:
                    description = desc_match.group(1).strip()
                    description = re.sub(r'<[^>]+>', '', description)
                    description = re.sub(r'\s+', ' ', description)
                    description = description.strip()

                return {
                    "id": cwe_id,
                    "name": name,
                    "description": description,
                    "url": url
                }
    except Exception as e:
        print(f"Error fetching CWE details for {cwe_id}: {str(e)}")

    return None

class CweInfoHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        cwe_id = ida_kernwin.ask_str("CWE-", 0, "Enter CWE ID (e.g., CWE-119)")
        if not cwe_id:
            return 1

        # Normalize format
        if not cwe_id.startswith("CWE-"):
            if cwe_id.isdigit():
                cwe_id = f"CWE-{cwe_id}"
            else:
                print("Invalid CWE ID format. Use CWE-XXX where XXX is a number.")
                return 1

        ida_kernwin.show_wait_box(f"Fetching information for {cwe_id}...")

        try:
            details = get_cwe_details(cwe_id)
            ida_kernwin.hide_wait_box()

            if details:
                info = f"{'='*80}\n"
                info += f"CWE ID: {details['id']}\n"
                info += f"Name: {details['name']}\n"
                info += f"{'='*80}\n\n"
                info += f"Description:\n{details['description']}\n\n"
                info += f"Reference: {details['url']}\n"
                info += f"{'='*80}"

                ida_kernwin.info(info)
            else:
                print(f"Could not find information for {cwe_id}")

        except Exception as e:
            ida_kernwin.hide_wait_box()
            print(f"Error: {str(e)}")

        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

# ---- Headless runner & PLUGIN_ENTRY -----------------------------------------
def run_headless(args):
    """Run in headless mode with command-line arguments"""
    print("[+] Running VulChatGPT in headless mode")
    print(f"[+] Arguments: {args}")

    # Make sure the decompiler is available
    if not ida_hexrays.init_hexrays_plugin():
        print("[-] Hex-Rays decompiler is not available. Exiting.")
        return

    if args.scan_all:
        print("[+] Starting vulnerability scan of all functions...")
        scan_handler = HeadlessScanHandler()
        scan_handler.batch_size = args.batch_size
        scan_handler.pause_seconds = args.function_pause
        scan_handler.batch_pause_seconds = args.batch_pause
        scan_handler.output_file = args.output
        scan_handler.run()

    elif args.decompile_all:
        print("[+] Starting decompilation of all functions...")
        decompile_handler = HeadlessDecompileHandler()
        decompile_handler.batch_size = args.batch_size
        decompile_handler.pause_seconds = args.function_pause
        decompile_handler.batch_pause_seconds = args.batch_pause

        # Set cache directory if specified (fixed to always assign)
        if args.cache_dir:
            try:
                os.makedirs(args.cache_dir, exist_ok=True)
            except Exception as e:
                print(f"[-] Could not create cache directory: {e}")
            decompile_handler.cache_dir = args.cache_dir

        decompile_handler.run()

    print("[+] Headless operation completed")

def PLUGIN_ENTRY():
    # Validate OpenAI configuration early to provide actionable message within IDA.
    if not _OPENAI_API_KEY and _OPENAI_SDK is not None:
        print("Set OPENAI_API_KEY in your environment before using VulChat.")

    # Check if we're running in headless mode and parse args
    args = parse_args()
    if IS_HEADLESS and args:
        # Wait for IDA's auto-analysis to finish
        idaapi.auto_wait()
        # Run our headless operations
        run_headless(args)
        # Quit IDA when done if we're in headless mode and ran an operation
        if args.scan_all or args.decompile_all:
            print("[+] Exiting IDA...")
            idaapi.qexit(0)
        return None

    return VulChatPlugin()
