import functools
import json
import idaapi
import ida_hexrays
import ida_kernwin
import idc
import openai
import os
import re
import textwrap
import threading

# Set your API key here, or put in in the OPENAI_API_KEY environment variable.
openai.api_key = "ENTER_OPEN_API_KEY_HERE"

# =============================================================================
# Setup the context menu and hotkey in IDA
# =============================================================================

class VulChatPlugin(idaapi.plugin_t):
    flags = 0
    
    vuln_action_name = "vulchat:vuln_function"
    vuln_menu_path = "Edit/VulChat/Find Possible Vulnerability"
    wanted_name = 'VulChat'
    wanted_hotkey = ''
    comment = "Uses davinci-003 to find vulnerabilites the decompiler's output"
    help = "See usage instructions on GitHub"
    menu = None

    def init(self):
        # Check whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        #Function vulnerability Checker
        vuln_action = idaapi.action_desc_t(self.vuln_action_name,
                                           'Find possible vulnerability in function',
                                           VulnHandler(),
                                           "Ctrl+Alt+V",
                                           "Use davinci-003 to find possible vulnerability in decompiled function",
                                           199)
        idaapi.register_action(vuln_action)
        idaapi.attach_action_to_menu(self.vuln_menu_path, self.vuln_action_name, idaapi.SETMENU_APP)

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.vuln_menu_path, self.vuln_action_name)
        if self.menu:
            self.menu.unhook()
        return

# -----------------------------------------------------------------------------

class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, VulChatPlugin.vuln_action_name, "VulChat/")

# -----------------------------------------------------------------------------

def comment_callback(address, view, response):
    """
    Callback that sets a comment at the given address.
    :param address: The address of the function to comment
    :param view: A handle to the decompiler window
    :param response: The comment to add
    """
    # Add newlines at the end of each sentence.
    response = "\n".join(textwrap.wrap(response, 80, replace_whitespace=False))

    # Add the response as a comment in IDA.
    idc.set_func_cmt(address, response, 0)
    # Refresh the window so the comment is displayed properly
    if view:
        view.refresh_view(False)
    print("davinci-003 query finished!")

# -----------------------------------------------------------------------------
class VulnHandler(idaapi.action_handler_t):
    """
    This handler is tasked with querying davinci-003 for a possible check of vulneranilities on a given function.
    Once the reply is received its added to the function as a comment.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async("Can you find the vulnerabilty in the following C function and suggest the possible way to exploit it?\n"
        + str(decompiler_output),
        functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# =============================================================================
# davinci-003 interaction
# =============================================================================

def query_model(query, cb):
    """
    Function which sends a query to davinci-003 and calls a callback when the response is available.
    Blocks until the response is received
    :param query: The request to send to davinci-003
    :param cb: Tu function to which the response will be passed to.
    """
    try:
        response = openai.Completion.create(
            model="text-davinci-003",
            prompt=query,
            temperature=0.6,
            max_tokens=2500,
            top_p=1,
            frequency_penalty=1,
            presence_penalty=1,
            timeout=60  # Wait 60 seconds maximum
        )
        ida_kernwin.execute_sync(functools.partial(cb, response=response.choices[0].text), ida_kernwin.MFF_WRITE)
    except openai.OpenAIError as e:
        print(f"davinci-003 could not complete the request: {str(e)}")
    except Exception as e:
        print(f"General exception encountered while running the query: {str(e)}")

# -----------------------------------------------------------------------------

def query_model_async(query, cb):
    """
    Function which sends a query to davinci-003 and calls a callback when the response is available.
    :param query: The request to send to davinci-003
    :param cb: Tu function to which the response will be passed to.
    """
    print("Request to davinci-003 sent...")
    t = threading.Thread(target=query_model, args=[query, cb])
    t.start()

# =============================================================================
# Main
# =============================================================================

def PLUGIN_ENTRY():
    if not openai.api_key:
        openai.api_key = os.getenv("OPENAI_API_KEY")
        if not openai.api_key:
            print("Please edit this script to insert your OpenAI API key!")
            raise ValueError("No valid OpenAI API key found")

    return VulChatPlugin()
