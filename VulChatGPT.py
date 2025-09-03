import functools
import json
import os
import re
import textwrap
import threading

import idaapi
import ida_hexrays
import ida_kernwin
import idc

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


class VulChatPlugin(idaapi.plugin_t):
    flags = 0
    wanted_name = "VulChat"
    wanted_hotkey = ""
    comment = "Uses GPT-5 to analyze the decompiler's output"
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

    menu = None

    def init(self):
        # Ensure decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        # Register actions (IDA 9 uses ida_kernwin.action_desc_t)
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
        except Exception:
            pass
        if self.menu:
            self.menu.unhook()


class ContextMenuHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        if ida_kernwin.get_widget_type(form) == ida_kernwin.BWN_PSEUDOCODE:
            ida_kernwin.attach_action_to_popup(form, popup, VulChatPlugin.vuln_action_name, "VulChat/")
            ida_kernwin.attach_action_to_popup(form, popup, VulChatPlugin.expl_action_name, "VulChat/Safe_Tests")
            ida_kernwin.attach_action_to_popup(form, popup, VulChatPlugin.explain_action_name, "VulChat/Explain")
            ida_kernwin.attach_action_to_popup(form, popup, VulChatPlugin.rename_action_name, "VulChat/Rename_Vars")


# ----- Helpers ---------------------------------------------------------------

def comment_callback(address, view, response):
    # Wrap lines for readability
    response = "\n".join(textwrap.wrap(response or "", 80, replace_whitespace=False))
    idc.set_func_cmt(address, response, 0)
    if view:
        view.refresh_view(False)
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
        if ida_hexrays.rename_lvar(function_addr, n, names[n]):
            replaced.append(n)

    # Update function comment occurrences
    comment = idc.get_func_cmt(address, 0)
    if comment and replaced:
        for n in replaced:
            comment = re.sub(r"\b%s\b" % re.escape(n), names[n], comment)
        idc.set_func_cmt(address, comment, 0)

    if view:
        view.refresh_view(True)
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
        query_model_async(
            "Can you find potential vulnerabilities in the following C function and suggest mitigations?\n"
            + str(decompiler_output),
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


# ---- OpenAI integration -----------------------------------------------------

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
                        {"role": "system", "content": "You are a helpful, concise assistant for reverse engineering and secure code review. Avoid unsafe instructions."},
                        {"role": "user", "content": query},
                    ],
                    temperature=0.4,
                    max_tokens=max_output_tokens,
                )
                text = resp.choices[0].message.content if resp.choices else ""
            except Exception:
                resp = client.responses.create(  # type: ignore
                    model=model_name,
                    input=query,
                    temperature=0.4,
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


# Entry point ---------------------------------------------------------------

def PLUGIN_ENTRY():
    # Validate OpenAI configuration early to provide actionable message within IDA.
    if not _OPENAI_API_KEY and _OPENAI_SDK is not None:
        print("Set OPENAI_API_KEY in your environment before using VulChat.")

    return VulChatPlugin()
