import idaapi
import ida_kernwin
from pygments.lexers.c_cpp import CLexer, CppLexer
from pygments.token import Token
from pygments.formatter import Formatter
from pygments import highlight
import logging
from io import StringIO

logger = logging.getLogger("REAI")


class IDAColorFormatter(Formatter):
    """
    Custom Pygments formatter that outputs IDA Pro color tags
    """
    def __init__(self, **options):
        Formatter.__init__(self, **options)

        # Map token types to IDA colors
        self.styles = {
            Token.Keyword: idaapi.SCOLOR_KEYWORD,
            Token.Keyword.Type: idaapi.SCOLOR_KEYWORD,
            Token.Name.Function: idaapi.SCOLOR_DNAME,
            Token.Name.Class: idaapi.SCOLOR_DNAME,
            Token.Name.Namespace: idaapi.SCOLOR_KEYWORD,
            Token.Name.Builtin: idaapi.SCOLOR_DNAME,
            Token.Literal.Number: idaapi.SCOLOR_NUMBER,
            Token.Literal.String: idaapi.SCOLOR_STRING,
            Token.Comment: idaapi.SCOLOR_RPTCMT,
            Token.Comment.Single: idaapi.SCOLOR_RPTCMT,
            Token.Comment.Multiline: idaapi.SCOLOR_RPTCMT,
            Token.Operator: idaapi.SCOLOR_SYMBOL,
            Token.Punctuation: idaapi.SCOLOR_SYMBOL,
        }

    def format(self, tokensource, outfile):
        """Format tokens to IDA colored text"""
        current_line = ""

        for ttype, value in tokensource:
            # Find the closest matching token type
            ida_color = None
            token_type = ttype

            while token_type is not Token and ida_color is None:
                if token_type in self.styles:
                    ida_color = self.styles[token_type]
                token_type = token_type.parent

            # Apply IDA color if found
            if ida_color is not None:
                current_line += chr(ida_color) + value + idaapi.SCOLOR_OFF
            else:
                current_line += value

            # Check for line breaks
            if '\n' in value:
                parts = value.split('\n')
                for i, part in enumerate(parts):
                    if i < len(parts) - 1:
                        # Write completed line
                        outfile.write(
                            current_line[:current_line.rfind(part) + len(part)]
                        )
                        outfile.write('\n')
                        current_line = ""

        # Write any remaining content
        if current_line:
            outfile.write(current_line)


class FlexibleCodeHighlighter:
    """
    A syntax highlighter that can handle both C and C++ code
    """
    def __init__(self):
        self.c_lexer = CLexer()
        self.cpp_lexer = CppLexer()

    def highlight_code(self, code, language: str | None = None):
        """
        Highlight the given code and return the lines with IDA color tags

        Args:
            code (str): The code to highlight
            language (str, optional): 'c', 'cpp', or None (auto-detect)

        Returns:
            list: The highlighted lines
        """
        if language is None:
            language = "c"  # Default to C if not specified

            cpp_indicators = ['class ', 'namespace ', 'template<', '::',
                              'new ', 'delete ', 'public:', 'private:',
                              'protected:', 'virtual ', 'std::']

            is_cpp = any(indicator in code for indicator in cpp_indicators)
            if is_cpp:
                language = "cpp"

        # logger.info(f"Formatted code: \n{formatted_code}")

        match language:
            case "c":
                lexer = self.c_lexer
            case "cpp":
                lexer = self.cpp_lexer
            case _:
                # Default to C if language is not specified
                lexer = self.c_lexer

        output = StringIO()

        highlight(
            code,
            lexer,
            IDAColorFormatter(),
            output=output
        )

        # logger.info(f"Highlighted code: {code_highlighted}")

        return output.getvalue().splitlines()


# Define the action handlers for the popup menu
class SwitchToCAction(ida_kernwin.action_handler_t):
    def __init__(self, viewer):
        ida_kernwin.action_handler_t.__init__(self)
        self.viewer = viewer

    def activate(self, ctx):
        self.viewer.switch_language('c')
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class SwitchToCppAction(ida_kernwin.action_handler_t):
    def __init__(self, viewer):
        ida_kernwin.action_handler_t.__init__(self)
        self.viewer = viewer

    def activate(self, ctx):
        self.viewer.switch_language('cpp')
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class AICodeViewer(idaapi.simplecustviewer_t):
    """
    A custom viewer that provides syntax highlighting for both C and C++ code
    """
    def __init__(self):
        idaapi.simplecustviewer_t.__init__(self)
        self.raw_lines = []
        self.highlighter = FlexibleCodeHighlighter()
        self.language = None  # Will be auto-detected
        self.current_code = ""

    def Create(self, title):
        """Create the custom view with the given title"""
        if not idaapi.simplecustviewer_t.Create(self, title):
            return False

        # Register actions for the popup menu
        self.register_actions()

        # Attach popup menu to the viewer
        self.hook = self.ViewHooks(self)
        self.hook.hook()

        return True

    def register_actions(self):
        """Register actions for the popup menu"""
        # Switch to C action
        self.c_action_name = "aic_switch_to_c"
        self.c_action_desc = ida_kernwin.action_desc_t(
            self.c_action_name,           # Action name
            "Switch to C syntax",         # Action text
            SwitchToCAction(self),        # Handler
            None,                         # Shortcut
            "Switch to C syntax highlighting",  # Tooltip
            -1                            # Icon
        )
        ida_kernwin.register_action(self.c_action_desc)

        # Switch to C++ action
        self.cpp_action_name = "aic_switch_to_cpp"
        self.cpp_action_desc = ida_kernwin.action_desc_t(
            self.cpp_action_name,         # Action name
            "Switch to C++ syntax",       # Action text
            SwitchToCppAction(self),      # Handler
            None,                         # Shortcut
            "Switch to C++ syntax highlighting",  # Tooltip
            -1                            # Icon
        )
        ida_kernwin.register_action(self.cpp_action_desc)

    def unregister_actions(self):
        """Unregister the actions"""
        ida_kernwin.unregister_action(self.c_action_name)
        ida_kernwin.unregister_action(self.cpp_action_name)

    def switch_language(self, language):
        """Switch to the specified language"""
        self.language = language
        if self.current_code:
            self.set_code(self.current_code, self.language)

    def set_code(self, code, language=None):
        """
        Set and highlight the code to be displayed

        Args:
            code (str): The code to display
            language (str, optional): 'c', 'cpp', or None (auto-detect)
        """
        self.ClearLines()
        self.current_code = code  # Save for language switching
        self.raw_lines = code.split("\n")

        # Use language setting if provided, otherwise use the class setting or
        # auto-detect
        lang = language if language else self.language

        # Use the highlighter to get highlighted lines
        highlighted_lines = self.highlighter.highlight_code(code, lang)

        # Add each highlighted line to the viewer
        for line in highlighted_lines:
            self.AddLine(line)

        self.Refresh()

    def OnClose(self):
        """Called when view is closed"""
        # Clean up actions
        self.unregister_actions()
        if hasattr(self, 'hook') and self.hook:
            self.hook.unhook()
        return True

    class ViewHooks(ida_kernwin.UI_Hooks):
        """Hooks for the custom viewer to handle popup menu"""
        def __init__(self, viewer):
            ida_kernwin.UI_Hooks.__init__(self)
            self.viewer = viewer

        def populating_widget_popup(self, widget, popup):
            """Called when a popup menu is about to be shown"""
            if self.viewer.GetWidget() == widget:
                # Add our actions to the popup menu
                ida_kernwin.attach_action_to_popup(
                    widget,
                    popup,
                    self.viewer.c_action_name,
                    "Language/"
                )
                ida_kernwin.attach_action_to_popup(
                    widget,
                    popup,
                    self.viewer.cpp_action_name,
                    "Language/"
                )
                return 1
            return 0
