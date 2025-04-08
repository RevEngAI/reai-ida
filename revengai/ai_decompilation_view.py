import idaapi
import ida_kernwin
import logging
import io

from tree_sitter import Language, Parser
import tree_sitter_c as language_c
import tree_sitter_cpp as language_cpp
from tree_sitter import Node

from pygments.lexers.c_cpp import CLexer, CppLexer
from pygments.token import Token, _TokenType
from pygments.formatter import Formatter
from pygments import highlight

logger = logging.getLogger("REAI")


def preprocess_code(code):
    """
    Preprocess code to fix broken strings across newlines and join adjacent
    strings

    Args:
        code (str): The code to preprocess

    Returns:
        str: The preprocessed code with fixed strings
    """
    # First, normalize line endings
    code = code.replace('\r\n', '\n')

    # Fix multiline strings and handle adjacent string literals
    lines = code.split('\n')
    processed_lines = []
    i = 0
    in_string = False
    current_string = ""

    # First pass: handle multiline strings
    while i < len(lines):
        line = lines[i]

        if not in_string:
            # Count unescaped quotes to see if we have an unclosed string
            j = 0
            while j < len(line):
                if line[j] == '"' and (j == 0 or line[j-1] != '\\'):
                    in_string = not in_string
                j += 1

            # If string is still open at end of line, save and continue
            if in_string:
                current_string = line
            else:
                processed_lines.append(line)
        else:
            # We're in the middle of a string that spans multiple lines
            # Remove leading whitespace from the line
            stripped_line = line.lstrip()

            # Add the line to our current string with a space instead of
            # newline
            current_string += " " + stripped_line

            # Check if the string closes on this line
            j = 0
            while j < len(stripped_line):
                if stripped_line[j] == '"' and \
                        (j == 0 or stripped_line[j-1] != '\\'):
                    in_string = not in_string
                j += 1

            # If string is now closed, add the complete string
            if not in_string:
                processed_lines.append(current_string)
                current_string = ""

        i += 1

    # Handle any unclosed string at the end
    if current_string:
        if in_string:
            # Close the string if it's still open
            processed_lines.append(current_string + '"')
        else:
            processed_lines.append(current_string)

    # Second pass: fix adjacent string literals separated by newlines
    i = 0
    final_lines = []

    while i < len(processed_lines):
        current_line = processed_lines[i]

        # Check if this line ends with a string or a comma followed by a string
        if '"' in current_line:
            # Find the last quote in the line
            last_quote = current_line.rfind('"')

            # Make sure it's actually the end of a string (not escaped)
            if last_quote > 0 and current_line[last_quote-1] != '\\':
                # Check if there's a next line that starts with a string
                if i + 1 < len(processed_lines):
                    next_line = processed_lines[i+1].lstrip()
                    if next_line and next_line[0] == '"':
                        # Check if we need a comma or if there's already one
                        if current_line.rstrip().endswith('"'):
                            # No comma at the end, add one
                            final_lines.append(current_line + ", " + next_line)
                        elif current_line.rstrip().endswith(','):
                            # Already has a comma, just add with a space
                            final_lines.append(current_line + " " + next_line)
                        else:
                            # There's something else between the string and
                            #  the end of line
                            final_lines.append(current_line)
                            final_lines.append(next_line)
                        i += 2  # Skip the next line since we've processed it
                        continue

        # Normal line handling
        final_lines.append(current_line)
        i += 1

    return '\n'.join(final_lines)


class TreeSitterCodeHighlighter:
    """
    A syntax highlighter using Tree-sitter for more accurate parsing
    """

    def __init__(self):
        self.parser = None
        self.parser_c = None
        self.parser_cpp = None
        self.initialized = False
        if self._initialize_treesitter():
            logger.info("Tree-sitter initialized successfully")
            self.initialized = True

    def _initialize_treesitter(self):
        """Initialize the Tree-sitter parser and languages"""
        try:
            self.c_language = Language(language_c.language())
            self.cpp_language = Language(language_cpp.language())
            self.parser_c = Parser(self.c_language)
            self.parser_cpp = Parser(self.cpp_language)
            return True
        except Exception as e:
            logger.error(f"Error initializing tree-sitter: {e}")
            return False

    def highlight_code(self, code, language=None) -> str:
        """
        Highlight code using Tree-sitter

        Args:
            code (str): The code to highlight
            language (str, optional): 'c', 'cpp', or None (auto-detect)

        Returns:
            str: The highlighted code with IDA color tags
        """
        if not self.initialized:
            logger.error("Tree-sitter not initialized")
            return ""

        # Preprocess the code
        # code = preprocess_code(code)

        # Set language
        if language == 'c':
            parser = self.parser_c
        elif language == 'cpp':
            parser = self.parser_cpp
        elif language is None:
            # Auto-detect based on content
            cpp_indicators = ['class ', 'namespace ', 'template<', '::',
                              'new ', 'delete ', 'public:', 'private:',
                              'protected:', 'virtual ', 'std::']
            is_cpp = any(indicator in code for indicator in cpp_indicators)

            parser = self.parser_cpp if is_cpp else self.parser_c

        # Parse the code
        try:
            tree = parser.parse(bytes(code, 'utf8'))
            root_node = tree.root_node

            # Create a list of highlighted tokens with their positions
            highlighted_segments = []
            self._collect_highlighted_segments(
                code, root_node, highlighted_segments)

            # Reconstruct the code preserving original whitespace and line
            # breaks
            return self._reconstruct_code(code, highlighted_segments)
        except Exception as e:
            logger.error(f"Error parsing with tree-sitter: {e}")
            return ""

    def _collect_highlighted_segments(self, code, node, segments):
        """
        Recursively collect segments of code with their highlighting
        information

        Args:
            code (str): The original code
            node (Node): The tree-sitter node to process
            segments (list): List to collect the segments
        """
        # If this is a leaf node, add it to our segments
        if node.child_count == 0:
            node_text = code[node.start_byte:node.end_byte]
            node_type = node.type

            # Skip if the node is empty
            if not node_text:
                return

            # Map tree-sitter node types to IDA colors
            ida_color = self._get_ida_color_for_node_type(node_type)

            # Add this segment with its position information
            segments.append({
                'start': node.start_byte,
                'end': node.end_byte,
                'text': node_text,
                'color': ida_color
            })
        else:
            # Process children
            for child in node.children:
                self._collect_highlighted_segments(code, child, segments)

    def _reconstruct_code(self, original_code, segments):
        """
        Reconstruct the code preserving original formatting but with
        highlighting

        Args:
            original_code (str): The original code
            segments (list): List of highlighted segments

        Returns:
            str: The highlighted code with IDA color tags
        """
        # Sort segments by start position
        segments.sort(key=lambda x: x['start'])

        result = ""
        last_end = 0

        for segment in segments:
            # Add any text between the last segment and this one
            # (preserves whitespace)
            if segment['start'] > last_end:
                result += original_code[last_end:segment['start']]

            # Add the highlighted segment
            if segment['color'] != idaapi.SCOLOR_DEFAULT:
                result += idaapi.COLSTR(segment['text'], segment['color'])
            else:
                result += segment['text']

            last_end = segment['end']

        # Add any remaining text after the last segment
        if last_end < len(original_code):
            result += original_code[last_end:]

        return result

    def _get_ida_color_for_node_type(self, node_type: Node):
        """
        Map tree-sitter node types to IDA colors

        Args:
            node_type (str): The tree-sitter node type

        Returns:
            int: The IDA color constant
        """
        # Map common tree-sitter node types to IDA colors
        node_type_map = {
            # Keywords
            'if': idaapi.SCOLOR_INSN,
            'else': idaapi.SCOLOR_INSN,
            'for': idaapi.SCOLOR_INSN,
            'while': idaapi.SCOLOR_INSN,
            'return': idaapi.SCOLOR_INSN,
            'break': idaapi.SCOLOR_INSN,
            'continue': idaapi.SCOLOR_INSN,
            'switch': idaapi.SCOLOR_INSN,
            'case': idaapi.SCOLOR_INSN,
            'default': idaapi.SCOLOR_INSN,
            'goto': idaapi.SCOLOR_INSN,
            'sizeof': idaapi.SCOLOR_INSN,
            'typedef': idaapi.SCOLOR_INSN,
            'struct': idaapi.SCOLOR_INSN,
            'enum': idaapi.SCOLOR_INSN,
            'union': idaapi.SCOLOR_INSN,
            'class': idaapi.SCOLOR_INSN,
            'namespace': idaapi.SCOLOR_INSN,
            'public': idaapi.SCOLOR_INSN,
            'private': idaapi.SCOLOR_INSN,
            'protected': idaapi.SCOLOR_INSN,
            'template': idaapi.SCOLOR_INSN,
            'typename': idaapi.SCOLOR_INSN,
            'const': idaapi.SCOLOR_INSN,
            'static': idaapi.SCOLOR_INSN,
            'volatile': idaapi.SCOLOR_INSN,
            'extern': idaapi.SCOLOR_INSN,
            'register': idaapi.SCOLOR_INSN,
            'auto': idaapi.SCOLOR_INSN,
            'inline': idaapi.SCOLOR_INSN,
            'virtual': idaapi.SCOLOR_INSN,

            # Type names  use a light blue color for type names
            'primitive_type': idaapi.SCOLOR_REG,
            'type_identifier': idaapi.SCOLOR_REG,

            # Function names
            'function_declarator': idaapi.SCOLOR_DNAME,
            'function_definition': idaapi.SCOLOR_DNAME,
            'call_expression': idaapi.SCOLOR_DNAME,
            # This seems to be used in some tree-sitter versions
            'function_call': idaapi.SCOLOR_DNAME,

            # Variables and identifiers
            'identifier': idaapi.SCOLOR_DNAME,

            # String literals
            'string_literal': idaapi.SCOLOR_STRING,
            'raw_string_literal': idaapi.SCOLOR_STRING,
            'string_content': idaapi.SCOLOR_STRING,
            'escape_sequence': idaapi.SCOLOR_STRING,

            # Numeric literals
            'number_literal': idaapi.SCOLOR_NUMBER,
            'integer_literal': idaapi.SCOLOR_NUMBER,
            'float_literal': idaapi.SCOLOR_NUMBER,
            'hex_literal': idaapi.SCOLOR_NUMBER,
            'octal_literal': idaapi.SCOLOR_NUMBER,
            'binary_literal': idaapi.SCOLOR_NUMBER,

            # Comments
            'comment': idaapi.SCOLOR_RPTCMT,
            'line_comment': idaapi.SCOLOR_RPTCMT,
            'block_comment': idaapi.SCOLOR_RPTCMT,
            'comment_content': idaapi.SCOLOR_RPTCMT,

            # Operators and symbols
            'operator': idaapi.SCOLOR_SYMBOL,
            'field_expression': idaapi.SCOLOR_SYMBOL,
            'pointer_expression': idaapi.SCOLOR_SYMBOL,
            'binary_expression': idaapi.SCOLOR_SYMBOL,
            'unary_expression': idaapi.SCOLOR_SYMBOL,
            '*': idaapi.SCOLOR_SYMBOL,
            '&': idaapi.SCOLOR_SYMBOL,
            '+': idaapi.SCOLOR_SYMBOL,
            '-': idaapi.SCOLOR_SYMBOL,
            '/': idaapi.SCOLOR_SYMBOL,
            '%': idaapi.SCOLOR_SYMBOL,
            '=': idaapi.SCOLOR_SYMBOL,
            '<': idaapi.SCOLOR_SYMBOL,
            '>': idaapi.SCOLOR_SYMBOL,
            '!': idaapi.SCOLOR_SYMBOL,
            '~': idaapi.SCOLOR_SYMBOL,
            '|': idaapi.SCOLOR_SYMBOL,
            '^': idaapi.SCOLOR_SYMBOL,
            '(': idaapi.SCOLOR_SYMBOL,
            ')': idaapi.SCOLOR_SYMBOL,
            '[': idaapi.SCOLOR_SYMBOL,
            ']': idaapi.SCOLOR_SYMBOL,
            '{': idaapi.SCOLOR_SYMBOL,
            '}': idaapi.SCOLOR_SYMBOL,
            '.': idaapi.SCOLOR_SYMBOL,
            ',': idaapi.SCOLOR_SYMBOL,
            ';': idaapi.SCOLOR_SYMBOL,
            ':': idaapi.SCOLOR_SYMBOL,
            '?': idaapi.SCOLOR_SYMBOL,

            'NULL': idaapi.SCOLOR_MACRO,
        }

        return node_type_map.get(node_type, idaapi.SCOLOR_DEFAULT)


class PygmentsIDAColorFormatter(Formatter):
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
            Token.Literal.Number.Integer: idaapi.SCOLOR_NUMBER,
            Token.Literal.String: idaapi.SCOLOR_STRING,
            Token.Comment: idaapi.SCOLOR_RPTCMT,
            Token.Comment.Single: idaapi.SCOLOR_RPTCMT,
            Token.Comment.Multiline: idaapi.SCOLOR_RPTCMT,
            Token.Operator: idaapi.SCOLOR_SYMBOL,
            Token.Punctuation: idaapi.SCOLOR_SYMBOL,
            Token.Name: idaapi.SCOLOR_DNAME,
            Token.Text: idaapi.SCOLOR_DEFAULT,
            Token.Text.Operator: idaapi.SCOLOR_DEFAULT,
            Token.Text.Whitespace: idaapi.SCOLOR_DEFAULT,
        }

    def _find_closest_token_color(self, token_type: _TokenType):
        """
        Find the closest matching token type in our map.
        Walks up the token hierarchy to find a match.
        """
        if True:
            pass
        while token_type is not Token:
            if token_type in self.styles:
                col = self.styles[token_type]
                return col
            # Go up one level in the token hierarchy
            token_type = token_type.parent
        return idaapi.SCOLOR_DEFAULT

    def format(self, tokensource, outfile):
        """Format tokens to IDA colored text"""
        result = ""

        for token_type, token_value in tokensource:
            # Skip empty tokens
            if not token_value:
                continue

            # Find the best matching token type in our map
            ida_color = self._find_closest_token_color(token_type)

            # Add the colored text to the result
            if ida_color != idaapi.SCOLOR_DEFAULT:
                result += idaapi.COLSTR(token_value, ida_color)
            else:
                result += token_value

        outfile.write(result)


class PygmentsCodeHighlighter:
    """
    A syntax highlighter that can handle both C and C++ code
    """

    def __init__(self):
        self.c_lexer = CLexer()
        self.cpp_lexer = CppLexer()

    def highlight_code(self, code, language: str | None = None) -> str:
        """
        Highlight the given code and return the lines with IDA color tags

        Args:
            code (str): The code to highlight
            language (str, optional): 'c', 'cpp', or None (auto-detect)

        Returns:
            list: The highlighted lines
        """

        code = preprocess_code(code)  # Preprocess the code

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

        output = io.StringIO()

        highlight(
            code,
            lexer,
            PygmentsIDAColorFormatter(),
            output
        )

        # logger.info(f"Highlighted code: {code_highlighted}")

        return output.getvalue()


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
        self.highlighter = TreeSitterCodeHighlighter()
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
            language (str, optional): 'c', 'cpp', or None (use class setting)
        """
        self.ClearLines()
        self.current_code = code  # Save for language switching

        # Use language setting if provided, otherwise use the class setting
        lang = language if language is not None else self.language

        # Get the highlighted code with IDA color tags
        highlighted_code = self.highlighter.highlight_code(code, lang)

        # Split only on actual newlines, not on IDA color escape sequences
        # This is the key fix to prevent incorrect line splitting

        # First, find all real newlines that aren't inside color tags
        # We're looking for literal \n characters, not inside the COLSTR
        # control sequences
        line_positions = []
        i = 0
        inside_color_tag = False

        while i < len(highlighted_code):
            # Check for start of color tag (SCOLOR_xxx)
            if highlighted_code[i] == idaapi.COLOR_ON:
                inside_color_tag = True
            # Check for end of color tag
            elif highlighted_code[i] == idaapi.COLOR_OFF:
                inside_color_tag = False
            # Only consider newlines outside of color tags
            elif highlighted_code[i] == '\n' and not inside_color_tag:
                line_positions.append(i)
            i += 1

        # Now split the text at these positions
        last_pos = 0
        lines = []
        for pos in line_positions:
            lines.append(highlighted_code[last_pos:pos])
            last_pos = pos + 1  # Skip the newline character

        # Add the last part
        if last_pos < len(highlighted_code):
            lines.append(highlighted_code[last_pos:])

        # Add each line to the IDA viewer
        for line in lines:
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
