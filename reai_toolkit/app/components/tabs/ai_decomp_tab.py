from pathlib import Path
from typing import Any, Callable, Optional
from loguru import logger

import ida_kernwin as kw
from libbs.decompilers.ida.compat import execute_ui

from reai_toolkit.app.core.qt_compat import QtCore, QtGui, QtWidgets, Signal


_WORD_UNDER_CURSOR = getattr(
    getattr(QtGui.QTextCursor, "SelectionType", QtGui.QTextCursor), "WordUnderCursor"
)


def _thumb_icon(up: bool) -> Optional[QtGui.QIcon]:
    stem = "thumb_up" if up else "thumb_down"
    for ext in (".svg", ".png"):
        path = Path(__file__).resolve().parent.parent / "resources" / (stem + ext)
        if path.exists():
            icon = QtGui.QIcon(str(path))
            if not icon.isNull():
                return icon
    return None


def _menu_exec(menu, pos):
    fn = getattr(menu, "exec_", None) or getattr(menu, "exec")
    return fn(pos)


class _DecompEditor(QtWidgets.QPlainTextEdit):
    renameRequested = Signal(int, str)
    commentEditRequested = Signal(int)
    commentRemoveRequested = Signal(int)

    def mouseDoubleClickEvent(self, event) -> None:
        super().mouseDoubleClickEvent(event)
        cursor = self.textCursor()
        word = cursor.selectedText()
        if word:
            self.renameRequested.emit(cursor.blockNumber(), word)

    def contextMenuEvent(self, event) -> None:
        cursor = self.cursorForPosition(event.pos())
        line = cursor.blockNumber()
        cursor.select(_WORD_UNDER_CURSOR)
        word = cursor.selectedText()

        menu = self.createStandardContextMenu()
        menu.addSeparator()
        act_rename = menu.addAction(f"Rename '{word}'…") if word else None
        act_comment = menu.addAction("Add / edit comment…")
        act_remove = menu.addAction("Remove comment")

        chosen = _menu_exec(menu, event.globalPos())
        if chosen is None:
            return
        if act_rename is not None and chosen == act_rename:
            self.renameRequested.emit(line, word)
        elif chosen == act_comment:
            self.commentEditRequested.emit(line)
        elif chosen == act_remove:
            self.commentRemoveRequested.emit(line)


class AIDecompView(kw.PluginForm):
    """
    Dockable tab using Qt editor + QSyntaxHighlighter.
    API kept compatible with your previous simplecustviewer_t:
      - Create(title)    -> shows the form
      - set_code(text)   -> updates text (UI-thread safe)
      - focus()          -> activates the tab
      - OnClose()        -> calls on_closed callback
    """

    TITLE = "RevEng.AI — Decompiled View"

    def __init__(self, on_closed: Optional[Callable[[], None]] = None) -> None:
        super().__init__()
        self._on_closed: Callable[[], None] | None = on_closed
        self.on_refresh: Callable[[], None] | None = None
        self.on_rename: Callable[[int, str], None] | None = None
        self.on_edit_comment: Callable[[int], None] | None = None
        self.on_remove_comment: Callable[[int], None] | None = None
        self.on_rate_up: Callable[[], None] | None = None
        self.on_rate_down: Callable[[], None] | None = None
        self._parent_window: QtWidgets.QWidget | None = None
        self._editor: _DecompEditor | None = None
        self._refresh_btn: QtWidgets.QPushButton | None = None
        self._rate_up_btn: QtWidgets.QPushButton | None = None
        self._rate_down_btn: QtWidgets.QPushButton | None = None
        self._highlighter: CppHighlighter | None = None

    def Create(self, title: Any) -> Any:
        """Compatibility shim: show the PluginForm like your previous Create()."""
        flags = getattr(kw.PluginForm, "WOPN_DP_TAB", 0) | getattr(
            kw.PluginForm, "WOPN_RESTORE", 0
        )
        ok = self.Show(str(title) if title else self.TITLE, flags)
        if not ok:
            logger.error("Failed to show AI Decompiler tab")
        else:
            # Try docking near Hex-Rays
            try:
                kw.set_dock_pos(
                    str(title) if title else self.TITLE, "Pseudocode-A", kw.DP_RIGHT
                )
            except Exception:
                pass
        return ok

    def OnCreate(self, form) -> None:
        """Called by IDA when the form is created; build our Qt UI here."""
        self._parent_window = self.FormToPyQtWidget(form)

        # Layout root
        layout = QtWidgets.QVBoxLayout(self._parent_window)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header
        header = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("RevEng.AI — AI Decomp", self._parent_window)
        header.addWidget(title)
        header.addStretch(1)

        up_icon = _thumb_icon(up=True)
        self._rate_up_btn = QtWidgets.QPushButton(self._parent_window)
        if up_icon is not None:
            self._rate_up_btn.setIcon(up_icon)
            self._rate_up_btn.setIconSize(QtCore.QSize(16, 16))
        else:
            self._rate_up_btn.setText("\U0001f44d")
        self._rate_up_btn.setCheckable(True)
        self._rate_up_btn.setToolTip("Rate this AI decompilation as good")
        self._rate_up_btn.clicked.connect(self._on_rate_up_clicked)
        header.addWidget(self._rate_up_btn)

        down_icon = _thumb_icon(up=False)
        self._rate_down_btn = QtWidgets.QPushButton(self._parent_window)
        if down_icon is not None:
            self._rate_down_btn.setIcon(down_icon)
            self._rate_down_btn.setIconSize(QtCore.QSize(16, 16))
        else:
            self._rate_down_btn.setText("\U0001f44e")
        self._rate_down_btn.setCheckable(True)
        self._rate_down_btn.setToolTip("Rate this AI decompilation as poor")
        self._rate_down_btn.clicked.connect(self._on_rate_down_clicked)
        header.addWidget(self._rate_down_btn)

        self._refresh_btn = QtWidgets.QPushButton("Refresh", self._parent_window)
        self._refresh_btn.clicked.connect(self._on_refresh_clicked)
        header.addWidget(self._refresh_btn)
        layout.addLayout(header)

        # Editor
        self._editor = _DecompEditor(self._parent_window)
        self._editor.setReadOnly(True)
        self._editor.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)
        self._editor.renameRequested.connect(self._on_rename_requested)
        self._editor.commentEditRequested.connect(self._on_edit_comment_requested)
        self._editor.commentRemoveRequested.connect(self._on_remove_comment_requested)

        # Monospace font tuned for IDA
        font = QtGui.QFont(
            "Menlo"
            if QtCore.QOperatingSystemVersion.currentType()
            == QtCore.QOperatingSystemVersion.OSType.MacOS
            else "Consolas"
        )
        font.setStyleHint(QtGui.QFont.Monospace)
        font.setFixedPitch(True)
        font.setPointSize(11)
        self._editor.setFont(font)

        layout.addWidget(self._editor)

        # Highlighter
        self._highlighter = CppHighlighter(self._editor.document())

    def OnClose(self, form) -> None:
        """Called when the user closes the tab."""
        if callable(self._on_closed):
            try:
                self._on_closed()
            except Exception as e:
                logger.warning(f"on_closed callback failed: {e}")
        self._highlighter = None
        self._editor = None
        self._refresh_btn = None
        self._rate_up_btn = None
        self._rate_down_btn = None
        self._parent_window = None

    def _on_refresh_clicked(self) -> None:
        if self.on_refresh:
            self.on_refresh()

    def _on_rate_up_clicked(self) -> None:
        self.set_rating("up")
        if self.on_rate_up:
            self.on_rate_up()

    def _on_rate_down_clicked(self) -> None:
        self.set_rating("down")
        if self.on_rate_down:
            self.on_rate_down()

    @execute_ui
    def set_rating(self, rating: Optional[str]) -> None:
        if self._rate_up_btn:
            self._rate_up_btn.setChecked(rating == "up")
        if self._rate_down_btn:
            self._rate_down_btn.setChecked(rating == "down")

    def _on_rename_requested(self, line: int, word: str) -> None:
        if self.on_rename:
            self.on_rename(line, word)

    def _on_edit_comment_requested(self, line: int) -> None:
        if self.on_edit_comment:
            self.on_edit_comment(line)

    def _on_remove_comment_requested(self, line: int) -> None:
        if self.on_remove_comment:
            self.on_remove_comment(line)

    # --- public API ------------------------------------------------
    @execute_ui
    def update_view_content(self, code: str, follow_tail: bool = False) -> None:
        if not self._editor:
            return

        self._editor.blockSignals(True)
        try:
            self._editor.setPlainText(code)
            if follow_tail:
                bar = self._editor.verticalScrollBar()
                bar.setValue(bar.maximum())
        finally:
            self._editor.blockSignals(False)

    def clear(self) -> None:
        self.update_view_content("")

    def focus(self) -> None:
        if self._parent_window:
            try:
                kw.activate_widget(self._parent_window, True)
            except Exception:
                pass


# -----------------------------
# Rich C/C++-style highlighter
# -----------------------------
class CppHighlighter(QtGui.QSyntaxHighlighter):
    def __init__(self, parent_doc: QtGui.QTextDocument) -> None:
        super().__init__(parent_doc)

        self.fmt_kw: QtGui.QTextCharFormat = self._fmt("#c678dd", bold=True)  # keywords
        self.fmt_type: QtGui.QTextCharFormat = self._fmt("#56b6c2")  # builtin types
        self.fmt_num: QtGui.QTextCharFormat = self._fmt("#d19a66")  # numbers
        self.fmt_str: QtGui.QTextCharFormat = self._fmt("#98c379")  # strings / chars
        self.fmt_com: QtGui.QTextCharFormat = self._fmt(
            "#5c6370", italic=True
        )  # comments
        self.fmt_fn: QtGui.QTextCharFormat = self._fmt("#61afef")  # function idents

        keywords: list[str] = """
            alignas alignof and and_eq asm auto break case catch class compl concept const consteval constexpr constinit
            continue decltype default delete do else enum explicit export extern false for friend goto if inline mutable
            namespace new noexcept not not_eq nullptr operator or or_eq private protected public reflexpr register
            reinterpret_cast requires return sizeof static static_assert static_cast struct switch template this
            thread_local throw true try typedef typeid typename union using virtual volatile while xor xor_eq
        """.split()  # type: ignore

        types: list[str] = """
            char char8_t char16_t char32_t wchar_t bool short int long signed unsigned float double void
            size_t ptrdiff_t int8_t int16_t int32_t int64_t uint8_t uint16_t uint32_t uint64_t
        """.split()  # type: ignore

        self.rules: list[tuple[QtCore.QRegularExpression, QtGui.QTextCharFormat]] = []
        b = r"\b"
        self.rules += [
            (QtCore.QRegularExpression(b + k + b), self.fmt_kw) for k in keywords
        ]
        self.rules += [
            (QtCore.QRegularExpression(b + t + b), self.fmt_type) for t in types
        ]

        # numbers
        self.rules += [
            (QtCore.QRegularExpression(r"\b0[xX][0-9A-Fa-f]+\b"), self.fmt_num),
            (
                QtCore.QRegularExpression(r"\b\d+\.\d+(?:[eE][+-]?\d+)?[fFlL]?\b"),
                self.fmt_num,
            ),
            (QtCore.QRegularExpression(r"\b\d+[uUlL]*\b"), self.fmt_num),
        ]

        # strings & chars
        self.re_string = QtCore.QRegularExpression(r"\"([^\"\\]|\\.)*\"")
        self.re_char = QtCore.QRegularExpression(r"'([^'\\]|\\.)*'")

        # function identifier (group 1 = identifier)
        self.re_func = QtCore.QRegularExpression(r"\b([A-Za-z_]\w*)\s*(?=\()")

        # comments (// and /* ... */ with multi-line state)
        self.re_line_comment = QtCore.QRegularExpression(r"//[^\n]*")
        self.start_block = QtCore.QRegularExpression(r"/\*")
        self.end_block = QtCore.QRegularExpression(r"\*/")

    @staticmethod
    def _fmt(
        color: str, *, bold: bool = False, italic: bool = False
    ) -> QtGui.QTextCharFormat:
        f = QtGui.QTextCharFormat()
        f.setForeground(QtGui.QColor(color))
        if bold:
            f.setFontWeight(QtGui.QFont.Weight.Bold)
        if italic:
            f.setFontItalic(True)
        return f

    def highlightBlock(self, text: str) -> None:
        # base token rules
        for rx, fmt in self.rules:
            it: QtCore.QRegularExpressionMatchIterator = rx.globalMatch(text)
            while it.hasNext():
                m: QtCore.QRegularExpressionMatch = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), fmt)

        # strings / chars
        for rx in (self.re_string, self.re_char):
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), self.fmt_str)

        # function identifiers
        it = self.re_func.globalMatch(text)
        while it.hasNext():
            m = it.next()
            self.setFormat(m.capturedStart(1), m.capturedLength(1), self.fmt_fn)

        # // line comments
        it = self.re_line_comment.globalMatch(text)
        while it.hasNext():
            m = it.next()
            self.setFormat(m.capturedStart(), m.capturedLength(), self.fmt_com)

        # /* ... */ multi-line comments with state
        self.setCurrentBlockState(0)
        start_idx = 0
        if self.previousBlockState() != 1:
            m = self.start_block.match(text)
            start_idx = m.capturedStart() if m.hasMatch() else -1
        else:
            start_idx = 0

        while start_idx >= 0:
            endm: QtCore.QRegularExpressionMatch = self.end_block.match(text, start_idx)
            if endm.hasMatch():
                end_idx: int = endm.capturedEnd()
                self.setFormat(start_idx, end_idx - start_idx, self.fmt_com)
                m = self.start_block.match(text, end_idx)
                start_idx: int = m.capturedStart() if m.hasMatch() else -1
            else:
                self.setFormat(start_idx, len(text) - start_idx, self.fmt_com)
                self.setCurrentBlockState(1)
                break
