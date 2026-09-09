from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from reai_toolkit.app.services.ai_decomp.stream import PROSE_TAIL

if TYPE_CHECKING:
    from revengai.models.comments_data import CommentsData
    from revengai.models.decompilation_data import DecompilationData
    from revengai.models.get_tokens_response import GetTokensResponse
    from revengai.models.progress_message import ProgressMessage
    from revengai.models.rendered_token import RenderedToken
    from revengai.models.summary_data import SummaryData
    from revengai.models.workflow_progress import WorkflowProgress

    from reai_toolkit.app.services.ai_decomp.stream import StreamState


_IDENT_RE = re.compile(r"[A-Za-z_]\w*")

RENAME_NOT_READY = "The AI decompilation is still loading — try again once it finishes."
RENAME_NOT_DECOMP_LINE = "This line is not part of the AI decompilation."
RENAME_NOT_CODE_LINE = (
    "Only identifiers in the decompiled code can be renamed, not comments."
)
RENAME_NOT_ON_LINE = "'{word}' is not an identifier on this line."
RENAME_IS_DATA_TYPE = (
    "'{word}' is a data type — rename the type itself, not the AI decompilation."
)
RENAME_IS_FUNCTION = (
    "'{word}' is a function — rename it in the disassembly and it will sync."
)
RENAME_IS_IMPORTED_FUNCTION = "'{word}' is an imported function and cannot be renamed."
RENAME_UNRESOLVED = "'{word}' is not a renameable variable or type."

_RENAMED_ELSEWHERE: tuple[tuple[str, str], ...] = (
    ("data_type_id", RENAME_IS_DATA_TYPE),
    ("function_id", RENAME_IS_FUNCTION),
    ("imported_function_id", RENAME_IS_IMPORTED_FUNCTION),
)


@dataclass
class RenderModel:
    summary_line_count: int
    code_lines: list[str]
    comment_by_source: dict[int, str]
    display_source: list[Optional[int]]
    display_is_code: list[bool]


@dataclass
class RenameTarget:
    placeholder: Optional[str] = None
    kind: Optional[str] = None
    reason: Optional[str] = None


def render_view(
    decomp: "DecompilationData",
    summary: "Optional[SummaryData]",
    comments: "Optional[CommentsData]",
) -> str:
    text, _ = render_view_with_map(decomp, summary, comments)
    return text


def render_view_with_map(
    decomp: "DecompilationData",
    summary: "Optional[SummaryData]",
    comments: "Optional[CommentsData]",
) -> tuple[str, RenderModel]:
    code: str = decomp.decompilation or ""
    code_lines: list[str] = code.split("\n")

    summary_block: str | None = None
    if summary is not None and summary.ai_summary:
        summary_block = _format_summary_as_comment(summary.ai_summary)
    summary_line_count = len(summary_block.split("\n")) if summary_block is not None else 0

    inline = comments.inline_comments if comments is not None else None
    comment_by_source: dict[int, str] = {}
    if inline:
        for c in inline:
            if 1 <= c.line <= len(code_lines):
                comment_by_source[c.line] = c.comment

    display_lines: list[str] = []
    display_source: list[Optional[int]] = []
    display_is_code: list[bool] = []

    if summary_block is not None:
        for sline in summary_block.split("\n"):
            display_lines.append(sline)
            display_source.append(None)
            display_is_code.append(False)

    for idx, code_line in enumerate(code_lines):
        source_line = idx + 1
        comment = comment_by_source.get(source_line)
        if comment is not None:
            indent = code_line[: len(code_line) - len(code_line.lstrip())]
            for part in comment.split("\n"):
                display_lines.append(f"{indent}// {part}")
                display_source.append(source_line)
                display_is_code.append(False)
        display_lines.append(code_line)
        display_source.append(source_line)
        display_is_code.append(True)

    text = "\n".join(display_lines)
    return text, RenderModel(
        summary_line_count=summary_line_count,
        code_lines=code_lines,
        comment_by_source=comment_by_source,
        display_source=display_source,
        display_is_code=display_is_code,
    )


def render_progress(progress: "WorkflowProgress") -> str:
    lines: list[str] = ["// RevEng.AI — AI decompilation in progress…", "//"]

    steps_total = progress.steps_total or 0
    step_index = progress.step_index or 0
    step_name = progress.step or ""
    status = progress.status or ""

    if steps_total > 0:
        current = min(step_index + 1, steps_total)
        lines.append(f"// Step {current}/{steps_total}: {step_name} [{status}]")
    elif step_name:
        lines.append(f"// {step_name} [{status}]")
    else:
        lines.append(f"// {status}")

    messages = progress.messages or []
    if messages:
        lines.append("//")
        for message in messages:
            lines.append(f"// {_format_progress_message(message)}")

    return "\n".join(lines)


def render_stream(state: "StreamState") -> str:
    lines: list[str] = []

    if state.failed:
        lines.append("// RevEng.AI — AI decompilation failed")
        if state.error:
            lines.append(f"// {state.error}")
    elif state.finished:
        lines.append("// RevEng.AI — AI decompilation complete")
    else:
        attempt = f" (attempt {state.attempt})" if state.attempt > 1 else ""
        stage = "naming identifiers" if state.decomp_finished else "decompiling"
        lines.append(f"// RevEng.AI — {stage}…{attempt}")

    if state.prose and not state.source:
        lines.append("//")
        for text in state.prose[-PROSE_TAIL:]:
            for part in text.split("\n"):
                lines.append(f"// {part}")

    header = "\n".join(lines)
    if not state.source:
        return header
    return f"{header}\n\n{state.source}"


def _format_progress_message(message: "ProgressMessage") -> str:
    stamp = _format_progress_time(getattr(message, "timestamp", None))
    prefix = f"{stamp} " if stamp else ""
    return f"{prefix}[{message.level}] {message.text}"


def _format_progress_time(timestamp) -> str:
    if timestamp is None:
        return ""
    try:
        return timestamp.strftime("%H:%M:%S")
    except (AttributeError, ValueError):
        return ""


def _format_summary_as_comment(summary: str) -> str:
    prefix = " * "
    max_comment_width: int = 100
    content_width: int = max_comment_width - len(prefix)

    lines: list[str] = ["/*"]

    for paragraph in summary.split("\n"):
        if not paragraph.strip():
            lines.append(" *")
            continue

        words: list[str] = paragraph.split()
        current_line: str = ""

        for word in words:
            if not current_line:
                current_line = word
            elif len(current_line) + 1 + len(word) <= content_width:
                current_line += " " + word
            else:
                lines.append(prefix + current_line)
                current_line = word

        if current_line:
            lines.append(prefix + current_line)

    lines.append(" */")
    return "\n".join(lines)


def index_of_identifier(line: str, word: str) -> int:
    idents = _IDENT_RE.findall(line)
    return idents.index(word) if word in idents else -1


def source_line_at(model: RenderModel, display_line: int) -> Optional[int]:
    if not (0 <= display_line < len(model.display_source)):
        return None
    if not model.display_is_code[display_line]:
        return None
    return model.display_source[display_line]


def display_rows_for_source_lines(model: RenderModel, source_lines) -> list[int]:
    wanted = set(source_lines)
    if not wanted:
        return []
    return [
        row
        for row, source in enumerate(model.display_source)
        if source in wanted and model.display_is_code[row]
    ]


def effective_values(tokens: "GetTokensResponse") -> dict[str, str]:
    rendered = tokens.placeholder_to_rendered_token or {}
    overrides = tokens.placeholder_to_user_override or {}
    values: dict[str, str] = {}
    for placeholder, token in rendered.items():
        override = overrides.get(placeholder)
        values[placeholder] = override.value if override is not None else token.value
    return values


def names_token(ident: str, rendered_value: str) -> bool:
    return ident == rendered_value or ident in _IDENT_RE.findall(rendered_value)


def _unit_re(placeholders) -> re.Pattern:
    parts = [re.escape(p) for p in sorted(placeholders, key=len, reverse=True)]
    parts.append(_IDENT_RE.pattern)
    return re.compile("|".join(parts))


def find_token(
    tokens: "GetTokensResponse",
    source_index: int,
    ident_index: int,
    old_ident: str,
) -> Optional[tuple[str, "RenderedToken"]]:
    rendered = tokens.placeholder_to_rendered_token or {}
    if not rendered:
        return None
    values = effective_values(tokens)

    tok_lines = (tokens.ai_decomp or "").split("\n")
    if 0 <= source_index < len(tok_lines):
        units = _unit_re(rendered).findall(tok_lines[source_index])
        if 0 <= ident_index < len(units):
            unit = units[ident_index]
            if unit in rendered and names_token(old_ident, values[unit]):
                return unit, rendered[unit]

    matches = [p for p, value in values.items() if names_token(old_ident, value)]
    if len(matches) == 1:
        return matches[0], rendered[matches[0]]
    return None


def renamed_elsewhere_reason(token: "RenderedToken", word: str) -> Optional[str]:
    for name, reason in _RENAMED_ELSEWHERE:
        if getattr(token, name, None) is not None:
            return reason.format(word=word)
    return None


def is_renameable(token: "RenderedToken") -> bool:
    return all(getattr(token, name, None) is None for name, _ in _RENAMED_ELSEWHERE)


def resolve_token(
    tokens: "GetTokensResponse",
    source_index: int,
    ident_index: int,
    old_ident: str,
) -> Optional[tuple[str, str]]:
    found = find_token(tokens, source_index, ident_index, old_ident)
    if found is None:
        return None
    placeholder, token = found
    if not is_renameable(token):
        return None
    return placeholder, token.kind


def resolve_rename_target(
    model: RenderModel,
    tokens: "GetTokensResponse",
    display_line: int,
    word: str,
) -> RenameTarget:
    if not (0 <= display_line < len(model.display_is_code)):
        return RenameTarget(reason=RENAME_NOT_DECOMP_LINE)
    if not model.display_is_code[display_line]:
        return RenameTarget(reason=RENAME_NOT_CODE_LINE)

    source_line = model.display_source[display_line]
    if source_line is None:
        return RenameTarget(reason=RENAME_NOT_DECOMP_LINE)

    source_index = source_line - 1
    ident_index = index_of_identifier(model.code_lines[source_index], word)
    if ident_index < 0:
        return RenameTarget(reason=RENAME_NOT_ON_LINE.format(word=word))

    found = find_token(tokens, source_index, ident_index, word)
    if found is None:
        return RenameTarget(reason=RENAME_UNRESOLVED.format(word=word))

    placeholder, token = found
    reason = renamed_elsewhere_reason(token, word)
    if reason is not None:
        return RenameTarget(reason=reason)
    return RenameTarget(placeholder=placeholder, kind=token.kind)
