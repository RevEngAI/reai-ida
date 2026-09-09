from logging import Logger

import ida_funcs
import ida_kernwin
from libbs.decompilers.ida.compat import execute_read, execute_ui
from revengai.models.ai_decompilation_rating import AiDecompilationRating
from revengai.models.comments_data import CommentsData
from revengai.models.decompilation_data import DecompilationData
from revengai.models.summary_data import SummaryData
from revengai.models.get_tokens_response import GetTokensResponse
from revengai.models.workflow_progress import WorkflowProgress

from reai_toolkit.app.app import App
from reai_toolkit.app.components.tabs.ai_decomp_tab import AIDecompView
from reai_toolkit.app.coordinators.ai_decomp_render import (
    RENAME_NOT_READY,
    RenderModel,
    render_progress,
    render_stream,
    render_view_with_map,
    resolve_rename_target,
)
from reai_toolkit.app.coordinators.base_coordinator import BaseCoordinator
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.factory import DialogFactory
from reai_toolkit.app.services.ai_decomp.ai_decomp_service import AiDecompService
from reai_toolkit.app.services.ai_decomp.stream import StreamState
from reai_toolkit.hooks.reactive import AiDecompFunctionViewHooks


class AiDecompCoordinator(BaseCoordinator):
    def __init__(
        self,
        *,
        app: "App",
        factory: "DialogFactory",
        log: Logger,
        ai_decomp_service: AiDecompService,
    ) -> None:
        super().__init__(app=app, factory=factory, log=log)
        self.ai_decomp_service: AiDecompService = ai_decomp_service
        self._decomp_view: AIDecompView | None = None
        self._decomp_hooks: AiDecompFunctionViewHooks | None = None
        self._current_func_vaddr: int | None = None
        self._current_decomp: DecompilationData | None = None
        self._current_summary: SummaryData | None = None
        self._current_comments: CommentsData | None = None
        self._current_tokenised: GetTokensResponse | None = None
        self._baseline: RenderModel | None = None

    def enable_function_tracking(self) -> None:
        if self._decomp_hooks is None:
            self._decomp_hooks = AiDecompFunctionViewHooks(self)  # type: ignore
            self._decomp_hooks.hook()

    def disable_function_tracking(self) -> None:
        if self._decomp_hooks:
            self._decomp_hooks.unhook()
            self._decomp_hooks = None

    def is_tracking(self) -> bool:
        return self._decomp_hooks is not None

    @execute_ui
    def ensure_tracking(self) -> None:
        self.enable_function_tracking()

    @execute_ui
    def run_dialog(self) -> None:
        if self._decomp_view is None:
            self._decomp_view = self.factory.ai_decomp(on_closed=self._on_pane_closed)
            self._decomp_view.on_refresh = self.refresh_current
            self._decomp_view.on_rename = self.request_rename
            self._decomp_view.on_edit_comment = self.request_edit_comment
            self._decomp_view.on_remove_comment = self.request_remove_comment
            self._decomp_view.on_rate_up = self.rate_up
            self._decomp_view.on_rate_down = self.rate_down
            self._decomp_view.on_use_predicted_name = self.apply_predicted_name
            self._decomp_view.Create(self._decomp_view.TITLE)

    def start_decompilation(self, ea: int) -> None:
        self._current_decomp = None
        self._current_summary = None
        self._current_comments = None
        self._current_tokenised = None
        self._baseline = None
        self._current_func_vaddr = ea

        self.run_dialog()

        cached = self.ai_decomp_service.peek_decomp(ea)
        if self._decomp_view is not None:
            self._decomp_view.set_rating(None)
            self._decomp_view.set_predicted_name(None)
            if cached is not None and cached.decompilation:
                self._current_decomp = cached
                self._rerender()
            else:
                self._decomp_view.update_view_content(
                    "Please wait, decompilation in progress..."
                )

        self._dispatch_task(ea)

    def prefetch_decompilation(self, ea: int) -> None:
        self._dispatch_task(ea)

    def follow_function(self, ea: int, prefetch_if_closed: bool = False) -> None:
        if self._decomp_view is not None:
            if self._screen_function_start() == ea:
                self.start_decompilation(ea)
            else:
                self.prefetch_decompilation(ea)
        elif prefetch_if_closed:
            self.prefetch_decompilation(ea)

    @execute_read
    def _screen_function_start(self) -> int | None:
        func = ida_funcs.get_func(ida_kernwin.get_screen_ea())
        return func.start_ea if func else None

    def _dispatch_task(self, ea: int) -> None:
        self.ai_decomp_service.start_ai_decomp_task(
            ea=ea,
            on_decomp=lambda response: self._on_decomp_complete(ea, response),
            on_summary=lambda response: self._on_summary_complete(ea, response),
            on_comments=lambda response: self._on_comments_complete(ea, response),
            on_tokenised=lambda response: self._on_tokenised_complete(ea, response),
            on_progress=lambda progress: self._on_progress(ea, progress),
            on_stream=lambda state: self._on_stream(ea, state),
        )

    @execute_ui
    def _on_progress(self, ea: int, progress: WorkflowProgress) -> None:
        if ea != self._current_func_vaddr:
            return
        if self._current_decomp is not None:
            return
        if self._decomp_view is None:
            return
        self._decomp_view.update_view_content(render_progress(progress))

    @execute_ui
    def _on_stream(self, ea: int, state: StreamState) -> None:
        if ea != self._current_func_vaddr:
            return
        if self._current_decomp is not None:
            return
        if self._decomp_view is None:
            return
        self._decomp_view.update_view_content(render_stream(state), follow_tail=True)

    def _on_decomp_complete(
        self, ea: int, response: GenericApiReturn[DecompilationData]
    ) -> None:
        if ea != self._current_func_vaddr:
            return

        if response.success is False:
            if response.error_message:
                self.show_error_dialog(message=response.error_message)

                if self._decomp_view:
                    self._decomp_view.update_view_content(
                        code="//" + response.error_message
                    )

                if "model_not_supported" in response.error_message:
                    self.disable_function_tracking()
            return

        if response.data is None or response.data.decompilation is None:
            return

        if self._decomp_view is None:
            self.run_dialog()

        if self._decomp_view is None:
            return

        self._current_decomp = response.data
        self._rerender()

    def _on_summary_complete(
        self, ea: int, response: GenericApiReturn[SummaryData]
    ) -> None:
        if ea != self._current_func_vaddr:
            return
        if not response.success:
            self.log.warning(f"AI summary fetch failed: {response.error_message}")
            return
        if response.data is None:
            return
        self._current_summary = response.data
        if self._decomp_view is not None:
            self._decomp_view.set_predicted_name(response.data.predicted_function_name)
        self._rerender()

    def _on_comments_complete(
        self, ea: int, response: GenericApiReturn[CommentsData]
    ) -> None:
        if ea != self._current_func_vaddr:
            return
        if not response.success:
            self.log.warning(f"Inline comments fetch failed: {response.error_message}")
            return
        if response.data is None:
            return
        self._current_comments = response.data
        self._rerender()

    def _on_tokenised_complete(
        self, ea: int, response: GenericApiReturn[GetTokensResponse]
    ) -> None:
        if ea != self._current_func_vaddr:
            return
        if not response.success or response.data is None:
            return
        self._current_tokenised = response.data

    def refresh_current(self) -> None:
        ea = self._current_func_vaddr
        if ea is None:
            return
        self.ai_decomp_service.invalidate_ea(ea)
        self.start_decompilation(ea)

    def rate_up(self) -> None:
        self._rate(AiDecompilationRating.POSITIVE)

    def rate_down(self) -> None:
        self._rate(AiDecompilationRating.NEGATIVE)

    def _rate(self, rating: AiDecompilationRating) -> None:
        ea = self._current_func_vaddr
        if ea is None:
            return
        if self._current_decomp is None:
            self.show_info_dialog(msg="No AI decompilation to rate yet.")
            if self._decomp_view is not None:
                self._decomp_view.set_rating(None)
            return
        self.ai_decomp_service.rate_decomp(
            ea=ea,
            rating=rating,
            on_result=lambda response: self._on_rating_result(ea, response),
        )

    def _on_rating_result(
        self, ea: int, response: GenericApiReturn[bool]
    ) -> None:
        if ea != self._current_func_vaddr:
            return
        if not response.success:
            if response.error_message:
                self.show_error_dialog(message=response.error_message)
            if self._decomp_view is not None:
                self._decomp_view.set_rating(None)

    def apply_predicted_name(self, name: str) -> None:
        ea = self._current_func_vaddr
        if ea is None or not name:
            return

        if self.ai_decomp_service.update_function_name(ea, name):
            self.ai_decomp_service.tag_function_as_renamed(name)
            self.refresh_disassembly_view()
            return

        final = self.ai_decomp_service.apply_deduped_name(ea, name)
        if final is None:
            self.show_info_dialog(msg=f"Could not rename this function to '{name}'.")
            return
        self.ai_decomp_service.tag_function_as_renamed(final)
        self.refresh_disassembly_view()

    def request_rename(self, display_line: int, word: str) -> None:
        ea = self._current_func_vaddr
        if ea is None:
            return
        if self._baseline is None or self._current_tokenised is None:
            self.show_info_dialog(msg=RENAME_NOT_READY)
            return

        target = resolve_rename_target(
            self._baseline, self._current_tokenised, display_line, word
        )
        if target.placeholder is None:
            self.show_info_dialog(msg=target.reason)
            return

        new_name = ida_kernwin.ask_str(word, 0, f"Rename '{word}'")
        if not new_name or new_name == word:
            return

        self.ai_decomp_service.apply_overrides(
            ea=ea,
            overrides={target.placeholder: new_name},
            on_decomp=lambda response: self._on_decomp_complete(ea, response),
            on_tokenised=lambda response: self._on_tokenised_complete(ea, response),
        )

    def request_edit_comment(self, display_line: int) -> None:
        ea = self._current_func_vaddr
        if ea is None or self._baseline is None:
            return
        source_line = self._source_line_for(display_line)
        if source_line is None:
            return

        existing = self._baseline.comment_by_source.get(source_line, "")
        text = ida_kernwin.ask_text(0, existing, f"Comment for line {source_line}")
        if text is None:
            return
        text = text.strip()
        if not text:
            if source_line in self._baseline.comment_by_source:
                self.ai_decomp_service.remove_comment(
                    ea=ea,
                    line=source_line,
                    on_result=lambda response: self._on_comments_updated(ea, response),
                )
            return

        self.ai_decomp_service.set_comment(
            ea=ea,
            line=source_line,
            comment=text,
            on_result=lambda response: self._on_comments_updated(ea, response),
        )

    def request_remove_comment(self, display_line: int) -> None:
        ea = self._current_func_vaddr
        if ea is None or self._baseline is None:
            return
        source_line = self._source_line_for(display_line)
        if source_line is None:
            return
        if source_line not in self._baseline.comment_by_source:
            self.show_info_dialog(msg="No comment on this line.")
            return
        self.ai_decomp_service.remove_comment(
            ea=ea,
            line=source_line,
            on_result=lambda response: self._on_comments_updated(ea, response),
        )

    def _source_line_for(self, display_line: int) -> int | None:
        if self._baseline is None:
            return None
        if not (0 <= display_line < len(self._baseline.display_source)):
            return None
        return self._baseline.display_source[display_line]

    def _on_comments_updated(
        self, ea: int, response: GenericApiReturn[CommentsData]
    ) -> None:
        if ea != self._current_func_vaddr:
            return
        if not response.success:
            if response.error_message:
                self.show_error_dialog(message=response.error_message)
            return
        if response.data is None:
            return
        self._current_comments = response.data
        self._rerender()

    def _rerender(self) -> None:
        if self._decomp_view is None or self._current_decomp is None:
            return
        rendered, self._baseline = render_view_with_map(
            decomp=self._current_decomp,
            summary=self._current_summary,
            comments=self._current_comments,
        )
        self._decomp_view.update_view_content(rendered)

    def _on_pane_closed(self) -> None:
        self._decomp_view = None
        self.disable_function_tracking()
        self.log.debug("AI Decomp view closed, reference cleared.")
