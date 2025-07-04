import logging
from re import compile, match, Pattern
from typing import Optional

import idaapi
import idautils
import idc

logger = logging.getLogger("REAI")


class FunctionSignature(object):
    """
    @param return_type:     Return type of function
    @param call_convention: Calling convention used in function
    @param func_name:       Mangled function name
    @param func_args:       Array of type of function arguments
    """

    def __init__(
            self,
            return_type: str,
            call_convention: str,
            func_name: str,
            func_args: list
    ):
        self.ret = return_type
        self.conv = call_convention
        self.func_name = func_name
        self.args = func_args

    def make_sig(self) -> str:
        return f"{self.ret} {self.conv} {self.func_name}" \
               f"({', '.join(self.args)})"


func_sig_pattern: Pattern = compile(r"(\w+) (__\w+)(?:\()(\w.*)(?:\))")

version = float(idaapi.get_kernel_version())
if version < 9.0:

    def IWID_DISASMS() -> int:
        return idaapi.IWID_DISASMS

else:

    def IWID_DISASMS() -> int:
        return idaapi.IWID_DISASM


class IDAUtils(object):
    @staticmethod
    def set_name(func_ea: int, func_name: str, anyway: bool = False) -> bool:
        """
        Sets the name of an address in IDA.
        If the name already exists, check the `anyway` parameter:
            True - Add `_COUNTER` to the name (default IDA behaviour)
        """
        try:
            return IDAUtils.is_in_exec_segment(func_ea) and (
                idaapi.set_name(
                    func_ea, func_name, idaapi.SN_NOWARN | idaapi.SN_NOCHECK
                )
                or anyway
                and idaapi.force_name(func_ea, func_name)
            )
        finally:
            idaapi.request_refresh(IWID_DISASMS())

    @staticmethod
    def set_comment(func_ea: int, comment: str) -> None:
        if IDAUtils.is_in_exec_segment(func_ea):
            try:
                func = idaapi.get_func(func_ea)
                if not func:
                    logger.error(
                        "idaapi.get_func failed for function address: 0x%02X",
                        func_ea
                    )
                else:
                    idc.set_func_cmt(func.start_ea, comment, False)
            finally:
                idaapi.request_refresh(IWID_DISASMS())

    @staticmethod
    def decompile_func(func_ea: int) -> Optional[str]:
        if idaapi.init_hexrays_plugin() and \
                IDAUtils.is_in_exec_segment(func_ea):
            func = idaapi.get_func(func_ea)
            if not func:
                logger.error(
                    "idaapi.get_func failed at function address: 0x%02X",
                    func_ea
                )
            else:
                cfunc = idaapi.decompile(
                    func.start_ea, flags=idaapi.DECOMP_NO_WAIT)
                if not cfunc:
                    logger.error(
                        "idaapi.decompile failed at function address: 0x%02X",
                        func_ea
                    )
                else:
                    lines = []
                    for sline in cfunc.get_pseudocode():
                        lines.append(idaapi.tag_remove(sline.line))
                    return "\n".join(lines)
        return None

    @staticmethod
    def disasm_func(func_ea: int) -> str:
        if IDAUtils.is_in_exec_segment(func_ea):
            func = idaapi.get_func(func_ea)
            if not func:
                logger.error(
                    "idaapi.get_func failed at function address: 0x%02X",
                    func_ea
                )
            else:
                asm = []
                for ea in idautils.FuncItems(func_ea):
                    inst = idaapi.generate_disasm_line(ea)
                    asm.append(idaapi.tag_remove(inst))
                return "\n".join(asm)
        return ""

    @staticmethod
    def create_find_struct(name: str) -> any:
        sid = idc.get_struc_id(name)  # returns -1 if structure doesn't exist

        # if not, then create it
        if sid == -1:
            # ok, it doesn't exist, so we'll create it
            sid = idc.add_struc(-1, name, None)

        return sid if sid != -1 else None

    @staticmethod
    def get_func_name(func_ea: int) -> str:
        return idc.get_func_name(func_ea)

    @staticmethod
    def get_demangled_func_name(func_ea: int) -> str:
        # .split("(")[0]
        return IDAUtils.demangle(IDAUtils.get_func_name(func_ea))

    @staticmethod
    def demangle(mangled_name: str, attr: int = idc.INF_SHORT_DN) -> str:
        demangled_name = idc.demangle_name(
            mangled_name, idc.get_inf_attr(attr))

        return demangled_name if demangled_name else mangled_name

    @staticmethod
    def get_function_signature(func_ea: int) -> Optional[FunctionSignature]:
        signature = idc.get_type(
            idc.get_func_attr(func_ea, idc.FUNCATTR_START))

        if not signature:
            logger.error(
                "idc.get_type failed at function address: 0x%02X", func_ea)
            return None

        parsed_sig = match(func_sig_pattern, signature)

        if not parsed_sig:
            logger.error("Failed to run re.match for sig: %s", signature)
            return None

        return FunctionSignature(
            parsed_sig.group(1),  # return type
            parsed_sig.group(2),  # calling convention
            IDAUtils.get_demangled_func_name(func_ea),
            parsed_sig.group(3).split(", "),  # arguments
        )

    @staticmethod
    def refresh_pseudocode_view(func_ea: int) -> None:
        """Refreshes the pseudocode view in IDA."""
        names = [f"Pseudocode-{chr(ord('A') + i)}" for i in range(5)]
        for name in names:
            widget = idaapi.find_widget(name)
            if widget:
                vu = idaapi.get_widget_vdui(widget)

                # Check if the address is in the same function
                func = idaapi.get_func(vu.cfunc.entry_ea)
                if idaapi.func_contains(func, func_ea):
                    vu.refresh_view(True)

    @staticmethod
    def is_in_valid_segment(func_ea: int, segments: tuple[str] = None) -> bool:
        segments = [
            idaapi.get_segm_by_name(name)
            for name in (
                segments
                if segments
                else (
                    ".init",
                    ".text",
                    ".fini",
                )
            )
        ]

        return (
            any(seg and seg.start_ea <= func_ea <=
                seg.end_ea for seg in segments)
            if segments
            else False
        )

    @staticmethod
    def is_in_exec_segment(func_ea: int, segments: tuple[str] = None) -> bool:
        if segments:
            # If specific segments are provided, use them as before
            segments = [
                idaapi.get_segm_by_name(name)
                for name in segments
            ]
        else:
            # Find all segments with read-execute (r-x) flags
            segments = []
            for i in range(idaapi.get_segm_qty()):
                seg = idaapi.getnseg(i)
                if seg and (seg.perm & (idaapi.SEGPERM_READ | idaapi.SEGPERM_EXEC)) == (idaapi.SEGPERM_READ | idaapi.SEGPERM_EXEC):
                    segments.append(seg)

        return (
            any(seg and seg.start_ea <= func_ea <=
                seg.end_ea for seg in segments)
            if segments
            else False
        )

    @staticmethod
    def is_function(func_ea: int) -> bool:
        return True if idaapi.get_func(func_ea) else False
