# -*- coding: utf-8 -*-
import logging
from typing import Optional

import ida_segment
import idautils
import idc
import idaapi

from re import compile, match, Pattern


logger = logging.getLogger("REAI")


class FunctionSignature(object):
    """
    @param return_type:     Return type of function
    @param call_convention: Calling convention used in function
    @param func_name:       Mangled function name
    @param func_args:       Array of type of function arguments
    """

    def __init__(self, return_type: str, call_convention: str, func_name: str, func_args: list):
        self.ret = return_type
        self.conv = call_convention
        self.func_name = func_name
        self.args = func_args

    def make_sig(self) -> str:
        return f"{self.ret} {self.conv} {self.func_name}({', '.join(self.args)})"


func_sig_pattern: Pattern = compile(r"(\w+) (__\w+)(?:\()(\w.*)(?:\))")


class IDAUtils(object):
    @staticmethod
    def set_name(func_ea: int, func_name: str, anyway: bool = False) -> bool:
        """
        Sets the name of an address in IDA.
        If the name already exists, check the `anyway` parameter:
            True - Add `_COUNTER` to the name (default IDA behaviour)
        """
        return (IDAUtils.is_in_valid_segment(func_ea) and
                (idaapi.set_name(func_ea, func_name, idaapi.SN_NOWARN | idaapi.SN_NOCHECK) or
                 anyway and idaapi.force_name(func_ea, func_name)))

    @staticmethod
    def set_comment(func_ea: int, comment: str) -> None:
        if IDAUtils.is_in_valid_segment(func_ea):
            # Set in dissassembly
            idc.set_cmt(func_ea, comment, 0)

            # Set in decompiled data
            IDAUtils.set_hexrays_comment(func_ea, comment)

    @staticmethod
    def set_hexrays_comment(func_ea: int, comment: str) -> None:
        """
        Set comment in decompiled code
        """
        if idaapi.init_hexrays_plugin() and IDAUtils.is_in_valid_segment(func_ea):
            cfunc = idaapi.decompile(func_ea)

            if cfunc:
                tl = idaapi.treeloc_t()
                tl.ea = func_ea
                tl.itp = idaapi.ITP_SEMI

                cfunc.set_user_cmt(tl, comment)
                cfunc.save_user_cmts()

    @staticmethod
    def decompile_func(func_ea: int) -> str:
        if not idaapi.init_hexrays_plugin() or not IDAUtils.is_in_valid_segment(func_ea):
            return ''

        func = idaapi.get_func(func_ea)
        if func:
            cfunc = idaapi.decompile(func.start_ea)

            if cfunc:
                lines = []
                for sline in cfunc.get_pseudocode():
                    lines.append(idaapi.tag_remove(sline.line))
                return "\n".join(lines)
        return ''

    @staticmethod
    def disasm_func(func_addr: int) -> str:
        func = idaapi.get_func(func_addr)
        if func:
            asm = []
            for ea in idautils.FuncItems(func_addr):
                inst = idaapi.generate_disasm_line(ea)
                asm.append(idaapi.tag_remove(inst))
            return "\n".join(asm)
        return ''

    @staticmethod
    def create_find_struct(name: str) -> any:
        sid = idc.get_struc_id(name)    # returns -1 if structure doesn't exist

        # if not, then create it
        if sid == -1:
            # ok, it doesn't exist, so we'll create it
            sid = idc.add_struc(-1, name, None)

        return sid if sid != -1 else None

    @staticmethod
    def get_func_name(func_ea: int) -> str:
        return idc.get_func_name(func_ea)

    @staticmethod
    def demangle(mangled_name: str) -> str:
        return idc.demangle_name(mangled_name, idc.get_inf_attr(idc.INF_LONG_DEMNAMES))

    @staticmethod
    def get_function_signature(func_ea: int) -> Optional[FunctionSignature]:
        signature = idc.get_type(func_ea)

        if not signature:
            logger.error(f"idc.get_type failed at function address: {func_ea:#x}")
            return None

        parsed_sig = match(func_sig_pattern, signature)

        if not parsed_sig:
            logger.error(f"Failed to run re.match for sig: {signature}")
            return None

        return FunctionSignature(parsed_sig.group(1),  # return type
                                 parsed_sig.group(2),  # calling convention
                                 idc.get_name(func_ea),
                                 parsed_sig.group(3).split(', ')  # arguments
                                 )

    @staticmethod
    def is_in_valid_segment(func_ea: int) -> bool:
        segments = [ida_segment.get_segm_by_name(name) for name in [".init", ".text", ".fini"]]

        return any(segment.start_ea <= func_ea <= segment.end_ea for segment in segments) if segments else False
