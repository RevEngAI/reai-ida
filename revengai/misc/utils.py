# -*- coding: utf-8 -*-
import idautils
import idc
import idaapi


class IDAUtils(object):
    @staticmethod
    def set_name(func_addr: int, func_name: str, anyway: bool = False) -> bool:
        """
        Sets the name of an address in IDA.
        If the name already exists, check the `anyway` parameter:
            True - Add `_COUNTER` to the name (default IDA behaviour)
        """
        return idaapi.set_name(func_addr, func_name, idaapi.SN_NOWARN | idaapi.SN_NOCHECK) or \
            anyway and idaapi.force_name(func_addr, func_name)

    @staticmethod
    def set_comment(func_addr, comment: str) -> None:
        # Set in dissassembly
        idc.set_cmt(func_addr, comment, 0)

        # Set in decompiled data
        IDAUtils.set_hexrays_comment(func_addr, comment)

    @staticmethod
    def set_hexrays_comment(func_addr: int, comment: str):
        """
        Set comment in decompiled code
        """
        if idaapi.init_hexrays_plugin():
            cfunc = idaapi.decompile(func_addr)

            if cfunc:
                tl = idaapi.treeloc_t()
                tl.ea = func_addr
                tl.itp = idaapi.ITP_SEMI

                cfunc.set_user_cmt(tl, comment)
                cfunc.save_user_cmts()

    @staticmethod
    def decompile_func(fun_addr: int) -> str:
        if not idaapi.init_hexrays_plugin():
            return ''

        func = idaapi.get_func(fun_addr)
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
