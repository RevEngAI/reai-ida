import idautils
import ida_funcs
import idc

for func in idautils.Functions():
    function_name = idc.get_func_name(func)
    function_address = idc.get_func_attr(func, idc.FUNCATTR_START)
    function_end = idc.get_func_attr(func, idc.FUNCATTR_END)

    # Get function chunks
    chunks = list(idautils.Chunks(func))
    
    # Attempt to analyze function arguments and return type
    tinfo = idaapi.tinfo_t()
    if idaapi.get_tinfo(tinfo, func):
        function_args = tinfo.get_nargs()
        function_ret_type = tinfo.get_rettype().dstr()
    else:
        function_args = "Unknown"
        function_ret_type = "Unknown"

    print("Function Name:", function_name)
    print("Address:", hex(function_address))
    print("End Address:", hex(function_end))
    print("Arguments:", function_args)
    print("Return Type:", function_ret_type)
    print("\n")
