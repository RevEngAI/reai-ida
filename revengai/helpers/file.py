import ida_ida
import ida_loader
import idaapi


def _binary_isa_ida(file_format: str) -> str:
    proc_name = ida_ida.inf_get_procname().lower()
    is_64bit = ida_ida.inf_is_64bit()

    if "metapc" in proc_name or "x86" in proc_name or "386" in proc_name:
        return "x86_64" if is_64bit else "x86"

    elif "arm" in proc_name:
        if is_64bit or "aarch64" in proc_name or "arm64" in proc_name:
            return "ARM64"
        else:
            return "ARM32"

    raise RuntimeError(
        f"Error, could not determine or unsupported ISA for processor: {proc_name}, "
        f"file format: {file_format}"
    )


def _binary_format_ida() -> str:
    file_type = ida_ida.inf_get_filetype()

    if file_type == ida_ida.f_PE:
        return "PE"
    elif file_type == ida_ida.f_ELF:
        return "ELF"
    elif file_type == ida_ida.f_MACHO:
        return "Mach-O"

    file_type_name = ida_loader.get_file_type_name()
    if file_type_name:
        file_type_name = file_type_name.upper()
        if "PE" in file_type_name:
            return "PE"
        elif "ELF" in file_type_name:
            return "ELF"
        elif "MACH" in file_type_name:
            return "Mach-O"

    raise RuntimeError(
        f"Error, could not determine or unsupported binary format. "
        f"File type ID: {file_type}, File type name: {file_type_name}"
    )


def file_type_ida() -> tuple[str, str]:
    try:
        file_format = _binary_format_ida()
        isa_format = _binary_isa_ida(file_format)

        return file_format, isa_format

    except Exception as e:
        return "Unknown format", "Unknown format"
