import re
from dataclasses import dataclass, field
from typing import Any, Optional

import ida_funcs
import ida_typeinf
import idaapi

import libbs.artifacts
from libbs.api import DecompilerInterface
from libbs.decompilers.ida.compat import execute_write, convert_type_str_to_ida_type
from loguru import logger

APPLY_CHUNK_SIZE = 50
_ANALYSIS_SCOPE_RE = re.compile(r"^[0-9a-fA-F]{64}(?:::|/)")

_RECORD_KINDS = frozenset({"STRUCT", "UNION"})

_GHIDRA_PRIMITIVE_DECLARATORS: tuple[str, ...] = (
    "unsigned __int8 byte",
    "__int8 sbyte",
    "unsigned char uchar",
    "signed char schar",
    "unsigned __int16 word",
    "__int16 sword",
    "unsigned __int32 dword",
    "__int32 sdword",
    "unsigned __int64 qword",
    "__int64 sqword",
    "__int64 longlong",
    "unsigned __int64 ulonglong",
    "unsigned __int8 undefined",
    "unsigned __int8 undefined1",
    "unsigned __int16 undefined2",
    "unsigned __int32 undefined4",
    "unsigned __int8 undefined6[6]",
    "unsigned __int64 undefined8",
    "unsigned __int32 pointer32",
    "unsigned __int64 pointer64",
    "unsigned __int16 wchar16",
    "unsigned __int32 wchar32",
    "_TBYTE float10",
    "unsigned __int8 code",
)

_GHIDRA_PRIMITIVE_NAME_RE = re.compile(r"(\w+)(?:\[\d+\])?$")


def _primitive_name(declarator: str) -> str:
    match = _GHIDRA_PRIMITIVE_NAME_RE.search(declarator)
    return match.group(1) if match else declarator


def install_ghidra_primitives() -> int:
    missing = [
        f"typedef {declarator};"
        for declarator in _GHIDRA_PRIMITIVE_DECLARATORS
        if convert_type_str_to_ida_type(_primitive_name(declarator)) is None
    ]
    if not missing:
        return 0

    errors = ida_typeinf.parse_decls(None, "".join(missing), None, 0)
    if errors:
        logger.warning(
            f"RevEng.AI: {errors} error(s) declaring Ghidra primitive types; "
            "some server types may not resolve"
        )
    return len(missing)


def normalise_type(data_type: str) -> str:
    # When we obtain a type from DWARF information, it often looks something like `DWARF/stdint-uintn.h::uint32_t`
    # Let's remove the DWARF/*.h prefix
    if data_type.startswith("DWARF/"):
        # Find the first occurence of `::`
        delimiter: str = "::"
        pos: int = data_type.find(delimiter)
        data_type = data_type[pos+len(delimiter):]

    return _ANALYSIS_SCOPE_RE.sub("", data_type)


@dataclass
class FunctionSignatures:
    items: list[dict] = field(default_factory=list)
    data_types: dict[str, dict] = field(default_factory=dict)


@dataclass
class _Prototype:
    function_id: int
    name: Optional[str]
    return_type: Optional[str]
    args: list[libbs.artifacts.FunctionArgument]


class _TypeResolver:
    def __init__(self, data_types: dict[str, dict]) -> None:
        self._data_types = data_types
        self._artifacts: dict[str, Any] = {}
        self._visiting: set[str] = set()

    @property
    def artifacts(self) -> dict[str, Any]:
        return self._artifacts

    def resolve(self, data_type_id: Optional[int]) -> tuple[Optional[str], Optional[int]]:
        if data_type_id is None:
            return None, None

        entry = self._data_types.get(str(data_type_id))
        if entry is None:
            return None, None

        kind = (entry.get("kind") or "").upper()
        definition = entry.get("definition") or {}

        if kind in _RECORD_KINDS:
            self._record(entry, definition)
        elif kind == "ENUM":
            self._enum(entry, definition)
        elif kind == "TYPEDEF":
            self._typedef(entry, definition)
        elif kind == "POINTER":
            self.resolve(definition.get("pointee_data_type_id"))
        elif kind == "ARRAY":
            self.resolve(definition.get("element_data_type_id"))

        name = entry.get("name")
        return (normalise_type(name) if name else None), entry.get("size")

    def _record(self, entry: dict, definition: dict) -> None:
        name = entry.get("name")
        if not name or name in self._artifacts or name in self._visiting:
            return

        self._visiting.add(name)
        members: dict[int, libbs.artifacts.StructMember] = {}
        for member in definition.get("members") or []:
            member_type, member_size = self.resolve(member.get("data_type_id"))
            offset = member.get("offset")
            if offset is None or member_type is None:
                continue
            members[offset] = libbs.artifacts.StructMember(
                name=member.get("name") or f"field_{offset:x}",
                offset=offset,
                type_=member_type,
                size=member.get("size") or member_size,
            )
        self._visiting.discard(name)

        size = entry.get("size")
        if size is None:
            return
        self._artifacts[name] = libbs.artifacts.Struct(
            name=name, size=size, members=members
        )

    def _enum(self, entry: dict, definition: dict) -> None:
        name = entry.get("name")
        if not name or name in self._artifacts:
            return

        members: dict[str, int] = {}
        for value in definition.get("values") or []:
            try:
                members[value["name"]] = int(value["value"])
            except (KeyError, TypeError, ValueError):
                continue

        self._artifacts[name] = libbs.artifacts.Enum(name=name, members=members)

    def _typedef(self, entry: dict, definition: dict) -> None:
        name = entry.get("name")
        if not name or name in self._artifacts or name in self._visiting:
            return

        self._visiting.add(name)
        target, _ = self.resolve(definition.get("target_data_type_id"))
        self._visiting.discard(name)

        if target is None:
            return
        self._artifacts[name] = libbs.artifacts.Typedef(name=name, type_=target)


class ImportDataTypes:
    def __init__(self) -> None:
        self.deci: DecompilerInterface | None = None

    def execute(
        self,
        signatures: FunctionSignatures,
        matched_function_mapping: dict[int, int] = {},
    ) -> set[int]:
        resolver = _TypeResolver(signatures.data_types)
        prototypes = [
            proto
            for proto in (self._prototype(item, resolver) for item in signatures.items)
            if proto is not None
        ]
        if not prototypes:
            return set()

        self._install_primitives()

        if resolver.artifacts:
            self._apply_dependencies(resolver.artifacts)

        failed: set[int] = set()
        total: int = len(prototypes)
        for start in range(0, total, APPLY_CHUNK_SIZE):
            chunk = prototypes[start:start + APPLY_CHUNK_SIZE]
            failed |= self._apply_chunk(chunk, matched_function_mapping)
            logger.info(
                f"RevEng.AI: applied data types to {min(start + APPLY_CHUNK_SIZE, total)}/{total} functions"
            )

        return failed

    @staticmethod
    @execute_write
    def _install_primitives() -> None:
        declared = install_ghidra_primitives()
        if declared:
            logger.info(f"RevEng.AI: declared {declared} Ghidra primitive type(s)")

    @staticmethod
    def _prototype(item: dict, resolver: _TypeResolver) -> Optional[_Prototype]:
        if not item.get("has_signature"):
            return None

        function_id = item.get("function_id")
        if function_id is None:
            return None

        args: list[libbs.artifacts.FunctionArgument] = []
        for parameter in item.get("parameters") or []:
            ordinal = parameter.get("ordinal")
            if ordinal is None:
                continue
            arg_type, arg_size = resolver.resolve(parameter.get("data_type_id"))
            args.append(
                libbs.artifacts.FunctionArgument(
                    offset=ordinal,
                    name=parameter.get("name") or f"a{ordinal + 1}",
                    type_=arg_type,
                    size=arg_size,
                )
            )

        return_type, _ = resolver.resolve(item.get("return_data_type_id"))

        return _Prototype(
            function_id=function_id,
            name=item.get("function_name"),
            return_type=return_type,
            args=sorted(args, key=lambda a: a.offset),
        )

    def _ensure_deci(self) -> None:
        if self.deci is None:
            self.deci = DecompilerInterface.discover(force_decompiler="ida")  # type: ignore

    @execute_write
    def _apply_dependencies(self, artifacts: dict[str, Any]) -> None:
        self._ensure_deci()
        for name, artifact in artifacts.items():
            try:
                self.apply_dependency(artifact)
            except Exception as e:
                logger.warning(f"RevEng.AI: skipped dependency {name!r}: {e!r}")

    def apply_dependency(self, artifact: Any) -> None:
        if self.deci is None:
            return

        match artifact:
            case libbs.artifacts.Struct():
                self.deci.structs[artifact.name] = artifact
            case libbs.artifacts.Enum():
                self.deci.enums[artifact.name] = artifact
            case libbs.artifacts.Typedef():
                self.deci.typedefs[artifact.name] = artifact
            case _:
                logger.warning(f"unsupported dependency type: {artifact}")

    @execute_write
    def _apply_chunk(
        self,
        chunk: list[_Prototype],
        matched_function_mapping: dict[int, int],
    ) -> set[int]:
        failed: set[int] = set()
        for proto in chunk:
            ea = matched_function_mapping.get(proto.function_id)
            if ea is None:
                failed.add(proto.function_id)
                continue

            try:
                if not self.apply_function_type(proto, ea):
                    failed.add(proto.function_id)
            except Exception as e:
                logger.warning(
                    f"RevEng.AI: skipped data types for function {proto.function_id}: {e!r}"
                )
                failed.add(proto.function_id)

        return failed

    def apply_function_type(self, proto: _Prototype, ea: int) -> bool:
        if ida_funcs.get_func(ea) is None:
            logger.warning(f"failed to update function: {proto.name} at 0x{ea:x}")
            return False

        arg_types: list[tuple[str, ida_typeinf.tinfo_t]] = []
        for arg in proto.args:
            arg_tif = convert_type_str_to_ida_type(arg.type) if arg.type else None
            if arg_tif is None:
                return False
            arg_types.append((arg.name, arg_tif))

        details: ida_typeinf.func_type_data_t = self._current_func_details(ea)

        if proto.return_type:
            ret_tif = convert_type_str_to_ida_type(proto.return_type)
            if ret_tif is None:
                return False
            details.rettype = ret_tif
        elif details.rettype.empty():
            details.rettype = convert_type_str_to_ida_type("void")

        if arg_types:
            details.clear()
            for name, arg_tif in arg_types:
                funcarg = ida_typeinf.funcarg_t()
                funcarg.name = name
                funcarg.type = arg_tif
                details.push_back(funcarg)

        prototype = ida_typeinf.tinfo_t()
        if not prototype.create_func(details):
            return False

        return bool(ida_typeinf.apply_tinfo(ea, prototype, ida_typeinf.TINFO_DEFINITE))

    @staticmethod
    def _current_func_details(ea: int) -> "ida_typeinf.func_type_data_t":
        details = ida_typeinf.func_type_data_t()
        existing = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(existing, ea) and existing.is_func() and existing.get_func_details(details):
            return details

        if (
            ida_typeinf.guess_tinfo(existing, ea) != ida_typeinf.GUESS_FUNC_FAILED
            and existing.is_func()
            and existing.get_func_details(details)
        ):
            return details

        details = ida_typeinf.func_type_data_t()
        details.cc = ida_typeinf.CM_CC_UNKNOWN
        return details
