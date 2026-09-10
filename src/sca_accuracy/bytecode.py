from __future__ import annotations

import io
import struct


def method_references(class_data: bytes) -> set[str]:
    """Extract JVM method references from a class constant pool without loading the class."""
    stream = io.BytesIO(class_data)
    if _u4(stream) != 0xCAFEBABE:
        return set()
    _read(stream, 4)  # minor and major version
    count = _u2(stream)
    pool: list[tuple[int, object] | None] = [None] * count
    index = 1
    try:
        while index < count:
            tag = _u1(stream)
            if tag == 1:
                size = _u2(stream)
                pool[index] = (tag, _read(stream, size).decode("utf-8", errors="replace"))
            elif tag in {3, 4}:
                pool[index] = (tag, _read(stream, 4))
            elif tag in {5, 6}:
                pool[index] = (tag, _read(stream, 8))
                index += 1
            elif tag in {7, 8, 16, 19, 20}:
                pool[index] = (tag, _u2(stream))
            elif tag in {9, 10, 11, 12, 17, 18}:
                pool[index] = (tag, (_u2(stream), _u2(stream)))
            elif tag == 15:
                pool[index] = (tag, (_u1(stream), _u2(stream)))
            else:
                return set()
            index += 1
    except (EOFError, struct.error):
        return set()

    references: set[str] = set()
    for entry in pool:
        if entry is None or entry[0] not in {10, 11}:
            continue
        class_index, name_type_index = entry[1]
        owner = _class_name(pool, class_index)
        name, descriptor = _name_and_type(pool, name_type_index)
        if owner and name:
            references.add(f"{owner.replace('/', '.')}#{name}{descriptor}")
    return references


def class_names_from_jar_entries(names: list[str]) -> set[str]:
    result = set()
    for name in names:
        if name.endswith(".class") and not name.startswith("META-INF/versions/"):
            result.add(name.removesuffix(".class").replace("/", "."))
    return result


def symbol_owner(symbol: str) -> str:
    return symbol.split("#", 1)[0]


def _class_name(pool: list[tuple[int, object] | None], index: int) -> str:
    entry = pool[index]
    if entry is None or entry[0] != 7:
        return ""
    return _utf8(pool, entry[1])


def _name_and_type(pool: list[tuple[int, object] | None], index: int) -> tuple[str, str]:
    entry = pool[index]
    if entry is None or entry[0] != 12:
        return "", ""
    name_index, descriptor_index = entry[1]
    return _utf8(pool, name_index), _utf8(pool, descriptor_index)


def _utf8(pool: list[tuple[int, object] | None], index: int) -> str:
    entry = pool[index]
    return str(entry[1]) if entry is not None and entry[0] == 1 else ""


def _read(stream: io.BytesIO, size: int) -> bytes:
    value = stream.read(size)
    if len(value) != size:
        raise EOFError
    return value


def _u1(stream: io.BytesIO) -> int:
    return struct.unpack(">B", _read(stream, 1))[0]


def _u2(stream: io.BytesIO) -> int:
    return struct.unpack(">H", _read(stream, 2))[0]


def _u4(stream: io.BytesIO) -> int:
    return struct.unpack(">I", _read(stream, 4))[0]
