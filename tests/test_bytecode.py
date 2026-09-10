import struct

from sca_accuracy.bytecode import method_references


def utf8(value: str) -> bytes:
    encoded = value.encode()
    return b"\x01" + struct.pack(">H", len(encoded)) + encoded


def test_extracts_method_reference_from_constant_pool() -> None:
    constant_pool = b"".join(
        [
            utf8("org/apache/commons/lang3/StringUtils"),  # 1
            b"\x07" + struct.pack(">H", 1),  # Class #1
            utf8("defaultIfBlank"),  # 3
            utf8("(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/CharSequence;"),  # 4
            b"\x0c" + struct.pack(">HH", 3, 4),  # NameAndType #3:#4
            b"\x0a" + struct.pack(">HH", 2, 5),  # Methodref #2.#5
        ]
    )
    class_data = (
        struct.pack(">IHHH", 0xCAFEBABE, 0, 65, 7) + constant_pool + b"\x00\x21\x00\x00\x00\x00"
    )

    assert method_references(class_data) == {
        (
            "org.apache.commons.lang3.StringUtils#defaultIfBlank"
            "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/CharSequence;"
        )
    }


def test_rejects_non_class_input() -> None:
    assert method_references(b"not-a-class") == set()
