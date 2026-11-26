"""Minimal Android binary XML (AXML) patcher used by the dev build.

The dev build needs two manifest edits and neither of them justifies decoding the
whole 900+ MiB APK with apktool:

* ``android:debuggable`` — flip the boolean typed value in place (no size change);
* ``android:versionName`` — append a suffix, which requires adding one string to
  the manifest string pool.

Both helpers are strict: they raise instead of silently doing nothing, because a
dev build that *looks* instrumented but is not would poison the whole workflow.

Layout references: AOSP ``frameworks/base/libs/androidfw/include/androidfw/
ResourceTypes.h`` (``ResChunk_header``, ``ResStringPool_header``,
``ResXMLTree_node``, ``ResXMLTree_attrExt``, ``ResXMLTree_attribute``).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12

FLAG_UTF8 = 0x100

ATTR_DEBUGGABLE_ID = 0x0101000F
ATTR_VERSION_NAME_ID = 0x0101021C

# Node header: ResChunk_header (8 bytes) + lineNumber + comment.
_NODE_HEADER_SIZE = 16
_CHUNK_HEADER_SIZE = 8
_POOL_HEADER_SIZE = 28
_ATTR_EXT_SIZE = 20
_ATTR_SIZE = 20


@dataclass(frozen=True)
class Attribute:
    """One ``ResXMLTree_attribute`` entry."""

    offset: int  # offset of the attribute struct
    name: str
    resource_id: int | None  # from the resource-map chunk, when present
    data_type: int
    data: int
    raw_value: int

    @property
    def data_offset(self) -> int:
        """Offset of the 4-byte typed value."""
        return self.offset + 16

    @property
    def raw_value_offset(self) -> int:
        return self.offset + 8


@dataclass(frozen=True)
class Element:
    """One ``ResXMLTree_node`` of type START_ELEMENT."""

    name: str
    offset: int
    attributes: tuple[Attribute, ...]

    def attribute(self, name: str, resource_id: int | None = None) -> Attribute:
        for attribute in self.attributes:
            if resource_id is not None and attribute.resource_id == resource_id:
                return attribute
            if attribute.name == name:
                return attribute
        raise ValueError(
            f"<{self.name}> has no {name!r} attribute (attributes: "
            + ", ".join(a.name for a in self.attributes)
            + ")"
        )


class AxmlDocument:
    """Parsed view over a binary XML document (manifest)."""

    def __init__(self, data: bytes) -> None:
        if len(data) < 8:
            raise ValueError("Not an AXML document: too short")
        chunk_type = struct.unpack_from("<H", data, 0)[0]
        if chunk_type != RES_XML_TYPE:
            raise ValueError(
                f"Not an AXML document: chunk type 0x{chunk_type:04x} != 0x{RES_XML_TYPE:04x}"
            )
        self.data = data
        self._pool_offset = 0
        self._pool_size = 0
        self._pool_offsets: list[int] = []
        self._pool_data_offset = 0
        self._pool_flags = 0
        self._strings: list[str] = []
        self._resource_ids: list[int] = []
        self._parse_pool()
        self._parse_resource_map()
        self.elements = tuple(self._parse_elements())

    # -- string pool ------------------------------------------------------
    def _parse_pool(self) -> None:
        offset = _CHUNK_HEADER_SIZE
        chunk_type, header_size, size = _read_chunk_header(self.data, offset)
        if chunk_type != RES_STRING_POOL_TYPE:
            raise ValueError(
                f"Expected the string pool at offset 8, found chunk 0x{chunk_type:04x}"
            )
        string_count = struct.unpack_from("<I", self.data, offset + 8)[0]
        style_count = struct.unpack_from("<I", self.data, offset + 12)[0]
        flags = struct.unpack_from("<I", self.data, offset + 16)[0]
        strings_start = struct.unpack_from("<I", self.data, offset + 20)[0]
        if style_count:
            raise ValueError(
                "AXML documents with per-string styles are not supported "
                f"(styleCount={style_count})"
            )
        self._pool_offset = offset
        self._pool_size = size
        self._pool_flags = flags
        self._pool_data_offset = offset + strings_start
        self._pool_offsets = [
            struct.unpack_from("<I", self.data, offset + header_size + 4 * index)[0]
            for index in range(string_count)
        ]
        self._strings = [self._read_string(relative) for relative in self._pool_offsets]

    def _read_string(self, relative: int) -> str:
        offset = self._pool_data_offset + relative
        if self._pool_flags & FLAG_UTF8:
            # utf16 length, then utf8 byte length, each 1 or 2 bytes
            length16, offset = _read_length8(self.data, offset)
            length8, offset = _read_length8(self.data, offset)
            if length16 == 0 and length8 == 0:
                return ""
            return self.data[offset : offset + length8].decode("utf-8", "replace")
        length, offset = _read_length16(self.data, offset)
        return self.data[offset : offset + length * 2].decode("utf-16-le", "replace")

    def _parse_resource_map(self) -> None:
        offset = self._pool_offset + self._pool_size
        if offset + _CHUNK_HEADER_SIZE <= len(self.data):
            chunk_type, _header_size, size = _read_chunk_header(self.data, offset)
            if chunk_type == RES_XML_RESOURCE_MAP_TYPE:
                count = (size - _CHUNK_HEADER_SIZE) // 4
                self._resource_ids = [
                    struct.unpack_from("<I", self.data, offset + _CHUNK_HEADER_SIZE + 4 * i)[0]
                    for i in range(count)
                ]

    @property
    def strings(self) -> tuple[str, ...]:
        return tuple(self._strings)

    def string_at(self, index: int) -> str:
        if index == 0xFFFFFFFF or index >= len(self._strings):
            return ""
        return self._strings[index]

    # -- elements ---------------------------------------------------------
    def _parse_elements(self) -> list[Element]:
        elements: list[Element] = []
        offset = self._pool_offset + self._pool_size
        end = len(self.data)
        while offset + _CHUNK_HEADER_SIZE <= end:
            chunk_type, header_size, size = _read_chunk_header(self.data, offset)
            if size < _CHUNK_HEADER_SIZE or offset + size > end:
                break
            if chunk_type == RES_XML_START_ELEMENT_TYPE:
                body = offset + header_size
                name_index = struct.unpack_from("<I", self.data, body + 4)[0]
                attribute_start, attribute_size, attribute_count = struct.unpack_from(
                    "<HHH", self.data, body + 8
                )
                attributes = []
                for index in range(attribute_count):
                    attr_offset = body + attribute_start + index * attribute_size
                    ns_index, attr_name_index, raw_value = struct.unpack_from(
                        "<III", self.data, attr_offset
                    )
                    data_type = self.data[attr_offset + 15]
                    data = struct.unpack_from("<I", self.data, attr_offset + 16)[0]
                    resource_id = (
                        self._resource_ids[attr_name_index]
                        if attr_name_index < len(self._resource_ids)
                        else None
                    )
                    attributes.append(
                        Attribute(
                            offset=attr_offset,
                            name=self.string_at(attr_name_index),
                            resource_id=resource_id,
                            data_type=data_type,
                            data=data,
                            raw_value=raw_value,
                        )
                    )
                elements.append(
                    Element(
                        name=self.string_at(name_index),
                        offset=offset,
                        attributes=tuple(attributes),
                    )
                )
            elif chunk_type in (
                RES_XML_START_NAMESPACE_TYPE,
                RES_XML_END_NAMESPACE_TYPE,
                RES_XML_END_ELEMENT_TYPE,
                RES_XML_CDATA_TYPE,
            ):
                pass
            offset += size
        return elements

    def element(self, name: str) -> Element:
        for element in self.elements:
            if element.name == name:
                return element
        raise ValueError(f"No <{name}> element in the manifest")

    # -- rebuild helpers --------------------------------------------------
    def pool_string_bytes(self, text: str) -> bytes:
        """Encodes ``text`` the way the document's string pool expects it."""
        if self._pool_flags & FLAG_UTF8:
            encoded = text.encode("utf-8")
            out = bytearray()
            out += _encode_length8(len(text))
            out += _encode_length8(len(encoded))
            out += encoded + b"\x00"
            return bytes(out)
        utf16_bytes = text.encode("utf-16-le")
        return _encode_length16(len(utf16_bytes) // 2) + utf16_bytes + b"\x00\x00"

    def append_string(self, text: str) -> tuple[bytes, int]:
        """Returns the document with ``text`` appended to the pool and its index."""
        new_string = self.pool_string_bytes(text)
        count = len(self._pool_offsets)
        header_size = struct.unpack_from("<H", self.data, self._pool_offset + 2)[0]
        if header_size != _POOL_HEADER_SIZE:
            raise ValueError(f"Unsupported string pool header size: {header_size}")
        data_start = self._pool_data_offset
        data_end = self._pool_offset + self._pool_size
        data = bytearray(self.data[data_start:data_end])
        offsets = list(self._pool_offsets) + [len(data)]
        data += new_string
        # AXML chunks must stay 4-byte aligned; the pool data already ends on a
        # boundary, so padding the appended string keeps both the pool and the
        # outer XML chunk aligned (aapt warns/refuses otherwise).
        while len(data) % 4:
            data += b"\x00"
        strings_start = header_size + 4 * (count + 1)
        pool_size = strings_start + len(data)
        # Clear SORTED_FLAG (0x0001) because appending at the end may break sort order.
        flags = self._pool_flags & ~0x0001
        pool = bytearray()
        pool += struct.pack("<HHI", RES_STRING_POOL_TYPE, header_size, pool_size)
        pool += struct.pack(
            "<IIIII", count + 1, 0, flags, strings_start, 0
        )
        pool += b"".join(struct.pack("<I", value) for value in offsets)
        pool += data

        document = bytearray(self.data)
        document[self._pool_offset : self._pool_offset + self._pool_size] = pool
        delta = len(pool) - self._pool_size
        xml_size = struct.unpack_from("<I", document, 4)[0]
        struct.pack_into("<I", document, 4, xml_size + delta)
        return bytes(document), count


# -- module level helpers -------------------------------------------------
def _read_chunk_header(data: bytes, offset: int) -> tuple[int, int, int]:
    chunk_type, header_size, size = struct.unpack_from("<HHI", data, offset)
    return chunk_type, header_size, size


def _read_length8(data: bytes, offset: int) -> tuple[int, int]:
    value = data[offset]
    if value & 0x80:
        return ((value & 0x7F) << 8) | data[offset + 1], offset + 2
    return value, offset + 1


def _read_length16(data: bytes, offset: int) -> tuple[int, int]:
    value = struct.unpack_from("<H", data, offset)[0]
    if value & 0x8000:
        second = struct.unpack_from("<H", data, offset + 2)[0]
        return ((value & 0x7FFF) << 16) | second, offset + 4
    return value, offset + 2


def _encode_length8(length: int) -> bytes:
    if length > 0x7FFF:
        raise ValueError(f"String too long for an AXML pool: {length}")
    if length > 0x7F:
        return bytes(((length >> 8) | 0x80, length & 0xFF))
    return bytes((length,))


def _encode_length16(length: int) -> bytes:
    if length > 0x7FFFFFFF:
        raise ValueError(f"String too long for an AXML pool: {length}")
    if length > 0x7FFF:
        return struct.pack("<HH", (length >> 16) | 0x8000, length & 0xFFFF)
    return struct.pack("<H", length)


def patch_debuggable(manifest: bytes, *, enabled: bool = True) -> bytes:
    """Sets ``android:debuggable`` on ``<application>``; size preserving."""
    document = AxmlDocument(manifest)
    application = document.element("application")
    attribute = application.attribute("debuggable", ATTR_DEBUGGABLE_ID)
    if attribute.data_type != TYPE_INT_BOOLEAN:
        raise ValueError(
            "android:debuggable is not stored as a boolean "
            f"(dataType=0x{attribute.data_type:02x}); refusing to guess"
        )
    target = 1 if enabled else 0
    if attribute.data == target:
        return manifest
    patched = bytearray(manifest)
    struct.pack_into("<I", patched, attribute.data_offset, target)
    return bytes(patched)


def patch_version_name(manifest: bytes, suffix: str) -> tuple[bytes, str, str]:
    """Appends ``suffix`` to ``android:versionName``.

    Returns ``(patched_manifest, old_value, new_value)``.  The string is added to
    the pool, so every chunk after it shifts by four bytes; the XML chunk size is
    updated to match.  ``versionName`` lives on ``<manifest>``, not
    ``<application>``.
    """
    document = AxmlDocument(manifest)
    attribute = _find_attribute(document, "versionName", ATTR_VERSION_NAME_ID)
    if attribute.data_type != TYPE_STRING:
        raise ValueError(
            "android:versionName is not a literal string "
            f"(dataType=0x{attribute.data_type:02x}); refusing to guess"
        )
    current = document.string_at(attribute.data)
    if current.endswith(suffix):
        return manifest, current, current
    updated, new_index = document.append_string(current + suffix)
    attr = _find_attribute(AxmlDocument(updated), "versionName", ATTR_VERSION_NAME_ID)
    patched = bytearray(updated)
    struct.pack_into("<I", patched, attr.raw_value_offset, new_index)
    struct.pack_into("<I", patched, attr.data_offset, new_index)
    return bytes(patched), current, current + suffix


def _find_attribute(
    document: AxmlDocument, name: str, resource_id: int | None = None
) -> Attribute:
    """Finds an attribute anywhere in the document (element order decides)."""
    for element in document.elements:
        for attribute in element.attributes:
            if resource_id is not None and attribute.resource_id == resource_id:
                return attribute
            if resource_id is None and attribute.name == name:
                return attribute
    raise ValueError(f"No {name!r} attribute found in the manifest")


def read_manifest_info(manifest: bytes) -> dict[str, object]:
    """Convenience view used by the inspector and by the tests."""
    document = AxmlDocument(manifest)
    info: dict[str, object] = {"elements": len(document.elements)}
    for name in ("debuggable", "versionName", "versionCode"):
        try:
            attribute = _find_attribute(document, name)
        except ValueError:
            info[name] = None
            continue
        if attribute.data_type == TYPE_STRING:
            info[name] = document.string_at(attribute.data)
        else:
            info[name] = attribute.data
    return info
