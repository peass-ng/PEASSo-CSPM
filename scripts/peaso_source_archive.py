"""Recompress a bounded source ZIP with standard-library raw DEFLATE only."""
from collections import Counter
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import tempfile
import zipfile
import zlib

try:
    from zopfli.zlib import compress as zopfli_compress
except ImportError:
    zopfli_compress = None

PROFILES = ((9, 9, zlib.Z_DEFAULT_STRATEGY), (9, 9, zlib.Z_FILTERED),
            (6, 9, zlib.Z_DEFAULT_STRATEGY), (1, 9, zlib.Z_DEFAULT_STRATEGY),
            (9, 6, zlib.Z_DEFAULT_STRATEGY), (9, 6, zlib.Z_FILTERED),
            (9, 7, zlib.Z_DEFAULT_STRATEGY), (9, 7, zlib.Z_FILTERED),
            (9, 8, zlib.Z_FILTERED))


def optimize_source_archive(path, *, max_members, max_member_bytes, max_uncompressed_bytes, preserve_modes=False):
    """Keep every member's bytes; replace the archive only when it gets smaller.

    Files remain ordinary unencrypted ZIP method 8, readable without an extra
    dependency. No extraction occurs. A failed rewrite leaves the input intact.
    """
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("source archive must be a regular file")
    before_size = path.stat().st_size
    before_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    temporary = None
    choices, hashes, entries, permissions = Counter(), {}, [], {}
    try:
        with zipfile.ZipFile(path) as source, path.open("rb") as raw:
            members = source.infolist()
            if (len(members) > min(max_members, 65535)
                    or len({m.filename for m in members}) != len(members)
                    or sum(m.file_size for m in members) > max_uncompressed_bytes):
                raise ValueError("source archive exceeds member or expanded bounds")
            for member in members:
                name = member.filename
                mode = member.external_attr >> 16
                if (not name or name.startswith("/") or "\\" in name or "\x00" in name
                        or ":" in name.split("/", 1)[0] or ".." in PurePosixPath(name).parts
                        or member.is_dir() or member.flag_bits & 1
                        or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
                        or member.compress_type != zipfile.ZIP_DEFLATED
                        or member.file_size > max_member_bytes):
                    raise ValueError("invalid source archive member")
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".deflate-",
                                             delete=False) as output:
                temporary = Path(output.name)
                for member in members:
                    data = source.read(member)  # Also verifies the original CRC.
                    hashes[member.filename] = hashlib.sha256(data).hexdigest()
                    mode = member.external_attr >> 16
                    if preserve_modes and (stat.S_IFMT(mode) != stat.S_IFREG
                                           or stat.S_IMODE(mode) not in (0o644, 0o755)):
                        raise ValueError("invalid portable API member permissions")
                    permissions[member.filename] = mode if preserve_modes else 0o100644
                    raw.seek(member.header_offset)
                    header = raw.read(30)
                    if len(header) != 30 or header[:4] != b"PK\x03\x04":
                        raise ValueError("invalid source member header")
                    name_length, extra_length = struct.unpack("<HH", header[-4:])
                    raw.seek(name_length + extra_length, 1)
                    packed = raw.read(member.compress_size)
                    if len(packed) != member.compress_size or zlib.decompress(packed, -15) != data:
                        raise ValueError("invalid source member stream")
                    selected = "original"
                    for level, memory, strategy in PROFILES:
                        compressor = zlib.compressobj(level, zlib.DEFLATED, -15, memory, strategy)
                        candidate = compressor.compress(data) + compressor.flush()
                        if len(candidate) < len(packed):
                            packed, selected = candidate, f"{level}/{memory}/{strategy}"
                    if zopfli_compress and member.filename in {
                            "release.json", "peaso_release.json", "peaso/rulepacks/compliance_lookup.json",
                            "peaso/rulepacks/compliance_requirements.json", "peaso/rulepacks/runtime_metadata.json", "peaso/rulepacks/check_descriptions.json",
                            "peaso/rulepacks/native_catalog.json",
                            "peaso/rulepacks/upstream_manifest.json"}:
                        candidate = zopfli_compress(data, numiterations=15)[2:-4]
                        if len(candidate) < len(packed):
                            packed, selected = candidate, "zopfli/15"
                    choices[selected] += 1
                    name = member.filename.encode("utf-8")
                    if len(name) > 65535:
                        raise ValueError("source member name exceeds ZIP bounds")
                    offset, crc, size = output.tell(), zlib.crc32(data), len(data)
                    output.write(struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0x800, 8,
                                             0, 33, crc, len(packed), size, len(name), 0))
                    output.write(name)
                    output.write(packed)
                    entries.append((name, crc, len(packed), size, offset, permissions[member.filename]))
                central = output.tell()
                for name, crc, packed_size, size, offset, mode in entries:
                    output.write(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, (3 << 8) | 20,
                                             20, 0x800, 8, 0, 33, crc, packed_size, size,
                                             len(name), 0, 0, 0, 0, mode << 16, offset))
                    output.write(name)
                length, count = output.tell() - central, len(entries)
                output.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, count, count, length, central, 0))
        with zipfile.ZipFile(temporary) as result:
            if (len(result.infolist()) != len(hashes)
                    or {m.filename for m in result.infolist()} != set(hashes)
                    or any(hashlib.sha256(result.read(name)).hexdigest() != digest
                           for name, digest in hashes.items())
                    or any(m.compress_type != 8 or m.flag_bits & 1
                           or m.external_attr >> 16 != permissions[m.filename] for m in result.infolist())):
                raise ValueError("rewritten source archive differs from its source")
        applied = temporary.stat().st_size < before_size
        if applied:
            os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))
            os.replace(temporary, path)
        after_size = path.stat().st_size
        return {"applied": applied, "archive_bytes_before": before_size,
                "archive_bytes_after": after_size, "saved_bytes": before_size - after_size,
                "archive_sha256_before": before_sha,
                "archive_sha256_after": hashlib.sha256(path.read_bytes()).hexdigest(),
                "members": len(entries), "file_bytes_verified_unchanged": True,
                "compression_method": "standard ZIP DEFLATE", "profiles_selected": dict(choices)}
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
