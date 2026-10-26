"""Fast, exact decoding of one 512-byte tar header for the layer indexer.

`header(buf)` returns the fields the indexer reads with the same values
`tarfile.TarInfo.frombuf(buf, 'utf-8', 'strict')` gives. It handles the common
ustar/GNU shapes itself (octal numbers, a checksum that matches the unsigned
sum) and hands every other block to `frombuf`, so unusual or invalid headers
get the standard library's own answer or error.
"""
import struct
import tarfile

_LAYOUT = struct.Struct('100s8s8s8s12s12s8sc100s8x32s32s8s8s155s12x')
_NUMERIC = (100, 108, 116, 124, 136, 148, 329, 337)
_BASE256 = (0o200, 0o377)
_GNU_TYPES = frozenset(tarfile.GNU_TYPES)


class Header:
    __slots__ = ('name', 'linkname', 'size', 'type', 'devmajor', 'devminor')

    def __init__(self, name, linkname, size, type_, devmajor, devminor):
        self.name, self.linkname, self.size = name, linkname, size
        self.type, self.devmajor, self.devminor = type_, devmajor, devminor


def _text(field, encoding):
    end = field.find(b'\0')
    return (field if end == -1 else field[:end]).decode(encoding, 'strict')


def _number(field):
    return int(_text(field, 'ascii').strip() or '0', 8)


def _standard(buf):
    member = tarfile.TarInfo.frombuf(buf, 'utf-8', 'strict')
    return Header(member.name, member.linkname, member.size, member.type,
                  member.devmajor, member.devminor)


def header(buf):
    if len(buf) != tarfile.BLOCKSIZE or any(buf[at] in _BASE256 for at in _NUMERIC):
        return _standard(buf)
    (name, mode, uid, gid, size, mtime, chksum, type_, linkname,
     uname, gname, devmajor, devminor, prefix) = _LAYOUT.unpack(buf)
    try:
        if _number(chksum) != 256 + sum(buf) - sum(buf[148:156]):
            return _standard(buf)  # signed-sum tars and bad checksums
        for field in (mode, uid, gid, mtime):
            _number(field)
        size, devmajor, devminor = _number(size), _number(devmajor), _number(devminor)
        name, linkname = _text(name, 'utf-8'), _text(linkname, 'utf-8')
        _text(uname, 'utf-8'), _text(gname, 'utf-8')
        prefix = _text(prefix, 'utf-8')
    except ValueError:
        return _standard(buf)  # raises the standard library's own error
    if type_ == tarfile.GNUTYPE_SPARSE or not buf.count(0) < tarfile.BLOCKSIZE:
        return _standard(buf)
    if type_ == tarfile.AREGTYPE and name.endswith('/'):
        type_ = tarfile.DIRTYPE
    if type_ == tarfile.DIRTYPE:
        name = name.rstrip('/')
    if prefix and type_ not in _GNU_TYPES:
        name = prefix + '/' + name
    return Header(name, linkname, size, type_, devmajor, devminor)
