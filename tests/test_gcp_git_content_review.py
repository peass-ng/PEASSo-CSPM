"""Offline decoder review fixtures; callable directly, without a pytest session."""
import hashlib
import struct
import time
import zlib

from peaso.collectors import gcp_git_content as git


def oid(kind, data):
    return hashlib.sha1(kind + b" " + str(len(data)).encode() + b"\0" + data).digest()


def header(kind, size):
    first = (kind << 4) | (size & 15)
    size >>= 4
    out = bytearray([first | (128 if size else 0)])
    while size:
        out.append((size & 127) | (128 if size >> 7 else 0))
        size >>= 7
    return bytes(out)


def varint(size):
    out = bytearray()
    while True:
        out.append((size & 127) | (128 if size >> 7 else 0))
        size >>= 7
        if not size:
            return bytes(out)


def ofs(distance):
    result = [distance & 127]
    while distance >> 7:
        distance = (distance >> 7) - 1
        result.append(128 | (distance & 127))
    return bytes(reversed(result))


def literal_delta(base, target):
    out = varint(len(base)) + varint(len(target))
    for start in range(0, len(target), 127):
        part = target[start:start + 127]
        out += bytes([len(part)]) + part
    return out


def pack(entries, version=2):
    """Entries: (kind, data[, base entry index or raw REF identity])."""
    wire = b"PACK" + struct.pack("!II", version, len(entries))
    offsets = []
    for entry in entries:
        kind, data = entry[:2]
        start = len(wire)
        extra = b""
        if kind == 6:
            extra = ofs(start - offsets[entry[2]])
        elif kind == 7:
            extra = entry[2]
        offsets.append(start)
        wire += header(kind, len(data)) + extra + zlib.compress(data)
    return wire + hashlib.sha1(wire).digest()


def fixture(content=b"selected secret fixture\n", mode=b"100644", name=b"config.txt"):
    tree = mode + b" " + name + b"\0" + oid(b"blob", content)
    commit = (b"tree " + oid(b"tree", tree).hex().encode() + b"\n"
              b"author Tester <test@example.invalid> 1 +0000\n"
              b"committer Tester <test@example.invalid> 1 +0000\n\nmessage\n")
    return [(3, content), (2, tree), (1, commit)], oid(b"commit", commit).hex()


def reject(wire, commit, paths=None, **kwargs):
    try:
        git.decode_selected_files(wire, commit, ["config.txt"] if paths is None else paths, **kwargs)
    except git.GitContentError as exc:
        assert str(exc) == "git_content_rejected"
        assert repr(exc) == "GitContentError('git_content_rejected')"
    else:
        raise AssertionError("expected static rejection")


def test_plain_pack_exact_selection_and_safe_repr():
    entries, commit = fixture()
    result = git.decode_selected_files(pack(entries), commit, ["config.txt"])
    assert result.files[0].content == entries[0][1]
    assert result.files[0].object_sha == oid(b"blob", entries[0][1]).hex()
    assert result.object_count == 3
    assert result.inflated_bytes == sum(len(e[1]) for e in entries)
    assert "selected secret" not in repr(result) + repr(result.files[0])
    assert "config.txt" not in repr(result) + repr(result.files[0])
    assert git.decode_selected_files(pack(entries, 3), commit, ["config.txt"]).files == result.files


def test_internal_ofs_delta_copy_insert_and_default_copy_size():
    content = b"a" * 65536 + b"tail"
    entries, commit = fixture(content)
    base = b"a" * 65536
    instructions = varint(len(base)) + varint(len(content)) + b"\x80\x04tail"
    entries = [(3, base), (6, instructions, 0)] + entries[1:]
    result = git.decode_selected_files(pack(entries), commit, ["config.txt"])
    assert result.files[0].content == content
    assert result.inflated_bytes == sum(len(e[1]) for e in entries) + len(content)


def test_forward_ref_delta_and_mixed_chain():
    entries, commit = fixture()
    base = b"base"
    middle = b"middle"
    target = entries[0][1]
    entries = [(7, literal_delta(middle, target), oid(b"blob", middle)),
               (3, base), (6, literal_delta(base, middle), 1)] + entries[1:]
    assert git.decode_selected_files(pack(entries), commit, ["config.txt"]).files[0].content == target


def test_delta_commit_and_tree():
    entries, commit = fixture()
    base_commit = entries[2][1] + b"base\n"
    base_tree = b""
    entries = [entries[0], (1, base_commit), (2, base_tree),
               (6, literal_delta(base_tree, entries[1][1]), 2),
               (7, literal_delta(base_commit, entries[2][1]), oid(b"commit", base_commit))]
    assert git.decode_selected_files(pack(entries), commit, ["config.txt"]).object_count == 5


def test_nested_exact_paths_and_executable_regular_file():
    entries, _ = fixture(mode=b"100755", name=b"file")
    subtree = entries[1][1]
    root = b"40000 dir\0" + oid(b"tree", subtree)
    commit = entries[2][1].replace(oid(b"tree", subtree).hex().encode(), oid(b"tree", root).hex().encode())
    sha = oid(b"commit", commit).hex()
    wire = pack(entries[:2] + [(2, root), (1, commit)])
    assert git.decode_selected_files(wire, sha, ["dir/file"]).files[0].content == entries[0][1]
    reject(wire, sha, ["file"])
    reject(wire, sha, ["dir"])


def test_selection_rejections_before_pack_processing():
    entries, commit = fixture()
    for paths in ([], ["config.txt"] * 2, ["x"] * 9, ["/x"], ["a//b"], ["a/../b"],
                  ["./x"], ["a\\b"], [".git/config"], ["x\n"], ["x\0"], ["é" * 513],
                  ["a/" * 32 + "x"], ["\ud800"], "config.txt", [None]):
        reject(pack(entries), commit, paths)
    for sha in (commit.upper(), "main", "0" * 39, "x" * 40, None):
        reject(pack(entries), sha)


def test_wrong_commit_and_missing_selected_object():
    entries, commit = fixture()
    reject(pack(entries), "0" * 40)
    reject(pack(entries[1:]), commit)
    reject(pack(entries), oid(b"tree", entries[1][1]).hex())
    reject(pack(entries), commit, ["Config.txt"])


def test_checksum_trailing_data_and_wire_type():
    entries, commit = fixture()
    wire = pack(entries)
    reject(wire[:-1] + bytes([wire[-1] ^ 1]), commit)
    reject(wire + b"trailing", commit)
    reject(wire[:-20] + b"trailing" + hashlib.sha1(wire[:-20] + b"trailing").digest(), commit)
    reject(bytearray(wire), commit)
    reject(pack(entries, 1), commit)
    reject(pack([]), commit)


def test_truncated_every_byte():
    entries, commit = fixture()
    wire = pack(entries)
    for end in range(len(wire)):
        reject(wire[:end], commit)


def test_recomputed_checksum_truncated_zlib():
    entries, commit = fixture()
    raw = b"PACK" + struct.pack("!II", 2, 1) + header(3, len(entries[0][1])) + zlib.compress(entries[0][1])[:-2]
    reject(raw + hashlib.sha1(raw).digest(), commit)


def test_huge_varints_and_lying_object_sizes():
    _, commit = fixture()
    for payload in (b"\xb0" + b"\x80" * 20, header(3, git.MAX_OBJECT + 1),
                    header(3, 1) + zlib.compress(b"x" * (git.MAX_OBJECT + 1)),
                    header(3, 30) + zlib.compress(b"short")):
        raw = b"PACK" + struct.pack("!II", 2, 1) + payload
        reject(raw + hashlib.sha1(raw).digest(), commit)


def test_wire_object_and_inflated_limits(monkeypatch):
    entries, commit = fixture()
    wire = pack(entries)
    with monkeypatch.context() as m:
        m.setattr(git, "MAX_WIRE", len(wire) - 1)
        reject(wire, commit)
    with monkeypatch.context() as m:
        m.setattr(git, "MAX_OBJECTS", 2)
        reject(wire, commit)
    with monkeypatch.context() as m:
        m.setattr(git, "MAX_OBJECT", len(entries[2][1]) - 1)
        reject(wire, commit)
    with monkeypatch.context() as m:
        m.setattr(git, "MAX_INFLATED", sum(len(e[1]) for e in entries) - 1)
        reject(wire, commit)


def test_cumulative_delta_intermediates_count(monkeypatch):
    entries, commit = fixture()
    base = b"base"
    entries = [(3, base), (6, literal_delta(base, entries[0][1]), 0)] + entries[1:]
    wire = pack(entries)
    inflated = sum(len(e[1]) for e in entries)
    with monkeypatch.context() as m:
        m.setattr(git, "MAX_INFLATED", inflated)
        reject(wire, commit)


def test_delta_depth_32_accept_33_reject():
    entries, commit = fixture()
    for depth in (32, 33):
        chain = [(3, b"base")]
        previous = b"base"
        for index in range(depth):
            target = entries[0][1] if index == depth - 1 else str(index).encode()
            chain.append((6, literal_delta(previous, target), index))
            previous = target
        wire = pack(chain + entries[1:])
        if depth == 32:
            assert git.decode_selected_files(wire, commit, ["config.txt"]).files[0].content == entries[0][1]
        else:
            reject(wire, commit)


def test_external_ref_base_unresolvable_cycles_and_bad_offsets():
    entries, commit = fixture()
    reject(pack([(7, literal_delta(b"x", entries[0][1]), b"\0" * 20)] + entries[1:]), commit)
    reject(pack([(7, b"\x00\x00", b"a" * 20), (7, b"\x00\x00", b"b" * 20)]), commit)
    for offset in (b"\x00", b"\x01", b"\xff" * 8):
        raw = b"PACK" + struct.pack("!II", 2, 1) + header(6, 2) + offset + zlib.compress(b"\0\0")
        reject(raw + hashlib.sha1(raw).digest(), commit)


def test_delta_opcode_and_sizes_rejected():
    entries, commit = fixture()
    base = b"base"
    for delta in (b"\x80" * 10, b"\x05\x01\x01x", b"\x04\x01\x00",
                  b"\x04\x01\x02xx", b"\x04\x01\x91\xff\x01", b"\x04\x01\x81",
                  b"\x04\x01\x01", b"\x04\x02\x01x", b"\x04" + varint(git.MAX_OBJECT + 1)):
        reject(pack([(3, base), (6, delta, 0)] + entries[1:]), commit)


def test_duplicate_objects_and_unsupported_types():
    entries, commit = fixture()
    reject(pack(entries + [entries[0]]), commit)
    for kind in (0, 4, 5):
        reject(pack(entries + [(kind, b"unused")]), commit)
    # A reconstructed duplicate identity must also fail.
    reject(pack(entries + [(6, literal_delta(entries[0][1], entries[0][1]), 0)]), commit)


def test_selected_symlink_gitlink_and_lfs_rejected():
    for mode in (b"120000", b"160000"):
        entries, commit = fixture(mode=mode)
        reject(pack(entries), commit)
    entries, commit = fixture(b"version https://git-lfs.github.com/spec/v1\noid sha256:123\nsize 12\n")
    reject(pack(entries), commit)


def test_malformed_trees_even_if_unselected():
    entries, commit = fixture()
    blob = oid(b"blob", entries[0][1])
    for data in (b"100644 no-nul", b"100644 x\0short", b"100664 x\0" + blob,
                 b"100644 ../x\0" + blob, b"100644 .git\0" + blob,
                 b"100644 a\0" + blob + b"100644 a\0" + blob,
                 b"100644 z\0" + blob + b"100644 a\0" + blob):
        reject(pack(entries + [(2, data)]), commit)


def test_malformed_commits_even_if_unselected():
    entries, commit = fixture()
    valid = entries[2][1]
    for data in (b"", b"tree 0\n\n", valid.replace(b"author ", b"bad ", 1),
                 valid.replace(b"committer ", b"bad ", 1), valid.replace(b"\n\n", b"\n"),
                 b"\0" + valid, valid.replace(b"author Tester", b"author <invalid>"),
                 valid.replace(b"\n\n", b"\ntree " + b"0" * 40 + b"\n\n")):
        reject(pack(entries + [(1, data)]), commit)


def test_commit_signature_continuation_accepted():
    entries, _ = fixture()
    commit = entries[2][1].replace(b"\n\n", b"\ngpgsig signature\n continuation\n\n")
    sha = oid(b"commit", commit).hex()
    assert git.decode_selected_files(pack(entries[:2] + [(1, commit)]), sha, ["config.txt"]).commit_sha == sha


def test_selected_limits(monkeypatch):
    entries, commit = fixture(b"x" * (git.MAX_FILE + 1))
    reject(pack(entries), commit)
    entries, commit = fixture(b"x" * git.MAX_FILE)
    assert git.decode_selected_files(pack(entries), commit, ["config.txt"]).selected_bytes == git.MAX_FILE
    with monkeypatch.context() as m:
        m.setattr(git, "MAX_SELECTED", git.MAX_FILE - 1)
        reject(pack(entries), commit)


def test_cancel_deadline_and_callback_error():
    entries, commit = fixture()
    wire = pack(entries)
    reject(wire, commit, cancelled=lambda: True)
    reject(wire, commit, deadline=time.monotonic() - 1)
    def throwing():
        raise ValueError("raw exception text")
    reject(wire, commit, cancelled=throwing)
    calls = [0]
    def during():
        calls[0] += 1
        return calls[0] == 12
    reject(wire, commit, cancelled=during)
    assert calls[0] == 12


def test_tree_depth_and_path_byte_boundaries():
    entries, commit = fixture(name=b"x" * 1024)
    assert git.decode_selected_files(pack(entries), commit, ["x" * 1024]).files[0].content == entries[0][1]
    reject(pack(entries), commit, ["x" * 1025])
    content = b"depth fixture"
    blob = (3, content)
    tree = b"100644 x\0" + oid(b"blob", content)
    trees = [(2, tree)]
    for _ in range(31):
        tree = b"40000 d\0" + oid(b"tree", tree)
        trees.append((2, tree))
    commit_data = fixture()[0][2][1].replace(fixture()[0][2][1][5:45], oid(b"tree", tree).hex().encode())
    sha = oid(b"commit", commit_data).hex()
    assert git.decode_selected_files(pack([blob] + trees + [(1, commit_data)]), sha, ["d/" * 31 + "x"]).selected_bytes == len(content)


def test_deadline_and_callback_types_are_static_errors():
    entries, commit = fixture()
    for deadline in (float("nan"), float("inf"), "later", 10 ** 1000):
        reject(pack(entries), commit, deadline=deadline)
    reject(pack(entries), commit, cancelled="callback")


def test_wire_cap_exact_and_inflation_budget_exact(monkeypatch):
    entries, commit = fixture()
    wire = pack(entries)
    with monkeypatch.context() as m:
        m.setattr(git, "MAX_WIRE", len(wire))
        m.setattr(git, "MAX_INFLATED", sum(len(e[1]) for e in entries))
        assert git.decode_selected_files(wire, commit, ["config.txt"]).files[0].content == entries[0][1]


def test_many_selected_files_and_total_boundary():
    content = b"x" * git.MAX_FILE
    blob = oid(b"blob", content)
    tree = b"".join(b"100644 " + str(i).encode() + b"\0" + blob for i in range(8))
    template = fixture()[0][2][1]
    commit = template.replace(template[5:45], oid(b"tree", tree).hex().encode())
    result = git.decode_selected_files(pack([(3, content), (2, tree), (1, commit)]),
                                      oid(b"commit", commit).hex(), [str(i) for i in range(8)])
    assert len(result.files) == 8 and result.selected_bytes == git.MAX_SELECTED


def test_noncontiguous_delta_copy_offset_bytes():
    content = b"abc" * 300
    entries, commit = fixture(content[256:512])
    # offset2 present (0x01 << 8), size2 present (0x01 << 8).
    delta = varint(len(content)) + varint(256) + bytes([0xA2, 1, 1])
    wire = pack([(3, content), (6, delta, 0)] + entries[1:])
    assert git.decode_selected_files(wire, commit, ["config.txt"]).files[0].content == content[256:512]




def test_full_object_limit_and_4096_count_boundary():
    entries, commit = fixture()
    entries += [(3, b"a" * git.MAX_OBJECT)]
    entries += [(3, b"extra" + str(i).encode()) for i in range(git.MAX_OBJECTS - len(entries))]
    wire = pack(entries)
    assert git.decode_selected_files(wire, commit, ["config.txt"]).object_count == git.MAX_OBJECTS
    reject(pack(entries + [(3, b"one-too-many")]), commit)


def test_16mib_all_inflated_exact_boundary():
    entries, commit = fixture()
    remaining = git.MAX_INFLATED - sum(len(e[1]) for e in entries)
    for index in range(16):
        size = min(remaining, git.MAX_OBJECT)
        if size:
            entries.append((3, bytes([index]) * size))
            remaining -= size
    assert remaining == 0
    result = git.decode_selected_files(pack(entries), commit, ["config.txt"])
    assert result.inflated_bytes == git.MAX_INFLATED
    reject(pack(entries + [(3, b"overflow")]), commit)


def test_null_tree_identities_and_duplicate_parents_rejected():
    entries, commit = fixture()
    invalid = [
        (2, b"100644 x\0" + b"\0" * 20),
        (1, entries[2][1].replace(entries[2][1][5:45], b"0" * 40)),
        (1, entries[2][1].replace(b"\nauthor", b"\nparent " + b"a" * 40 + b"\nparent " + b"a" * 40 + b"\nauthor")),
        (1, entries[2][1].replace(b"\nauthor", b"\nparent " + b"0" * 40 + b"\nauthor")),
        (1, entries[2][1].replace(b"Tester <", b"Tester\r <")),
    ]
    for entry in invalid:
        reject(pack(entries + [entry]), commit)


def test_rechecksummed_mutations_never_escape_static_errors():
    entries, commit = fixture()
    wire = pack(entries)
    for index in range(12, len(wire) - 20):
        for mask in (1, 128):
            body = wire[:index] + bytes([wire[index] ^ mask]) + wire[index + 1:-20]
            mutated = body + hashlib.sha1(body).digest()
            try:
                result = git.decode_selected_files(mutated, commit, ["config.txt"])
            except git.GitContentError as exc:
                assert str(exc) == "git_content_rejected"
            else:
                # Changed unused deflate bits may preserve a valid canonical object.
                assert result.files[0].content == entries[0][1]
