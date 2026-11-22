"""Mạng IPFS thu nhỏ viết bằng Python: nhiều nút, mỗi nút một blockstore riêng, nội dung định danh theo CIDv0.

CID được tính đúng như `ipfs add` mặc định (UnixFS + dag-pb, khối 256 KiB, CIDv0, sha2-256), nên digest 32 byte
dùng để bảo vệ trên chuỗi khớp với Kubo. Khác Kubo: không có DHT/Bitswap thật; nút đọc khối từ các nút còn sống
(giả lập đường truyền bằng tham số bandwidth_mbps và rtt_ms nếu cần). Dùng để chạy thử và đo phần mật mã/chuỗi.
"""
from __future__ import annotations

import hashlib
import time

_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
CHUNK = 262144          # 256 KiB, mặc định của Kubo
FANOUT = 174            # số liên kết tối đa mỗi nút trung gian (balanced DAG của Kubo)


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _ALPHABET[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _ALPHABET.index(ch)
    return b"\0" * (len(s) - len(s.lstrip("1"))) + n.to_bytes((n.bit_length() + 7) // 8, "big")


def cid_to_digest(cid: str) -> bytes:
    raw = b58decode(cid)
    assert raw[:2] == b"\x12\x20" and len(raw) == 34, "không phải CIDv0 sha2-256"
    return raw[2:]


def digest_to_cid(d: bytes) -> str:
    assert len(d) == 32
    return b58encode(b"\x12\x20" + d)


# ------------------------------------------------------------------ protobuf tối thiểu cho dag-pb / UnixFS
def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _field_bytes(num: int, payload: bytes) -> bytes:
    return _varint(num << 3 | 2) + _varint(len(payload)) + payload


def _field_varint(num: int, v: int) -> bytes:
    return _varint(num << 3) + _varint(v)


def _unixfs(data: bytes | None, filesize: int, blocksizes: list[int]) -> bytes:
    m = _field_varint(1, 2)                         # Type = File
    if data is not None:
        m += _field_bytes(2, data)
    m += _field_varint(3, filesize)
    for b in blocksizes:
        m += _field_varint(4, b)
    return m


def _pbnode(links: list[tuple[bytes, int]], unixfs: bytes) -> bytes:
    out = b""
    for h, tsize in links:                          # PBLink: Hash(1), Name(2) = "", Tsize(3)
        out += _field_bytes(2, _field_bytes(1, h) + _field_bytes(2, b"") + _field_varint(3, tsize))
    return out + _field_bytes(1, unixfs)            # Links trước, rồi Data


def _mh(block: bytes) -> bytes:
    return b"\x12\x20" + hashlib.sha256(block).digest()


def build_dag(data: bytes) -> tuple[str, dict[bytes, bytes]]:
    """Trả về (CIDv0 gốc, {multihash: khối})."""
    store: dict[bytes, bytes] = {}
    leaves = []                                     # (multihash, tsize, filesize)
    pieces = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)] or [b""]
    for p in pieces:
        blk = _pbnode([], _unixfs(p, len(p), []))
        h = _mh(blk)
        store[h] = blk
        leaves.append((h, len(blk), len(p)))
    level = leaves
    if len(level) == 1:
        return b58encode(level[0][0]), store
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), FANOUT):
            grp = level[i:i + FANOUT]
            fs = sum(g[2] for g in grp)
            blk = _pbnode([(g[0], g[1]) for g in grp], _unixfs(None, fs, [g[2] for g in grp]))
            h = _mh(blk)
            store[h] = blk
            nxt.append((h, len(blk) + sum(g[1] for g in grp), fs))
        level = nxt
    return b58encode(level[0][0]), store


# ------------------------------------------------------------------ parse khối để đọc lại
def _read_varint(b: bytes, i: int) -> tuple[int, int]:
    n = shift = 0
    while True:
        c = b[i]
        i += 1
        n |= (c & 0x7F) << shift
        if not c & 0x80:
            return n, i
        shift += 7


def _parse(b: bytes) -> list[tuple[int, int | bytes]]:
    i, out = 0, []
    while i < len(b):
        tag, i = _read_varint(b, i)
        if tag & 7 == 2:
            ln, i = _read_varint(b, i)
            out.append((tag >> 3, b[i:i + ln]))
            i += ln
        else:
            v, i = _read_varint(b, i)
            out.append((tag >> 3, v))
    return out


def _decode_block(blk: bytes) -> tuple[list[bytes], bytes]:
    links, data = [], b""
    for num, v in _parse(blk):
        if num == 2:
            links.append(next(x for n2, x in _parse(v) if n2 == 1))
        elif num == 1:
            data = next((x for n2, x in _parse(v) if n2 == 2), b"")
    return links, data


class IpfsNetworkPy:
    def __init__(self, n_nodes: int, bandwidth_mbps: float | None = None, rtt_ms: float = 0.0):
        self.nodes = [NodePy(self, i) for i in range(n_nodes)]
        self.bandwidth_mbps, self.rtt_ms = bandwidth_mbps, rtt_ms

    def _delay(self, nbytes: int):
        d = self.rtt_ms / 1000
        if self.bandwidth_mbps:
            d += nbytes * 8 / (self.bandwidth_mbps * 1e6)
        if d:
            time.sleep(d)


class NodePy:
    def __init__(self, net: IpfsNetworkPy, idx: int):
        self.net, self.idx, self.alive = net, idx, True
        self.blocks: dict[bytes, bytes] = {}
        self.pinned: set[str] = set()

    def add(self, data: bytes) -> str:
        cid, blocks = build_dag(data)
        self.blocks.update(blocks)
        self.pinned.add(cid)
        return cid

    def _get_block(self, mh: bytes, timeout_ms: int = 0) -> bytes:
        if mh in self.blocks:
            return self.blocks[mh]
        for peer in self.net.nodes:
            if peer is not self and peer.alive and mh in peer.blocks:
                blk = peer.blocks[mh]
                assert hashlib.sha256(blk).digest() == mh[2:], "khối sai hash"
                self.net._delay(len(blk))
                self.blocks[mh] = blk                # nút nhận cũng giữ bản sao (như Bitswap)
                return blk
        raise TimeoutError("không tìm thấy khối trên nút nào còn sống")

    def cat(self, cid: str, timeout_ms: int = 30000) -> bytes:
        def walk(mh: bytes) -> bytes:
            links, data = _decode_block(self._get_block(mh, timeout_ms))
            return data + b"".join(walk(l) for l in links)
        return walk(b58decode(cid))

    def pin(self, cid: str) -> None:
        self.cat(cid)
        self.pinned.add(cid)

    def kill(self):
        self.alive = False
