# pragma version ^0.4.0
"""DKG: lưu t cam kết Feldman đã gộp (PK = C_0). Không lưu khóa bí mật."""
interface ACL:
    def roleOf(a: address) -> uint8: view
    def isApproved(rid: uint256) -> bool: view
    def kindOf(rid: uint256) -> uint8: view
    def threshold() -> uint8: view
    def shareholderCount() -> uint8: view
    def subjectOf(rid: uint256) -> address: view
    def markDone(rid: uint256): nonpayable

P: constant(uint256) = 115792089237316195423570985008687907853269984665640564039457584007908834671663
MAX_C: constant(uint256) = 32

struct Key:
    t: uint8
    n: uint8
    c: DynArray[uint256, MAX_C]

acl: public(immutable(address))
currentEpoch: public(HashMap[address, uint32])
keys: HashMap[address, HashMap[uint32, Key]]

event KeyStored:
    dataOwner: indexed(address)
    epoch: indexed(uint32)
    pkX: uint256
    pkY: uint256
    reqId: uint256


@deploy
def __init__(_acl: address):
    acl = _acl


@internal
@pure
def _on_curve(x: uint256, y: uint256) -> bool:
    # y^2 == x^3 + 7 (mod P)
    lhs: uint256 = uint256_mulmod(y, y, P)
    x2: uint256 = uint256_mulmod(x, x, P)
    rhs: uint256 = uint256_addmod(uint256_mulmod(x2, x, P), 7, P)
    return lhs == rhs


@external
def storeKeyCommit(reqId: uint256, t: uint8, n: uint8, c: DynArray[uint256, MAX_C]):
    assert staticcall ACL(acl).roleOf(msg.sender) == 2, "DKG: not SH"
    assert staticcall ACL(acl).isApproved(reqId), "DKG: not approved"
    assert staticcall ACL(acl).kindOf(reqId) == 0, "DKG: wrong kind"
    assert t == staticcall ACL(acl).threshold() and n == staticcall ACL(acl).shareholderCount(), "DKG: params"
    assert len(c) == convert(t, uint256) * 2, "DKG: commit length"
    for i: uint256 in range(MAX_C // 2):
        if 2 * i >= len(c):
            break
        assert self._on_curve(c[2 * i], c[2 * i + 1]), "DKG: off curve"
    owner: address = staticcall ACL(acl).subjectOf(reqId)
    epoch: uint32 = self.currentEpoch[owner] + 1
    self.currentEpoch[owner] = epoch
    self.keys[owner][epoch] = Key(t=t, n=n, c=c)
    extcall ACL(acl).markDone(reqId)
    log KeyStored(owner, epoch, c[0], c[1], reqId)


@view
@external
def getKey(owner: address, epoch: uint32) -> (uint8, uint8, uint256, uint256, DynArray[uint256, MAX_C]):
    k: Key = self.keys[owner][epoch]
    assert k.t != 0, "DKG: no key"
    return k.t, k.n, k.c[0], k.c[1], k.c
