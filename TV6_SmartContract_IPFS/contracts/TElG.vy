# pragma version ^0.4.0
"""TElG: nhận kết quả bảo vệ lại từ Shareholder khi yêu cầu đã đủ ngưỡng; lưu băm bằng chứng Chaum-Pedersen."""
MAX_ITEMS: constant(uint256) = 64

interface ACL:
    def roleOf(a: address) -> uint8: view
    def isApproved(rid: uint256) -> bool: view
    def kindOf(rid: uint256) -> uint8: view
    def markDone(rid: uint256): nonpayable

interface Vault:
    def storeRequesterCids(reqId: uint256, c1x: DynArray[uint256, MAX_ITEMS], c1y: DynArray[uint256, MAX_ITEMS],
                           ct: DynArray[bytes32, MAX_ITEMS]): nonpayable

acl: public(immutable(address))
vault: public(immutable(address))
reencDone: public(HashMap[uint256, bool])
proofHash: public(HashMap[uint256, bytes32])

event ReencResultSubmitted:
    reqId: indexed(uint256)
    submitter: indexed(address)
    proofHash: bytes32


@deploy
def __init__(_acl: address, _vault: address):
    acl = _acl
    vault = _vault


@external
def submitReencResult(reqId: uint256, c1x: DynArray[uint256, MAX_ITEMS], c1y: DynArray[uint256, MAX_ITEMS],
                      ct: DynArray[bytes32, MAX_ITEMS], proofsHash: bytes32):
    assert staticcall ACL(acl).roleOf(msg.sender) == 2, "TElG: not SH"
    assert staticcall ACL(acl).kindOf(reqId) == 1, "TElG: wrong kind"
    assert staticcall ACL(acl).isApproved(reqId), "TElG: not approved"
    assert not self.reencDone[reqId], "TElG: processed"
    self.reencDone[reqId] = True
    self.proofHash[reqId] = proofsHash
    extcall Vault(vault).storeRequesterCids(reqId, c1x, c1y, ct)
    extcall ACL(acl).markDone(reqId)
    log ReencResultSubmitted(reqId, msg.sender, proofsHash)
