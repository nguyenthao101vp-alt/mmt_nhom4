# pragma version ^0.4.0
"""
AccessControl (ACSC): vai trò, yêu cầu sinh khóa / truy cập, đếm phê duyệt theo ngưỡng t_SH, chống replay.
Bản Vyper (cú pháp Python) của AccessControl.sol.
"""
DATA_OWNER: constant(uint8) = 1
SHAREHOLDER: constant(uint8) = 2
REQUESTER: constant(uint8) = 3

KIND_KEYGEN: constant(uint8) = 0
KIND_ACCESS: constant(uint8) = 1

struct Request:
    subject: address
    ts: uint64
    kind: uint8
    approvals: uint8
    approved: bool
    done: bool

owner: public(immutable(address))
threshold: public(uint8)
shareholderCount: public(uint8)
roleOf: public(HashMap[address, uint8])
isModule: public(HashMap[address, bool])
usedAuth: public(HashMap[bytes32, bool])
voted: public(HashMap[uint256, HashMap[address, bool]])
reqs: HashMap[uint256, Request]
requestCount: public(uint256)

event RoleSet:
    account: indexed(address)
    role: uint8
event ThresholdSet:
    t: uint8
    n: uint8
event KeyGenRequested:
    id: indexed(uint256)
    dataOwner: indexed(address)
    authHash: bytes32
event AccessRequestOpened:
    id: indexed(uint256)
    requester: indexed(address)
event Approved:
    id: indexed(uint256)
    shareholder: indexed(address)
    approvals: uint8
event RequestApproved:
    id: indexed(uint256)
event RequestDone:
    id: indexed(uint256)


@deploy
def __init__():
    owner = msg.sender


@external
def setRole(account: address, role: uint8):
    assert msg.sender == owner, "ACL: not owner"
    assert role <= REQUESTER, "ACL: bad role"
    old: uint8 = self.roleOf[account]
    if old == SHAREHOLDER and role != SHAREHOLDER:
        self.shareholderCount -= 1
    if old != SHAREHOLDER and role == SHAREHOLDER:
        self.shareholderCount += 1
    self.roleOf[account] = role
    log RoleSet(account, role)


@external
def setThreshold(t: uint8):
    """Ngưỡng phải là đa số: t > n/2 và t <= n."""
    assert msg.sender == owner, "ACL: not owner"
    assert t <= self.shareholderCount and convert(t, uint256) * 2 > convert(self.shareholderCount, uint256), "ACL: bad threshold"
    self.threshold = t
    log ThresholdSet(t, self.shareholderCount)


@external
def setModules(dkg: address, telg: address, vault: address):
    assert msg.sender == owner, "ACL: not owner"
    self.isModule[dkg] = True
    self.isModule[telg] = True
    self.isModule[vault] = True


@external
def requestKeyGen(authHash: bytes32) -> uint256:
    """authHash = H(pk_DO, timestamp, nonce); mỗi giá trị chỉ dùng một lần."""
    assert self.roleOf[msg.sender] == DATA_OWNER, "ACL: not DO"
    assert not self.usedAuth[authHash], "ACL: replay"
    self.usedAuth[authHash] = True
    rid: uint256 = self.requestCount
    self.reqs[rid] = Request(subject=msg.sender, ts=convert(block.timestamp, uint64), kind=KIND_KEYGEN,
                             approvals=0, approved=False, done=False)
    self.requestCount = rid + 1
    log KeyGenRequested(rid, msg.sender, authHash)
    return rid


@external
def openAccessRequest(requester: address) -> uint256:
    assert self.isModule[msg.sender], "ACL: not module"
    assert self.roleOf[requester] == REQUESTER, "ACL: not requester"
    rid: uint256 = self.requestCount
    self.reqs[rid] = Request(subject=requester, ts=convert(block.timestamp, uint64), kind=KIND_ACCESS,
                             approvals=0, approved=False, done=False)
    self.requestCount = rid + 1
    log AccessRequestOpened(rid, requester)
    return rid


@external
def approve(rid: uint256):
    """Không phê duyệt = từ chối; mỗi Shareholder một phiếu."""
    assert self.roleOf[msg.sender] == SHAREHOLDER, "ACL: not SH"
    assert rid < self.requestCount, "ACL: no request"
    r: Request = self.reqs[rid]
    assert not r.done, "ACL: closed"
    assert not self.voted[rid][msg.sender], "ACL: voted"
    self.voted[rid][msg.sender] = True
    r.approvals += 1
    log Approved(rid, msg.sender, r.approvals)
    if not r.approved and r.approvals >= self.threshold:
        r.approved = True
        log RequestApproved(rid)
    self.reqs[rid] = r


@external
def markDone(rid: uint256):
    assert self.isModule[msg.sender], "ACL: not module"
    r: Request = self.reqs[rid]
    assert r.approved and not r.done, "ACL: not approved"
    r.done = True
    self.reqs[rid] = r
    log RequestDone(rid)


@view
@external
def isApproved(rid: uint256) -> bool:
    r: Request = self.reqs[rid]
    return r.approved and not r.done


@view
@external
def subjectOf(rid: uint256) -> address:
    return self.reqs[rid].subject


@view
@external
def kindOf(rid: uint256) -> uint8:
    return self.reqs[rid].kind
