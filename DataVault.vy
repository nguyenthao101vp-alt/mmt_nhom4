# pragma version ^0.4.0
"""DataVault: Batch + EncCid (C1.x, C1.y, ct) + yêu cầu truy cập + EncCid đã bảo vệ lại cho Requester."""
interface ACL:
    def roleOf(a: address) -> uint8: view
    def openAccessRequest(requester: address) -> uint256: nonpayable

interface DKG:
    def currentEpoch(owner: address) -> uint32: view

P: constant(uint256) = 115792089237316195423570985008687907853269984665640564039457584007908834671663
MAX_ITEMS: constant(uint256) = 64

struct Batch:
    owner: address
    ts: uint64
    n: uint16
    t: uint16
    dataId: bytes32
    keyEpoch: uint32
    fileType: uint8

struct EncCid:
    c1x: uint256
    c1y: uint256
    ct: bytes32

struct AccessReq:
    requester: address
    ts: uint64
    batchId: uint32
    pkX: uint256
    pkY: uint256

acl: public(immutable(address))
dkg: public(immutable(address))
deployer: public(immutable(address))
telg: public(address)
nextBatchId: public(uint256)
batches: HashMap[uint256, Batch]
encCids: HashMap[uint256, DynArray[EncCid, MAX_ITEMS]]
access: HashMap[uint256, AccessReq]
reenc: HashMap[uint256, DynArray[EncCid, MAX_ITEMS]]

event BatchCreated:
    batchId: indexed(uint256)
    dataOwner: indexed(address)
    dataId: bytes32
    keyEpoch: uint32
event EncCidAdded:
    batchId: indexed(uint256)
    index: uint256
event AccessRequested:
    reqId: indexed(uint256)
    requester: indexed(address)
    batchId: indexed(uint256)
event RequesterCidsStored:
    reqId: indexed(uint256)
    count: uint256


@deploy
def __init__(_acl: address, _dkg: address):
    acl = _acl
    dkg = _dkg
    deployer = msg.sender
    self.nextBatchId = 1


@external
def setTelg(_telg: address):
    assert msg.sender == deployer and self.telg == empty(address), "DV: set once"
    self.telg = _telg


@internal
@pure
def _on_curve(x: uint256, y: uint256) -> bool:
    lhs: uint256 = uint256_mulmod(y, y, P)
    x2: uint256 = uint256_mulmod(x, x, P)
    return lhs == uint256_addmod(uint256_mulmod(x2, x, P), 7, P)


@external
def createBatch(dataId: bytes32, n: uint16, t: uint16, fileType: uint8) -> uint256:
    assert staticcall ACL(acl).roleOf(msg.sender) == 1, "DV: not DO"
    epoch: uint32 = staticcall DKG(dkg).currentEpoch(msg.sender)
    assert epoch != 0, "DV: no group key"
    assert t >= 1 and t <= n, "DV: bad IDA params"
    bid: uint256 = self.nextBatchId
    self.nextBatchId = bid + 1
    self.batches[bid] = Batch(owner=msg.sender, ts=convert(block.timestamp, uint64), n=n, t=t,
                              dataId=dataId, keyEpoch=epoch, fileType=fileType)
    log BatchCreated(bid, msg.sender, dataId, epoch)
    return bid


@external
def addEncCid(batchId: uint256, c1x: uint256, c1y: uint256, ct: bytes32):
    assert self.batches[batchId].owner == msg.sender, "DV: not batch owner"
    assert self._on_curve(c1x, c1y), "DV: C1 off curve"
    self.encCids[batchId].append(EncCid(c1x=c1x, c1y=c1y, ct=ct))
    log EncCidAdded(batchId, len(self.encCids[batchId]) - 1)


@external
def addEncCids(batchId: uint256, c1x: DynArray[uint256, MAX_ITEMS], c1y: DynArray[uint256, MAX_ITEMS],
               ct: DynArray[bytes32, MAX_ITEMS]):
    """Gửi cả lô trong một giao dịch: tiết kiệm 21.000 gas cơ bản cho mỗi CID."""
    assert self.batches[batchId].owner == msg.sender, "DV: not batch owner"
    assert len(c1x) == len(c1y) and len(c1x) == len(ct) and len(c1x) > 0, "DV: length"
    for i: uint256 in range(MAX_ITEMS):
        if i >= len(c1x):
            break
        assert self._on_curve(c1x[i], c1y[i]), "DV: C1 off curve"
        self.encCids[batchId].append(EncCid(c1x=c1x[i], c1y=c1y[i], ct=ct[i]))
    log EncCidAdded(batchId, len(self.encCids[batchId]) - 1)


@external
def requestDataAccess(batchId: uint256, pkX: uint256, pkY: uint256) -> uint256:
    assert self.batches[batchId].owner != empty(address), "DV: no batch"
    assert self._on_curve(pkX, pkY), "DV: pk off curve"
    rid: uint256 = extcall ACL(acl).openAccessRequest(msg.sender)
    self.access[rid] = AccessReq(requester=msg.sender, ts=convert(block.timestamp, uint64),
                                 batchId=convert(batchId, uint32), pkX=pkX, pkY=pkY)
    log AccessRequested(rid, msg.sender, batchId)
    return rid


@external
def storeRequesterCids(reqId: uint256, c1x: DynArray[uint256, MAX_ITEMS], c1y: DynArray[uint256, MAX_ITEMS],
                       ct: DynArray[bytes32, MAX_ITEMS]):
    assert msg.sender == self.telg, "DV: not TElG"
    a: AccessReq = self.access[reqId]
    assert a.requester != empty(address), "DV: no request"
    expected: uint256 = len(self.encCids[convert(a.batchId, uint256)])
    assert len(c1x) == expected and len(c1y) == expected and len(ct) == expected, "DV: incomplete"
    for i: uint256 in range(MAX_ITEMS):
        if i >= expected:
            break
        assert self._on_curve(c1x[i], c1y[i]), "DV: C1' off curve"
        self.reenc[reqId].append(EncCid(c1x=c1x[i], c1y=c1y[i], ct=ct[i]))
    log RequesterCidsStored(reqId, expected)


@view
@external
def getBatch(batchId: uint256) -> Batch:
    return self.batches[batchId]


@view
@external
def encCidCount(batchId: uint256) -> uint256:
    return len(self.encCids[batchId])


@view
@external
def getEncCids(batchId: uint256) -> (DynArray[uint256, MAX_ITEMS], DynArray[uint256, MAX_ITEMS], DynArray[bytes32, MAX_ITEMS]):
    xs: DynArray[uint256, MAX_ITEMS] = []
    ys: DynArray[uint256, MAX_ITEMS] = []
    cs: DynArray[bytes32, MAX_ITEMS] = []
    for e: EncCid in self.encCids[batchId]:
        xs.append(e.c1x)
        ys.append(e.c1y)
        cs.append(e.ct)
    return xs, ys, cs


@view
@external
def getRequesterCids(reqId: uint256) -> (DynArray[uint256, MAX_ITEMS], DynArray[uint256, MAX_ITEMS], DynArray[bytes32, MAX_ITEMS]):
    xs: DynArray[uint256, MAX_ITEMS] = []
    ys: DynArray[uint256, MAX_ITEMS] = []
    cs: DynArray[bytes32, MAX_ITEMS] = []
    for e: EncCid in self.reenc[reqId]:
        xs.append(e.c1x)
        ys.append(e.c1y)
        cs.append(e.ct)
    return xs, ys, cs
