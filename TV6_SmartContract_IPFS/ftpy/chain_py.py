"""Chuỗi EVM chạy hoàn toàn bằng Python: py-evm + eth-tester, hợp đồng viết bằng Vyper (biên dịch qua pip).

Không cần Node.js, Hardhat hay solc. Cùng giao diện với Chain (JS/Hardhat) nên mã kịch bản dùng lại được.
"""
from __future__ import annotations

import time
import warnings
from collections import defaultdict
from pathlib import Path

import vyper
from web3 import Web3
from web3.providers.eth_tester import EthereumTesterProvider

warnings.filterwarnings("ignore")
CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"
_cache: dict[str, dict] = {}


def compile_contract(name: str) -> dict:
    if name not in _cache:
        out = vyper.compile_code((CONTRACTS / f"{name}.vy").read_text(), output_formats=["abi", "bytecode"])
        _cache[name] = {"abi": out["abi"], "bytecode": out["bytecode"]}
    return _cache[name]


class ChainPy:
    def __init__(self):
        self.w3 = Web3(EthereumTesterProvider())
        a = self.w3.eth.accounts
        self.owner, self.do, self.shs, self.req = a[0], a[1], a[2:7], a[7]
        self.gas: dict[str, list[int]] = defaultdict(list)
        self.tx_time: dict[str, list[float]] = defaultdict(list)

    def send(self, label: str, fn, sender: str):
        t0 = time.perf_counter()
        h = fn.transact({"from": sender})
        rc = self.w3.eth.wait_for_transaction_receipt(h)
        self.tx_time[label].append(time.perf_counter() - t0)
        assert rc["status"] == 1, f"{label} bị revert"
        self.gas[label].append(rc["gasUsed"])
        return rc

    def _deploy(self, name: str, *args):
        art = compile_contract(name)
        c = self.w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
        h = c.constructor(*args).transact({"from": self.owner})
        rc = self.w3.eth.wait_for_transaction_receipt(h)
        self.gas[f"deploy:{name}"].append(rc["gasUsed"])
        return self.w3.eth.contract(address=rc["contractAddress"], abi=art["abi"])

    def setup(self, t_sh: int = 3):
        self.acl = self._deploy("AccessControl")
        self.dkg = self._deploy("DKG", self.acl.address)
        self.vault = self._deploy("DataVault", self.acl.address, self.dkg.address)
        self.telg = self._deploy("TElG", self.acl.address, self.vault.address)
        self.send("DataVault.setTelg", self.vault.functions.setTelg(self.telg.address), self.owner)
        self.send("ACL.setModules", self.acl.functions.setModules(self.dkg.address, self.telg.address, self.vault.address), self.owner)
        self.send("ACL.setRole(DO)", self.acl.functions.setRole(self.do, 1), self.owner)
        for sh in self.shs:
            self.send("ACL.setRole(SH)", self.acl.functions.setRole(sh, 2), self.owner)
        self.send("ACL.setRole(R)", self.acl.functions.setRole(self.req, 3), self.owner)
        self.send("ACL.setThreshold", self.acl.functions.setThreshold(t_sh), self.owner)

    def request_count(self) -> int:
        return self.acl.functions.requestCount().call()
