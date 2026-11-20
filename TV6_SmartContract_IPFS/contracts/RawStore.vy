# pragma version ^0.4.0
"""Baseline: ghi thẳng dữ liệu lên chuỗi (mỗi 32 byte = 1 slot) để so với Hybrid."""
MAX_WORDS: constant(uint256) = 2048
words: DynArray[bytes32, 65536]

@external
def store(w: DynArray[bytes32, MAX_WORDS]):
    for x: bytes32 in w:
        self.words.append(x)
