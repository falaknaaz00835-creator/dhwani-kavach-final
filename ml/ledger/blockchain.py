"""
ml/ledger/blockchain.py - Tamper-Proof Evidence Ledger for Dhwani-Kavach v2
SIH26188 (MHA/I4C) Theme: Blockchain & Cybersecurity

Implements a local cryptographically linked evidence chain.
Each block hashes its index, timestamp, evidence payload, and previous block hash using SHA-256.
"""

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple


class EvidenceBlock:
    def __init__(
        self,
        index: int,
        timestamp: str,
        data: Dict[str, Any],
        previous_hash: str,
        block_hash: Optional[str] = None,
    ):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = block_hash or self.calculate_hash()

    def calculate_hash(self) -> str:
        # Strict deterministic canonical JSON representation of data
        data_str = json.dumps(self.data, sort_keys=True, ensure_ascii=False)
        raw = f"{self.index}|{self.timestamp}|{data_str}|{self.previous_hash}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EvidenceBlock":
        return cls(
            index=d["index"],
            timestamp=d["timestamp"],
            data=d["data"],
            previous_hash=d["previous_hash"],
            block_hash=d.get("hash"),
        )


class EvidenceChain:
    def __init__(self, storage_path: str = "data/evidence_chain.json"):
        self.storage_path = storage_path
        self.chain: List[EvidenceBlock] = []
        self.is_tampered: bool = False
        # Ensure parent directory exists
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        self.load_chain()

    def _create_genesis_block(self) -> EvidenceBlock:
        genesis_data = {
            "event": "GENESIS_INITIALIZATION",
            "system": "Dhwani-Kavach v2 Multimodal Screening Ledger",
            "track": "SIH26188 - Ministry of Home Affairs / I4C",
            "law": "Section 63 Bharatiya Sakshya Adhiniyam 2023",
        }
        timestamp = "2026-09-26T00:00:00+05:30"
        return EvidenceBlock(
            index=0,
            timestamp=timestamp,
            data=genesis_data,
            previous_hash="0" * 64,
        )

    def load_chain(self, force: bool = False) -> None:
        if getattr(self, "is_tampered", False) and not force:
            return
        if os.path.exists(self.storage_path) and os.path.getsize(self.storage_path) > 0:
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    raw_list = json.load(f)
                self.chain = [EvidenceBlock.from_dict(b) for b in raw_list]
                if self.chain:
                    return
            except Exception:
                pass  # Fall back to creating genesis block if corrupted/unreadable

        # Initialize with genesis block
        genesis = self._create_genesis_block()
        self.chain = [genesis]
        self.save_chain()

    def save_chain(self) -> None:
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        with open(self.storage_path, "w", encoding="utf-8") as f:
            json.dump([b.to_dict() for b in self.chain], f, indent=2, ensure_ascii=False)

    def get_latest_block(self) -> EvidenceBlock:
        if not self.chain:
            self.load_chain()
        return self.chain[-1]

    def add_block(self, data: Dict[str, Any]) -> EvidenceBlock:
        latest = self.get_latest_block()
        new_index = len(self.chain)
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S+05:30")
        new_block = EvidenceBlock(
            index=new_index,
            timestamp=timestamp,
            data=data,
            previous_hash=latest.hash,
        )
        self.chain.append(new_block)
        self.save_chain()
        return new_block

    def validate_chain(self, reload_from_disk: bool = True) -> Tuple[bool, Optional[str], int]:
        """
        Validates the entire chain:
        1. Every block's recomputed hash must match its stored hash.
        2. Every block's previous_hash must match the hash of the preceding block.
        Returns: (is_valid, error_description, total_block_count)
        """
        if reload_from_disk:
            self.load_chain()

        if not self.chain:
            return False, "Chain is empty", 0

        # Validate genesis block
        genesis = self.chain[0]
        if genesis.index != 0 or genesis.previous_hash != "0" * 64:
            return False, f"Genesis block structure invalid at index 0", len(self.chain)
        if genesis.hash != genesis.calculate_hash():
            return False, f"Genesis block hash mismatch (tampering detected at index 0)", len(self.chain)

        # Walk through subsequent blocks
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # Check 1: Has this block's data or hash been altered?
            if current.hash != current.calculate_hash():
                return False, f"Block #{current.index} data/hash tampering detected", len(self.chain)

            # Check 2: Is the linkage to the previous block broken?
            if current.previous_hash != previous.hash:
                return False, f"Block #{current.index} previous_hash mismatch (chain link broken)", len(self.chain)

        return True, None, len(self.chain)

    def get_recent_blocks(self, limit: int = 5) -> List[Dict[str, Any]]:
        self.load_chain()
        blocks = self.chain[-limit:]
        return [b.to_dict() for b in reversed(blocks)]

    def simulate_tamper(self, block_index: int = 1) -> Dict[str, Any]:
        """Subtly alters block data in memory to demonstrate cryptographic tamper detection."""
        if len(self.chain) <= 1:
            self.add_block({
                "case_id": "KAVACH-DEMO-01",
                "verdict": "AUTHENTIC",
                "holder": "RAJESH KUMAR SHARMA",
                "status": "CLEAR"
            })
        
        idx = min(block_index, len(self.chain) - 1)
        target = self.chain[idx]
        original_data = dict(target.data)
        # Malicious in-place alteration without re-signing hash
        target.data = dict(target.data)
        target.data["holder"] = "MALICIOUS_IMPOSTOR_VIKRAM"
        target.data["tampered_in_storage"] = True
        self.is_tampered = True
        return {
            "tampered_block_index": idx,
            "original_holder": original_data.get("holder", "RAJESH KUMAR SHARMA"),
            "tampered_holder": target.data["holder"],
            "stored_hash": target.hash,
            "actual_recomputed_hash": target.calculate_hash()
        }

    def reset_tamper(self) -> None:
        """Reloads pristine persistent chain from disk."""
        self.is_tampered = False
        self.load_chain(force=True)


# Global singleton instance for application use
_default_chain: Optional[EvidenceChain] = None


def get_evidence_chain() -> EvidenceChain:
    global _default_chain
    if _default_chain is None:
        _default_chain = EvidenceChain("data/evidence_chain.json")
    return _default_chain
