import math
import hashlib
from dataclasses import dataclass
from typing import List


# ==============================
# ADRS – address structure
# ==============================

class ADRS:
    """
    Placeholder for the 32-byte SPHINCS+ address structure (spec r3.1 §2.7.3).

    Layout (8 × 32-bit words = 32 bytes):
      word 0      : layer address
      words 1-3   : tree address  (spec uses 3 words; simplified to 1 here)
      word 4      : type
      word 5      : key pair address
      word 6      : chain address / tree height / padding
      word 7      : hash address  / tree index  / padding

    Per spec: setType() zeroes the subsequent three words.

    TODO (integration): expand words 1-3 to the full 96-bit tree address
    required by the SPHINCS+ hypertree (spec §2.7.3).
    """

    # Type constants (spec §2.7.3)
    WOTS_HASH  = 0
    WOTS_PK    = 1
    TREE       = 2
    FORS_TREE  = 3
    FORS_ROOTS = 4
    WOTS_PRF   = 5
    FORS_PRF   = 6

    def __init__(self):
        self._words = [0] * 8  # 8 × 32-bit words

    def copy(self) -> "ADRS":
        a = ADRS()
        a._words = self._words[:]
        return a

    # --- setters ---
    def setLayerAddress(self, v: int):   self._words[0] = v
    def setTreeAddress(self, v: int):    self._words[1] = v   # simplified: 1 word
    def setType(self, v: int):
        self._words[4] = v
        self._words[5] = 0   # zero subsequent words per spec
        self._words[6] = 0
        self._words[7] = 0
    def setKeyPairAddress(self, v: int): self._words[5] = v
    def setChainAddress(self, v: int):   self._words[6] = v
    def setHashAddress(self, v: int):    self._words[7] = v
    def setTreeHeight(self, v: int):     self._words[6] = v
    def setTreeIndex(self, v: int):      self._words[7] = v

    # --- getters ---
    def getKeyPairAddress(self) -> int:  return self._words[5]
    def getTreeHeight(self) -> int:      return self._words[6]
    def getTreeIndex(self) -> int:       return self._words[7]

    def to_bytes(self) -> bytes:
        return b"".join(w.to_bytes(4, "big") for w in self._words)


# ==============================
# SPHINCS+ parameter container
# ==============================

@dataclass
class SphincsParams:
    n: int  # security parameter (bytes)
    w: int  # Winternitz parameter — must be 4, 16, or 256 (spec r3.1 §3.1)
    # placeholders – not used in WOTS+
    h: int = 0
    d: int = 0
    k: int = 0
    t: int = 0

    def __post_init__(self):
        # Derived WOTS+ parameters per SPHINCS+ spec (r3.1 §3.1).
        # len1 = ceil(8n / lg(w))
        self.len1 = math.ceil(8 * self.n / math.log2(self.w))
        # len2 = floor(lg(len1*(w-1)) / lg(w)) + 1
        self.len2 = math.floor(math.log2(self.len1 * (self.w - 1)) / math.log2(self.w)) + 1
        # len  = len1 + len2
        self.len  = self.len1 + self.len2


# ==============================
# Placeholder cryptographic primitives
# ==============================

def PRF(SK_seed: bytes, ADRS_obj: ADRS, n: int) -> bytes:
    """
    Placeholder for PRF(SK.seed, ADRS) → n bytes (spec r3.1 §2.7.2).
    TODO (integration): replace with the keyed PRF from the chosen
    SPHINCS+ instantiation (SHA-2 or SHAKE).
    """
    h = hashlib.sha256()
    h.update(SK_seed)
    h.update(ADRS_obj.to_bytes())
    return h.digest()[:n]


def F(PK_seed: bytes, ADRS_obj: ADRS, M: bytes, n: int) -> bytes:
    """
    Placeholder for F(PK.seed, ADRS, M) → n bytes (spec r3.1 §2.7.1).
    F is defined as T_1, the single-input tweakable hash function.
    TODO (integration): replace with the tweakable hash F from the chosen
    SPHINCS+ instantiation (SHA-2 or SHAKE).
    """
    h = hashlib.sha256()
    h.update(PK_seed)
    h.update(ADRS_obj.to_bytes())
    h.update(M)
    return h.digest()[:n]


def T_len(PK_seed: bytes, ADRS_obj: ADRS, tmp: List[bytes], n: int) -> bytes:
    """
    Placeholder for T_l(PK.seed, ADRS, tmp) → n bytes (spec r3.1 §2.7.1).
    Compresses len n-byte chain ends into a single n-byte public key value.
    TODO (integration): replace with the tweakable hash T_l from the chosen
    SPHINCS+ instantiation (SHA-2 or SHAKE).
    """
    h = hashlib.sha256()
    h.update(PK_seed)
    h.update(ADRS_obj.to_bytes())
    for block in tmp:
        h.update(block)
    return h.digest()[:n]


# ==============================
# Utility: base_w  (spec r3.1 §2.5, Algorithm 1)
# ==============================

def base_w(X: bytes, w: int, out_len: int) -> List[int]:
    """
    base_w(X, w, out_len) – convert byte string X into out_len base-w digits.
    Spec requires out_len ≤ 8*len(X) / lg(w).
    """
    log_w = int(math.log2(w))
    if 2 ** log_w != w:
        raise ValueError("w must be a power of 2")

    bits   = int.from_bytes(X, "big")
    digits = []
    for _ in range(out_len):
        digits.append(bits & (w - 1))
        bits >>= log_w
    digits.reverse()   # big-endian: most-significant digit first
    return digits


# ==============================
# WOTS+ implementation  (spec r3.1 §3)
# ==============================

class WOTSPlus:

    def __init__(self, params: SphincsParams):
        self.params = params

    # ------------------------------------------------------------------
    # Algorithm 2: chain(X, i, s, PK.seed, ADRS)  (spec r3.1 §3.2)
    # ------------------------------------------------------------------

    def chain(self, X: bytes, i: int, s: int,
              PK_seed: bytes, ADRS_obj: ADRS) -> bytes:
        """
        Chaining function: iterate F s times on X starting from position i.
        Returns NULL (raises) if i + s > w - 1.
        """
        n = self.params.n
        w = self.params.w

        if s == 0:
            return X
        if (i + s) > (w - 1):
            raise ValueError("chain: i + s exceeds w - 1")

        tmp = self.chain(X, i, s - 1, PK_seed, ADRS_obj)
        ADRS_obj.setHashAddress(i + s - 1)
        tmp = F(PK_seed, ADRS_obj, tmp, n)
        return tmp

    # ------------------------------------------------------------------
    # Algorithm 3: wots_SKgen(SK.seed, ADRS)  (spec r3.1 §3.3)
    # ------------------------------------------------------------------

    def wots_SKgen(self, SK_seed: bytes, ADRS_obj: ADRS) -> List[bytes]:
        """
        Generate the WOTS+ secret key (len n-byte strings).
        Each sk[i] = PRF(SK.seed, skADRS) where skADRS has type WOTS_PRF.
        """
        n = self.params.n

        skADRS = ADRS_obj.copy()
        skADRS.setType(ADRS.WOTS_PRF)
        skADRS.setKeyPairAddress(ADRS_obj.getKeyPairAddress())

        sk = []
        for i in range(self.params.len):
            skADRS.setChainAddress(i)
            skADRS.setHashAddress(0)
            sk.append(PRF(SK_seed, skADRS, n))
        return sk

    # ------------------------------------------------------------------
    # Algorithm 4: wots_PKgen(SK.seed, PK.seed, ADRS)  (spec r3.1 §3.4)
    # ------------------------------------------------------------------

    def wots_PKgen(self, SK_seed: bytes, PK_seed: bytes,
                   ADRS_obj: ADRS) -> bytes:
        """
        Generate the WOTS+ public key.
        Derives sk internally; compresses all chain ends via T_len.
        Returns a single n-byte public key value.
        """
        n = self.params.n
        w = self.params.w

        wotspkADRS = ADRS_obj.copy()
        skADRS     = ADRS_obj.copy()
        skADRS.setType(ADRS.WOTS_PRF)
        skADRS.setKeyPairAddress(ADRS_obj.getKeyPairAddress())

        tmp = []
        for i in range(self.params.len):
            skADRS.setChainAddress(i)
            skADRS.setHashAddress(0)
            sk_i = PRF(SK_seed, skADRS, n)

            ADRS_obj.setChainAddress(i)
            ADRS_obj.setHashAddress(0)
            tmp.append(self.chain(sk_i, 0, w - 1, PK_seed, ADRS_obj))

        wotspkADRS.setType(ADRS.WOTS_PK)
        wotspkADRS.setKeyPairAddress(ADRS_obj.getKeyPairAddress())
        return T_len(PK_seed, wotspkADRS, tmp, n)

    # ------------------------------------------------------------------
    # Algorithm 5: wots_sign(M, SK.seed, PK.seed, ADRS)  (spec r3.1 §3.5)
    # ------------------------------------------------------------------

    def wots_sign(self, M: bytes, SK_seed: bytes, PK_seed: bytes,
                  ADRS_obj: ADRS) -> List[bytes]:
        """
        Generate a WOTS+ signature on message digest M.
        Returns a list of len n-byte signature elements.
        """
        n   = self.params.n
        w   = self.params.w
        p   = self.params

        assert len(M) == n, "M must be n bytes"

        # convert message to base w
        msg = base_w(M, w, p.len1)

        # compute checksum
        csum = sum((w - 1) - m for m in msg)

        # convert checksum to base w  (spec r3.1 §3.5)
        log_w = int(math.log2(w))
        if log_w % 8 != 0:
            csum = csum << (8 - (p.len2 * log_w) % 8)
        len2_bytes = math.ceil(p.len2 * log_w / 8)
        msg = msg + base_w(csum.to_bytes(len2_bytes, "big"), w, p.len2)

        # build signature
        skADRS = ADRS_obj.copy()
        skADRS.setType(ADRS.WOTS_PRF)
        skADRS.setKeyPairAddress(ADRS_obj.getKeyPairAddress())

        sig = []
        for i in range(p.len):
            skADRS.setChainAddress(i)
            skADRS.setHashAddress(0)
            sk = PRF(SK_seed, skADRS, n)

            ADRS_obj.setChainAddress(i)
            ADRS_obj.setHashAddress(0)
            sig.append(self.chain(sk, 0, msg[i], PK_seed, ADRS_obj))
        return sig

    # ------------------------------------------------------------------
    # Algorithm 6: wots_pkFromSig(sig, M, PK.seed, ADRS)  (spec r3.1 §3.6)
    # ------------------------------------------------------------------

    def wots_pkFromSig(self, sig: List[bytes], M: bytes,
                       PK_seed: bytes, ADRS_obj: ADRS) -> bytes:
        """
        Reconstruct the WOTS+ public key from a signature and message digest.
        Returns a single n-byte value (to be compared against wots_PKgen output).
        """
        n = self.params.n
        w = self.params.w
        p = self.params

        assert len(M)   == n,      "M must be n bytes"
        assert len(sig) == p.len,  "sig must have len elements"

        wotspkADRS = ADRS_obj.copy()

        # convert message to base w
        msg = base_w(M, w, p.len1)

        # compute checksum
        csum = sum((w - 1) - m for m in msg)

        # convert checksum to base w  (spec r3.1 §3.6)
        log_w = int(math.log2(w))
        if log_w % 8 != 0:
            csum = csum << (8 - (p.len2 * log_w) % 8)
        len2_bytes = math.ceil(p.len2 * log_w / 8)
        msg = msg + base_w(csum.to_bytes(len2_bytes, "big"), w, p.len2)

        tmp = []
        for i in range(p.len):
            ADRS_obj.setChainAddress(i)
            tmp.append(self.chain(sig[i], msg[i], w - 1 - msg[i], PK_seed, ADRS_obj))

        wotspkADRS.setType(ADRS.WOTS_PK)
        wotspkADRS.setKeyPairAddress(ADRS_obj.getKeyPairAddress())
        return T_len(PK_seed, wotspkADRS, tmp, n)


# ==============================
# Quick self-test
# ==============================

if __name__ == "__main__":
    params = SphincsParams(
        n=16,        # 128-bit security parameter, placeholder
        w=16,        # Winternitz parameter
        h=60,        # placeholders for later SPHINCS+ integration
        d=12,
        k=15,
        t=2 ** 15,
    )

    wots = WOTSPlus(params)

    SK_seed = b"demo_secret_seed_16b"[:params.n]   # placeholder; use os.urandom(n) in production
    PK_seed = b"demo_public_seed_16b"[:params.n]   # placeholder; use os.urandom(n) in production

    # Generate public key
    pk = wots.wots_PKgen(SK_seed, PK_seed, ADRS())

    # Sign a dummy n-byte digest
    M = hashlib.sha256(b"hello wtf").digest()[:params.n]
    sig = wots.wots_sign(M, SK_seed, PK_seed, ADRS())

    # Reconstruct public key from signature
    pk2 = wots.wots_pkFromSig(sig, M, PK_seed, ADRS())

    assert pk == pk2, "WOTS+ verification failed: pk mismatch"
    print("WOTS+ self-test passed.")
