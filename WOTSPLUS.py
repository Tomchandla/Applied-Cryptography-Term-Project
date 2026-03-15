import math
import hashlib
from dataclasses import dataclass
from typing import List, Tuple

# ==============================
# SPHINCS+ parameter container
# ==============================

@dataclass
class SphincsParams:
    n: int  # security parameter (bytes)
    w: int  # Winternitz parameter
    # placeholders – not used in WOTS+
    h: int = 0
    d: int = 0
    k: int = 0
    t: int = 0

    def __post_init__(self):
        # Derived WOTS+ parameters per SPHINCS+ spec (r3.1).[web:12]
        # len1 = ceil(8*n / log2(w))
        self.len1 = math.ceil(8 * self.n / math.log2(self.w))
        # len2 = ceil(log2(len1 * (w-1)) / log2(w)) + 1
        self.len2 = math.ceil(math.log2(self.len1 * (self.w - 1)) / math.log2(self.w)) + 1
        # total length
        self.len = self.len1 + self.len2


# ==============================
# Utility functions
# ==============================

def _to_base_w(x: bytes, w: int, out_len: int) -> List[int]:
    """
    Convert a byte string x into base-w digits (big-endian),
    as in the WOTS+ spec (r2.5).[web:7]
    """
    total_bits = len(x) * 8
    log_w = int(math.log2(w))
    if 2 ** log_w != w:
        raise ValueError("w must be a power of 2")

    bits = int.from_bytes(x, "big")
    digits = []
    for _ in range(out_len):
        digits.append(bits & (w - 1))
        bits >>= log_w
    digits.reverse()  # big-endian ordering
    return digits


def _compute_checksum(msg_base_w: List[int], w: int, len2: int) -> List[int]:
    """
    Compute WOTS+ checksum as in the spec (r3.5).[web:15]
    """
    csum = 0
    for d in msg_base_w:
        csum += (w - 1) - d

    # Represent checksum in base w using len2 digits.
    log_w = int(math.log2(w))
    # csum = csum << ( 8 - ( ( len_2 * lg(w) ) % 8 ));
    csum_bits = csum << (len2 * log_w - csum.bit_length())
    # len_2_bytes = ceil( ( len_2 * lg(w) ) / 8 );
    # csum_bytes = toByte(csum, len_2_bytes)
    csum_bytes = csum_bits.to_bytes((len2 * log_w + 7) // 8, "big")
    return _to_base_w(csum_bytes, w, len2)


def _tweakable_hash(x: bytes, addr: bytes, n: int) -> bytes:
    """
    Very simplified stand-in for the SPHINCS+ tweakable hash function thash.
    In the real implementation, this will depend on PK.seed and ADRS.[web:29]

    TODO (integration): replace with F(PK.seed, ADRS, x) spec (r2.7.1) [web:9]. PK.seed and the structured 32-byte
    ADRS object will be supplied by the enclosing SPHINCS+ context.
    """
    h = hashlib.sha256()
    # Concatenate address and input; treat addr as a tweak
    h.update(addr)
    h.update(x)
    out = h.digest()
    if len(out) < n:
        raise ValueError("Hash output shorter than n")
    return out[:n]


def chain(x: bytes, start: int, steps: int, addr: bytes, n: int, w: int) -> bytes:
    """
    WOTS+ chaining function: iteratively apply F starting from x,
    from step 'start' for 'steps' iterations.[web:13]
    Here F is instantiated via _tweakable_hash with (addr || step).

    TODO (integration): addr should be a structured 32-byte ADRS object.
    Each iteration should call ADRS.setHashAddress(i) then F(PK.seed, ADRS, x) spec (r3.2) [web:13].
    """
    assert len(x) == n
    if (start + steps) > (w - 1):
        raise ValueError("chain: start + steps exceeds w-1")

    if steps == 0:
        return x
    for i in range(start, start + steps):
        # incorporate step into address (again, very simplified)
        step_addr = addr + i.to_bytes(4, "big")
        x = _tweakable_hash(x, step_addr, n)
    return x


# ==============================
# WOTS+ implementation
# ==============================

class WOTSPlus:
    def __init__(self, params: SphincsParams):
        self.params = params

    # ---- Key generation ----

    def sk_gen(self, sk_seed: bytes, addr: bytes) -> List[bytes]:
        """
        Generate WOTS+ secret key as len n-byte strings.[web:14]
        In the real spec, each sk element is PRF(SK.seed, ADRS || i).[web:31]
        Here I simplify with H(sk_seed || i || addr) as FORS is not implemented yet.

        TODO (integration): replace with PRF(SK.seed, ADRS) where
        ADRS.setChainAddress(i) is called before each invocation spec (r3.3) [web:14]
        addr here is a flat-byte placeholder for the structured 32-byte ADRS object.
        """
        n = self.params.n
        sk = []
        for i in range(self.params.len):
            h = hashlib.sha256()
            h.update(sk_seed)
            h.update(i.to_bytes(4, "big"))
            h.update(addr)
            sk_i = h.digest()[:n]
            sk.append(sk_i)
        return sk

    def pk_gen(self, sk: List[bytes], addr: bytes) -> List[bytes]:
        """
        Generate WOTS+ public key as len n-byte strings.
        Each pk[i] = chain(sk[i], 0, w-1, addr, n, w).[web:29]

        TODO (integration): two changes required spec (r3.5) [web:14]:
        1. sk should be derived internally via PRF(SK.seed, ADRS) rather than
           passed in — sk_gen and pk_gen should be merged into wots_PKgen.
        2. After computing all chain ends, compress into a single n-byte public
           key via T_len(PK.seed, wotspkADRS, tmp) where wotspkADRS has type
           WOTS_PK. Currently returns a list of len values as a placeholder.
        """
        n = self.params.n
        w = self.params.w
        pk = []
        for i, sk_i in enumerate(sk):
            # chain address tweak could incorporate i; simplified here
            chain_addr = addr + i.to_bytes(4, "big")
            pk_i = chain(sk_i, 0, w - 1, chain_addr, n, w)
            pk.append(pk_i)
        return pk

    def keygen(self, sk_seed: bytes, addr: bytes) -> Tuple[List[bytes], List[bytes]]:
        """
        Convenience: generate (sk, pk) pair.
        """
        sk = self.sk_gen(sk_seed, addr)
        pk = self.pk_gen(sk, addr)
        return sk, pk

    # ---- Signing ----

    def _msg_to_chain_lengths(self, msg_digest: bytes) -> List[int]:
        """
        Map a message digest to WOTS+ chain lengths:
          - convert digest to base-w (len1 digits)
          - compute checksum (len2 digits)
          - return concatenation of both.[web:15]
        """
        p = self.params
        # base-w representation of message digest
        msg_base_w = _to_base_w(msg_digest, p.w, p.len1)
        # checksum digits
        csum_digits = _compute_checksum(msg_base_w, p.w, p.len2)
        # msg = msg || base_w(toByte(csum, len_2_bytes), w, len_2);
        return msg_base_w + csum_digits  # length len1 + len2 = len

    def sign(self, sk: List[bytes], msg_digest: bytes, addr: bytes) -> List[bytes]:
        """
        Generate WOTS+ signature:
          - derive chain lengths a[i] from message digest
          - sig[i] = chain(sk[i], 0, a[i], addr_i).[web:29]
        """
        n = self.params.n
        assert len(msg_digest) == n, "msg_digest must be n bytes"
        assert len(sk) == self.params.len

        a = self._msg_to_chain_lengths(msg_digest)
        sig = []
        for i, (sk_i, steps) in enumerate(zip(sk, a)):
            chain_addr = addr + i.to_bytes(4, "big")
            sig_i = chain(sk_i, 0, steps, chain_addr, n, self.params.w)
            sig.append(sig_i)
        return sig

    # ---- Public key from signature (for verification) ----

    def pk_from_sig(self, sig: List[bytes], msg_digest: bytes, addr: bytes) -> List[bytes]:
        """
        Reconstruct WOTS+ public key from signature and message digest:
          - derive chain lengths a[i]
          - pk[i] = chain(sig[i], a[i], w-1-a[i], addr_i).[web:29]
        """
        n = self.params.n
        assert len(msg_digest) == n
        assert len(sig) == self.params.len

        a = self._msg_to_chain_lengths(msg_digest)
        pk = []
        for i, (sig_i, steps) in enumerate(zip(sig, a)):
            chain_addr = addr + i.to_bytes(4, "big")
            pk_i = chain(sig_i, steps, self.params.w - 1 - steps, chain_addr, n, self.params.w)
            pk.append(pk_i)
        return pk


# ==============================
# Example usage / quick test
# ==============================

if __name__ == "__main__":
    # Example placeholder parameters (like 128-bit security)
    params = SphincsParams(
        n=16,   # 128-bit security parameter, placeholder
        w=16,   # Winternitz parameter (must be power of 2 in this simplified base_w)
        h=60,   # placeholders for later SPHINCS+ integration
        d=12,
        k=15,
        t=2 ** 15,
    )

    wots = WOTSPlus(params)

    sk_seed = b"this_is_a_demo_seed_for_wots"  # placeholder; later, use random n-byte seed
    addr = b"WOTSADDR"  # placeholder; later, use real ADRS structure

    # Generate key pair
    sk, pk = wots.keygen(sk_seed, addr)

    # Sign a dummy n-byte digest
    msg_digest = hashlib.sha256(b"wtf").digest()[:params.n]
    sig = wots.sign(sk, msg_digest, addr)

    # Recompute pk from signature + message
    pk2 = wots.pk_from_sig(sig, msg_digest, addr)

    assert pk == pk2, "WOTS+ verification failed: pk mismatch"
    print("WOTS+ self-test passed.")
