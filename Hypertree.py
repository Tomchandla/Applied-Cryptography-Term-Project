import math
import hashlib
import ctypes
from ADRS import ADRSType, ADRS
from typing import List, Tuple
from WOTSPLUS import WOTSPlus, SphincsParams

#===============
# SPHINCS+ Hypertree Implementtion
#==============
class Hypertree:
    # A hypertree is a form of XMSS, as such it uses some of the functions it does.
    wots_plus = WOTSPlus();
    def __init__(self):
        self.wots_plus = WOTSPlus(SphincsParams)
    class XMSS:
        h: int # height of the tree (number of levels - 1) (supposed to be h')
        n: int # the length in bytes of messages as well as of each node.
        w: int # the Winternitz parameter
        # some leaves parameter which is defined as 2^h


        """
            Tree hash function
            sk_seed = secret key seed
            pk_seed = public key seed
            s = start index (unsigned integer)
            z = end idnex (unsigned int)
            ADDR = address.
        """
        def _TreeHash(self, sk_seed: bytes, s: int, z:int, pk_seed:bytes, adrs: ADRS) -> bytes:
            # ensure s and z are unsigned integers.
            if (s  < 0 or z < 0):
                raise ValueError(f"{s} or/and {z} must be a positive integer value to be put into a word")
            if (s > 0xFFFFFFFF or z > 0xFFFFFFFF):
                raise ValueError(f"Values {s} or/and {z} exceeds 32 bit limit")
            
            if (s % (1 <<z) != 0): return 1;
            # list impl of stack
            stack = []

            for i in range(pow(2, z)):
                adrs.set_type(ADRSType.WOTS_HASH)
                adrs.set_key_pair_add(s + i)
                # TODO: wots pkgen is incomplete so this is basically equiv to a stub right now.
                node = self.WOTSPlus.pk_gen(self.WOTSPlus, sk_seed, adrs)
                adrs.set_type(ADRSType.TREE)
                adrs.set_tree_height(1)
                adrs.set_tree_add(s + i)
                while stack and stack[-1][1] == height:
                    adrs.set_tree_index((adrs.get_tree_index-1) / 2);
                    # TODO should be a hash func here.
                    node = self.H(pk_seed, adrs, (stack.pop()[0] + node))
                    height += 1
                    adrs.set_tree_height(height)
                # mimic stack push
                stack.append((node, height))
            return stack.pop()[0]
        
        """
        xmss public key generator 
        """
        def xmss_PKgen(self, sk_seed: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
            pk = self.TreeHash(sk_seed, 0, self.h, pk_seed, adrs)
            return pk;
        """
        An XMSS signature is a ((len + h') * n)-byte signature consisting of:
        A WOTS+ signature sig taking len * n bytes
        The authentication path AUTH for the leaf associated with the used WOTS+ key pair taking h' * n bytes
        Auth path - array of h' n-byte strings ontains the siblings of the nodes in on the path from the used leaf to the root
        """
        class xmss_sig:
            sig: bytes
            auth: List[bytes]

        """
            XMSS signature generator with variables:
            M - n-byte message
            sk seed - secret key seed
            index - index number.
            pk seed - public key seed
            adrs - address
        """
        def xmss_sign(self, M:bytes, sk_seed: bytes, idx: int, pk_seed: bytes, adrs: ADRS) -> xmss_sig:
            AUTH = []
            for j in self.h:
                k = math.floor(idx / (pow(2,j))) ^ 1
                AUTH[j] = self._TreeHash(sk_seed, k * pow(2,j), j, pk_seed, adrs)
            
            adrs.set_type(ADRSType.WOTS_HASH)
            adrs.set_key_pair_add(idx)
            sig = self.WOTSPlus.sign(self.WOTSPlus, M, sk_seed, adrs)
            return sig + b''.join(AUTH)
        
        def xmss_pkFromSig(idx: int, sig:bytes, M: bytes, pk_seed: bytes, adrs: ADRS) -> bytes:
            adrs.set_type(ADRSType.WOTS_HASH)
            adrs.set_key_pair_add(idx)
            
            


    