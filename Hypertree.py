import math
import hashlib
import ctypes
from xmlrpc.client import Boolean
from ADRS import ADRSType, ADRS
from typing import List, Tuple
from WOTSPLUS import WOTSPlus, SphincsParams
from XMSS import XMSS
from helpers import toByte
from Hypertree_sig import hypertree_sig
from XMSS_sig import xmss_sig

#===============
# SPHINCS+ Hypertree Implementtion
#==============
class Hypertree:
    # A hypertree is a form of XMSS, as such it uses some of the functions it does.
    # In addition to all XMSS parameters, it also has a normal h representing tree height
    # and number of tree layers d. The same tree height h/d = h' and winternitz param
    # is used for all layers
    h: int # height of tree
    d: int # number of tree layers
    w: int # winternitz param
    n: int # length in bytes to be passed unto the XMSS constructo
    wots_plus = WOTSPlus();
    adrs = ADRS();
    XMSS = XMSS(h, n, d, w, wots_plus, ADRS);
    def __init__(self):
        self.wots_plus = WOTSPlus(SphincsParams)
        self.ADRS = ADRS()
        self.XMSS = XMSS(self.h, self.n, self.d, self.w, self.wots_plus, self.ADRS)

    """
    Hypertree public key generator
    The public key generation takes as input a private and public seed
    and outputs its own seed.
    """
    def ht_PkGen(self, sk_seed:bytes, pk_seed:bytes) -> bytes:
        self.adrs = toByte(0, 32)
        self.adrs.setlayer(self.d - 1)
        self.adrs.set_tree_add(0)
        root = self.XMSS.xmss_PKgen(sk_seed, pk_seed, self.adrs)
        return root;


    def ht_sign(self, M:bytes, sk_seed: bytes, pk_seed: bytes, tree_index: int, leaf_index: int) -> hypertree_sig:
        self.adrs = toByte(0, 32)
        self.adrs.set_layer_add(0)
        self.adrs.set_tree_add(tree_index)
        SIG_tmp = self.XMSS.xmss_sign(M, sk_seed, leaf_index, pk_seed, self.adrs)
        SIG_HT = List[xmss_sig]();
        root = self.XMSS.xmss_pkFromSig(leaf_index, SIG_tmp, M, pk_seed, self.adrs)
        for i in range(1, self.d):
            leaf_index = self.h / self.d # least sig bits of tree index.
            tree_index = (self.h - (self.j +1) * (self.h/ self.d)) # most sig bits of tree
            self.adrs.set_layer_add(i)
            self.adrs.set_tree_add(tree_index)
            SIG_tmp = self.XMSS.xmss_sign(root, sk_seed, leaf_index, pk_seed, self.adrs)
            SIG_HT.append(SIG_tmp)
            if (i < self.d - 1):
                root = self.XMSS.xmss_pkFromSig(leaf_index, SIG_tmp, root, pk_seed, self.adrs)
        
        return hypertree_sig(SIG_HT)
    
    def ht_verify(self, M: bytes, SIG_HT: hypertree_sig, pk_seed: bytes, tree_index: int, leaf_index: int, pk_ht: bytes) -> Boolean:
        self.adrs = toByte(0, 32)
        SIG_TMP = SIG_HT.get_xmss_sigs(0)
        self.adrs.set_layer_add(0)
        self.adrs.set_tree_add(tree_index)
        node = self.XMSS.xmss_pkFromSig(leaf_index, SIG_TMP,M, pk_seed, self.adrs)
        for i in range(1, self.d):
            leaf_index = self.h / self.d # least sig bits of tree index.
            tree_index = (self.h - (self.j +1) * (self.h/ self.d)) # most sig bits of tree
            SIG_TMP = SIG_HT.get_xmss_sigs(i)
            self.adrs.set_layer_add(i)
            self.adrs.set_treE_add(tree_index)
            node = self.XMSS.xmss_pkFromSig(leaf_index, SIG_TMP, node, pk_seed, self.adrs)
        if (node == pk_ht):
            return True
        else:
            return False
