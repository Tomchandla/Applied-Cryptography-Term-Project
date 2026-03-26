from typing import List
from XMSS_sig import xmss_sig

"""
A hypertree signature (SIG_HT) is a byte string of length (h + d * len)) * n bytes.
It consits of d XMSS signatures (each of length (h/d) + len * n bytes each)
for more info on len, see sphincs+ parameters.
"""
class hypertree_sig:
  xmss_sigs: List[xmss_sig]
  def __init__(self, xmss_sigs: List[xmss_sig]):
    self.xmss_sigs = xmss_sigs
  def get_xmss_sigs(self, layer:int) -> List[xmss_sig]:
    return self.xmss_sigs[layer]
    