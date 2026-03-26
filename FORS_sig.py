from typing import List
"""
k log t-bit string M
has two components: SK and AUTH
both are essentially lists of bytes of up to k-1 elements
Each auth is composed of log t * n bytes
Each SK is composed of n bytes
This will be checked in sig gen
"""

class FORS_sig:
    sk: List[bytes]
    auth: List[bytes]
    
    def __init__(self, sk: List[bytes], auth: List[bytes]):
        self.sk = sk
        self.auth = auth

    def get_sk(self, layer: int) -> bytes:
        return self.sk[layer]
    
    def get_auth(self, layer: int) -> List[bytes]:
        return self.auth[layer]
    
    def get_self(self) -> "FORS_sig":
        return self