from typing import List

"""
An XMSS signature is a ((len + h') * n)-byte signature consisting of:
A WOTS+ signature sig taking len * n bytes
for more info on len, see sphinc+ parameters.
The authentication path AUTH for the leaf associated with the used WOTS+ key pair taking h' * n bytes
Auth path - array of h' n-byte strings ontains the siblings of the nodes in on the path from the used leaf to the root
"""
class xmss_sig:
    sig: bytes
    auth: List[bytes]
    def __init__(self, sig: bytes, auth: List[bytes]):
        self.sig = sig
        self.auth = auth
    

    def get_sig(self) -> bytes:
        return self.sig
    
    def get_auth(self) -> List[bytes]:
        return self.auth; 
    
    def get_self(self) -> "xmss_sig":
        return self