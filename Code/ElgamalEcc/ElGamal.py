import random
from os import urandom
from typing import Callable
from ElgamalEcc.Curve import Curve, Point



class ElGamal:
    curve: Curve

    def __init__(self,newcurve):
        self.curve=newcurve

    def encrypt(self, plaintext: bytes, public_key: Point, randfunc: Callable =None):
        randfunc = randfunc or urandom
        # Base point
        G = Point(self.curve.gx, self.curve.gy, curve=self.curve)
        # Encode plaintext into curve point
        M = self.curve.encode_point(plaintext)

        random.seed(randfunc(1024))
        k = random.randint(1, self.curve.n)

        C1 = k * G
        C2 = M + k * public_key
        return C1, C2

    def decrypt(self, private_key, C1, C2):
       M = C2 - (private_key)*C1
       return self.curve.decode_point(M)
