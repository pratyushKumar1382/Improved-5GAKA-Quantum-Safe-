from math import log2 as lg
import base58

from parameters import Parameters, Standard
from poly import Polynomial as poly
from ntru_poly_ops import invert_in_p, invert_in_2tor


class NTRUKey:

    def __init__(self, P, h, f=None, g=None, fp=None, fq=None):
        """Key parameters"""

        self._P = P  # parameter set
        self._h = h  # public key
        self._f = f  # private key f
        self._g = g  # private key g
        self._fp = fp  # used for decryption
        self._fq = fq  # ensure correctness
        # print(P,h,f,g,fp,fq)
        # print(type(P))
        # print(type(h))
        # print(type(f))
        # print(type(g))
        # print(type(fp))
        # print(type(fq))
        # print(h.coefficients())

    def get_h():
        return _h

    def encrypt(self, m, h):
        """m is a the message encoded as a polynomial"""
        if m._N <= self._P.get_N():

            r = self._P.gen_rPoly()
            e = (r.scale(self._P.get_p()) * h + m) % self._P.get_q()

            return e  # Polynomial representing the encryption message
        else:
            raise Exception("m is too large, must be equal or under size %d" % N)

    def decrypt(self, e):
        """e is an encrypted message encoded as a polynomial"""
        if self._f is None or self._g is None:
            raise Exception("Private key not found.")

        if e._N <= self._P.get_N():

            if not self._fp:
                self._fp = invert_in_p(self._f, self._P.get_N())
            if not self._fq:
                self._fq = invert_in2tor(
                    self._f, self._P.get_N(), int(lg(self._P.get_q()))
                )

            assert self._h == self._fq * self._g

            a = (self._f * e) % self._P.get_q()
            b = (self._fp * a) % self._P.get_p()

            return b  # decrypted message
        else:
            raise Exception(
                "e is too large, must be equal or under size %d" % self._P.get_N()
            )

    def is_private(self):
        return self._f is not None and self._g is not None


def generate_key(params=Standard()):

    f = params.gen_fPoly()
    g = params.gen_gPoly()

    fp = invert_in_p(f, params.get_N())
    fq = invert_in_2tor(f, params.get_N(), 8)

    h = fq * g

    return NTRUKey(params, h, f, g, fp, fq)


if __name__ == "__main__":
    keys = generate_key()
