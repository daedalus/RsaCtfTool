# /usr/bin/env python
# code taken from https://maths.dk/teaching/courses/math357-spring2016/projects/factorization.pdf

from attacks.abstract_attack import AbstractAttack
from lib.keys_wrapper import PrivateKey
from lib.rsalibnum import gcd, isqrt
from lib.utils import timeout, TimeoutError


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["slow"]

    def euler(self, n):
        if n & 1 == 0:
            return (n >> 1, 2) if n > 2 else (2, 1)
        end = isqrt(n)
        a = 0
        solutionsFound = []
        firstb = -1
        while a < end and len(solutionsFound) < 2:
            bsquare = n - pow(a, 2)
            if bsquare > 0:
                b = isqrt(bsquare)
                if (pow(b, 2) == bsquare) and (a != firstb) and (b != firstb):
                    firstb = b
                    solutionsFound.append([int(b), a])
            a += 1
        if len(solutionsFound) < 2:
            return -1
        a = solutionsFound[0][0]
        b = solutionsFound[0][1]
        c = solutionsFound[1][0]
        d = solutionsFound[1][1]
        k = gcd(a - c, d - b)
        h = gcd(a + c, d + b)
        m = gcd(a + c, d - b)
        l = gcd(a - c, d + b)
        pk2 = pow(k, 2)
        ph2 = pow(h, 2)
        pl2 = pow(l, 2)
        pm2 = pow(m, 2)
        n = (pk2 + ph2) * (pl2 + pm2)
        return [(pk2 + ph2) >> 1, (pl2 + pm2) >> 1]

    def attack(self, publickey, cipher=[], progress=True):
        """Run attack with Euler method"""
        if not hasattr(publickey, "p"):
            publickey.p = None
        if not hasattr(publickey, "q"):
            publickey.q = None

        # Euler attack
        with timeout(self.timeout):
            try:
                try:
                    euler_res = self.euler(publickey.n)
                except:
                    return (None, None)
                if euler_res and len(euler_res) > 1:
                    publickey.p, publickey.q = euler_res

                if publickey.q is not None:
                    priv_key = PrivateKey(
                        int(publickey.p),
                        int(publickey.q),
                        int(publickey.e),
                        int(publickey.n),
                    )
                    return (priv_key, None)
            except TimeoutError:
                return (None, None)

        return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MCEwDQYJKoZIhvcNAQEBBQADEAAwDQIGBUZ2EydBAgMBAAE=
-----END PUBLIC KEY-----"""
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
