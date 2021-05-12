#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from attacks.abstract_attack import AbstractAttack
import subprocess
from lib.keys_wrapper import PrivateKey
from lib.utils import rootpath


class Attack(AbstractAttack):
    def __init__(self, timeout=60):
        super().__init__(timeout)
        self.speed = AbstractAttack.speed_enum["medium"]
        self.required_binaries = ["sage"]

    def attack(self, publickey, cipher=[], progress=True):
        """Qi Cheng - A New Class of Unsafe Primes"""
        try:
            attempts = 1000
            sageresult = subprocess.check_output(
                    ["sage", "%s/sage/qicheng.sage" % rootpath, str(publickey.n),str(attempts)],
                    timeout=self.timeout,
                    stderr=subprocess.DEVNULL,
                )
            sageresult = int(sageresult.decode("utf8").replace("\n",""))
           
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, ValueError):
            return (None, None)

        if sageresult > 0:
            p = sageresult
            q = publickey.n // sageresult
            priv_key = PrivateKey(int(p), int(q), int(publickey.e), int(publickey.n))
            return (priv_key, None)
        else:
            return (None, None)

    def test(self):
        from lib.keys_wrapper import PublicKey

        key_data = """-----BEGIN PUBLIC KEY-----
MIHfMA0GCSqGSIb3DQEBAQUAA4HNADCByQKBwQOQAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAEJaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVuNoAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAs77PAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAADXxXC8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB5u1rSgAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI20Lb0UCAwEAAQ==
-----END PUBLIC KEY-----"""
        self.timeout = 120
        result = self.attack(PublicKey(key_data), progress=False)
        return result != (None, None)
