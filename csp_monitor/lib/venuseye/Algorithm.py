# _*_ coding:utf-8 _*_

from Crypto.Cipher import AES  # aes 加密需要
import hashlib  # aes 加密需要
from csp_monitor.setting import VENUS_EYE_SECRET_KEY


class AES_II:
    def __init__(self):
        self.key = VENUS_EYE_SECRET_KEY  # 秘钥
        self.MODE = AES.MODE_ECB

    def crp_str(self, value):
        hl = hashlib.md5()
        hl.update(self.key.encode(encoding='utf-8'))
        crypt = AES.new(hl.digest(), self.MODE)
        pading = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
        text = pading(value)
        ciphertext = crypt.encrypt(text.encode(encoding='utf-8'))
        return ciphertext

    def decry_str(self, value):
        hl = hashlib.md5()
        hl.update(self.key.encode(encoding='utf-8'))
        crypto = AES.new(hl.digest(), self.MODE)
        plain_text = crypto.decrypt(value)
        return plain_text
