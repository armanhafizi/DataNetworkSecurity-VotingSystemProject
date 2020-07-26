import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES


def symmetric_encrypt(key, raw):
    key = hashlib.sha256(key.encode()).digest()
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher.encrypt(raw.encode()))

def symmetric_decrypt(key, enc):
    key = hashlib.sha256(key.encode()).digest()
    enc = base64.b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(enc[AES.block_size:]).decode('utf-8')

enc = symmetric_encrypt(str(1234145987), "just work")
print(enc)
print(symmetric_decrypt(str(1234145987), enc))