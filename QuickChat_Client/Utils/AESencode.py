"""
ECB没有偏移量
"""
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex


def add_to_16(text):
    if len(text.encode('utf-8')) % 16:
        add = 16 - (len(text.encode('utf-8')) % 16)
    else:
        add = 0
    text = text + ('\0' * add)
    return text.encode('utf-8')


# 加密函数
def encrypt(plaintext,key):
    mode = AES.MODE_ECB
    plaintext = add_to_16(plaintext)
    cryptos = AES.new(key, mode)
    cipher_text = cryptos.encrypt(plaintext)
    return b2a_hex(cipher_text)


# 解密后，去掉补足的空格用strip() 去掉
def decrypt(ciphertext,key):
    mode = AES.MODE_ECB
    cryptor = AES.new(key, mode)
    plain_text = cryptor.decrypt(a2b_hex(ciphertext))
    print(bytes.decode(plain_text).rstrip('\0'))
    return bytes.decode(plain_text).rstrip('\0')


if __name__ == '__main__':
    key = '1234567891011121'.encode('utf-8')
    text = "我叫王昕怡"
    e = encrypt(text,key)  # 加密
    d = decrypt(e,key)  # 解密

    print("加密:", e)
    print("解密:", d)
