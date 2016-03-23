#!-*- coding:utf-8 -*-
__author__ = 'sweet'

from OpenSSL.crypto import *
import base64

strPubKey = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgbjTF4sgN1ckBT1nAyxYqKNVi
/4mujsLg4ru0sBjazAkjWgha63wIC91GHpJdvS+GPwwjcgMN1rtKUZlT45+MbtKs
atqP41mmwOZsGF8Gt2HMxj7wJPtqCxd9zl8hbxb4WB+L+p5ybmDk+hjxexxP4Tvc
R3J7ZZ1qlBKoFJv1HwIDAQAB
-----END PUBLIC KEY-----'''

message = 'hello'
pubKey = load_publickey(FILETYPE_PEM, strPubKey)



# key = load_privatekey(FILETYPE_PEM, open("private.pem").read())

# d = sign(key, content, 'sha1')  # d为经过SHA1算法进行摘要、使用私钥进行签名之后的数据
# b = base64.b64encode(d)  # 将d转换为BASE64的格式
# print(b)
