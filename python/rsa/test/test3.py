#! -*- coding:utf-8 -*-
import base64

__author__ = 'sweet'
# pycrypto模块
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as pk
from Crypto.Cipher import *

strPubKey = '''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgbjTF4sgN1ckBT1nAyxYqKNVi
/4mujsLg4ru0sBjazAkjWgha63wIC91GHpJdvS+GPwwjcgMN1rtKUZlT45+MbtKs
atqP41mmwOZsGF8Gt2HMxj7wJPtqCxd9zl8hbxb4WB+L+p5ybmDk+hjxexxP4Tvc
R3J7ZZ1qlBKoFJv1HwIDAQAB
-----END PUBLIC KEY-----'''

strPriKey = '''-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKBuNMXiyA3VyQFP
WcDLFioo1WL/ia6OwuDiu7SwGNrMCSNaCFrrfAgL3UYekl29L4Y/DCNyAw3Wu0pR
mVPjn4xu0qxq2o/jWabA5mwYXwa3YczGPvAk+2oLF33OXyFvFvhYH4v6nnJuYOT6
GPF7HE/hO9xHcntlnWqUEqgUm/UfAgMBAAECgYA7BWBf3tdHk7uPwlAcR/q/Bue+
NJHECNx0HKX+yvxR3leMTG6feFvYn/jHd67UUqn9wwslrSenezTLGisE/ExxKXkr
kbXzJVdYDSCiS6dfF7PsbQOKYu1wXGiFq2wumUdtje8q8/G6aTqg1UeJEWbYLuxS
MGImZxYQ7ccvYi5jQQJBAN7SaUftFCgAa6+LfUBbUn223ycjkXPFhAi4JSVokGFd
YivzWmTTA0pmUSr2onTgdwrCEewBDiWv8A3kA8/IVN8CQQC4UYp5J4r50t0mBU/g
bAbBqPkhwPXmf2sRTr6eKpwEUpcxfWI9a8Ogbe2kTwAj5T4ATJQpcLpu4/LxKm4V
GifBAkArDo25kF5svGgSq+mwHfV6xXOppH3e2TQCW1MSP3pm1hy6UXQON5hTMCJP
IwmRfC6Erau45xtMvQquJHl4FUYRAkBrcYTx6P4XcTbe4fvVC8PIgjJv3aa6LY6B
MVDmrFn0HxzpiXiJ61bHHy2HOVIQmqJQ1FMN8RuMZq6IrL4s6OlBAkEAm1KrdB3k
BbEZXBTL/OmmMJX0usE410c6tkavdDKGNC1Dc+u4SIeG+DkYDBR90rEd4UxF3n3X
ygbpt12Vjod9Vg==
-----END PRIVATE KEY-----'''

message = 'hello2'

pubKey = RSA.importKey(strPubKey)
priKey = RSA.importKey(strPriKey)

print(pubKey.size())
print(priKey.size())

# PKCS1_OAEP
cipher = pk.new(pubKey)
encrypted = cipher.encrypt(message.encode('utf-8'))
print(encrypted)
print(base64.b64encode(encrypted))

# 解密
strBase64 = 'dpWyUtt+Y4Rl2jASsVlLzlZI2QwxqKWiSmBTf4qdxastR4oZ4dg0Ke3xibleI2mKekujs0XS7ZC3mG4E5jMLW5Jg1N/dgKIL7NVMFzCqlX9rqk6MfUXW+IIsook+QCEyXfY3udRokWdWv5AjhfljGkDzdmqNA+8FKUGcFBiuSss='
encrypted = base64.decodebytes(strBase64.encode('utf-8'))
print(encrypted)

cipher = pk.new(priKey)
dsize = SHA.digest_size
sentinel = Random.new().read(15 + dsize)
decrypted = cipher.decrypt(encrypted, sentinel)
print(decrypted)
print(decrypted.decode('utf-8'))
print(base64.b64decode(decrypted).decode('utf-8'))

#
# f = open('private-key.pem', 'r')
# r = RSA.importKey(f.read(),  passphrase='some-pass')
# f.close()
