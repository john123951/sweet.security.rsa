#! -*- coding:utf-8 -*-
# 需要安装 pycrypto 模块
# python3时会有bug，处理：修改python3安装目录下的  lib/Crypto/Random/OSRNG/nt.py 文件中找到
# import winrandom
# 修改为
# from Crypto.Random.OSRNG import winrandom

__author__ = 'sweet'

import collections
import base64
import math
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as PKCipher
from Crypto.Signature import PKCS1_v1_5 as PKSignature

formatEnum = collections.namedtuple('formatEnum', ('ASN', 'XML', 'PEM'))
format = formatEnum(1, 2, 3)


class KeyWorker:
    """
    RSA加密
    目前仅支持ASN、PEM格式
    """

    def __init__(self, key='', format=format.ASN):
        self._key = key
        self._format = format
        self._rsaKey = None
        return

    def _get_MAX_ENCRYPT_BLOCK(self):
        size = self._rsaKey.size() + 1
        return size // 8 - 11

    def _get_MAX_DECRYPT_BLOCK(self):
        size = self._rsaKey.size() + 1
        return size // 8

    def _makesureProvider(self):
        if self._rsaKey is not None: return

        rawKey = self._key
        isPrivate = len(rawKey) > 500
        count = math.ceil(len(rawKey) * 1.0 / 64)
        keyList = []
        for i in range(0, count):
            keyList.append(rawKey[i * 64:64 * (i + 1)])

        if self._format == format.ASN:
            if isPrivate:
                key = '-----BEGIN PRIVATE KEY-----\n'
                key = key + '\n'.join(keyList)
                key = key + '\n-----END PRIVATE KEY-----'
            else:
                key = '-----BEGIN PUBLIC KEY-----\n'
                key = key + '\n'.join(keyList)
                key = key + '\n-----END PUBLIC KEY-----'
        else:
            key = rawKey

        self._rsaKey = RSA.importKey(key)
        return

    def encrypt(self, data):
        """
        RSA加密
        :param data: 需要加密的字符串
        :return:
        """
        self._makesureProvider()
        cipher = PKCipher.new(self._rsaKey)

        source = base64.b64encode(data.encode('utf-8'))
        encrypted = b''
        # 分段加密
        if len(source) > self._get_MAX_ENCRYPT_BLOCK():
            maxSize = self._get_MAX_ENCRYPT_BLOCK()
            count = math.ceil(len(source) * 1.0 / maxSize)
            for i in range(0, count):
                buffer = source[i * maxSize:maxSize * (i + 1)]
                encrypted = encrypted + cipher.encrypt(buffer)
            pass
        else:
            encrypted = cipher.encrypt(source)
        return base64.b64encode(encrypted).decode('utf-8')

    def decrypt(self, data):
        """
        RSA解密
        :param data: 需要解密的字符串
        :return:
        """
        self._makesureProvider()
        cipher = PKCipher.new(self._rsaKey)

        source = base64.b64decode(data)
        decrypted = b''
        # 分段解密
        if len(source) > self._get_MAX_DECRYPT_BLOCK():
            maxSize = self._get_MAX_DECRYPT_BLOCK()
            count = math.ceil(len(source) * 1.0 / maxSize)
            pass
            for i in range(0, count):
                buffer = source[i * maxSize:maxSize * (i + 1)]
                decrypted = decrypted + cipher.decrypt(buffer, None)
        else:
            decrypted = cipher.decrypt(source, None)
        return base64.b64decode(decrypted).decode('utf-8')

    def sign(self, signData):
        """
        签名
        :param signData: 需要签名的字符串
        :return:
        """
        self._makesureProvider()
        signature = PKSignature.new(self._rsaKey)
        hash = SHA.new(signData.encode('utf-8'))

        result = signature.sign(hash)
        result = base64.b64encode(result).decode('utf-8')
        return result

    def verify(self, signData, sign):
        """
        验签
        :param signData: 签名原数据
        :param sign: 签名字符串
        :return:
        """
        self._makesureProvider()
        signature = PKSignature.new(self._rsaKey)
        hash = SHA.new(signData.encode('utf-8'))

        signn = base64.b64decode(sign)
        return signature.verify(hash, signn)


if __name__ == "__main__":
    strPubKey = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnaf6bHe76tz7yPQNj7TKmLiDk+ujB0jsJ9RDmxum0KMZVTFaphL8oWHncPBeih4Vt0F8pA6ian+kKd4AyO57W/0RBpSkCKoRVbeCKQM5yJ5fPovVAI+drBZDcqHVsPoauky86EhUGilAVulI+hByVddBZYMn+xg9WUI/7H1u+4p4nPzgO6PIIPWTDthnbfz7nsHtTa+9bfuDSLPTnV5lshn6GIrMmwAi2aNZICXyHuXpZS74pTnqbXFdZ/8iRnhz5DCmJBXFmxTdm7DY5mAmnhaGkaDScI+y7WTjGmxGEJxPdKIiES4IImnej9+G7BHrBCneSLDp994crQdHGXCdNwIDAQAB'
    strPriKey = 'MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCdp/psd7vq3PvI9A2PtMqYuIOT66MHSOwn1EObG6bQoxlVMVqmEvyhYedw8F6KHhW3QXykDqJqf6Qp3gDI7ntb/REGlKQIqhFVt4IpAznInl8+i9UAj52sFkNyodWw+hq6TLzoSFQaKUBW6Uj6EHJV10Flgyf7GD1ZQj/sfW77inic/OA7o8gg9ZMO2Gdt/Puewe1Nr71t+4NIs9OdXmWyGfoYisybACLZo1kgJfIe5ellLvilOeptcV1n/yJGeHPkMKYkFcWbFN2bsNjmYCaeFoaRoNJwj7LtZOMabEYQnE90oiIRLggiad6P34bsEesEKd5IsOn33hytB0cZcJ03AgMBAAECggEAXatiFHQHSIHHbxvhutI11Qs70fUcxcVD2l45VLzXHfrpoD5Ul3uMce4TbnzCDtnVGS5leavgP9palS171eYrkPoI1ZoW47b32a/QO8HY4SOHf0fhZBXwHkCUDlWs+xt+KdZSHshqf6imu3ybiUegRvQ/vKpyZLOAL7o29LGJ8RTj2LzFIVgzllV6xoVEycLQdLp33VuiQcodsHy4Dv23Dr+6KwY0gJfXq3USlGpeGzW8Ezt7oxtPQJ+x+SosliGTAL6IUBUaJkkE1NBEshPAi9OymrOGAjy7LUAQnZPJEdzKZBdVNI/cU1O7fRMqtDHJdv4thRM4oGvkBTO2jhs1YQKBgQDLvv+Ozet/UXCW2GX746+ZH3+PEhAjdvxlcd59Dd6kFcbX7BJQ+4trT9VwpzBPh5uBKDLI9mWzZ/DMS9GVU0f7+XWL6n+95C2NydK0SxNcOV91z8QWVDbcZKnj36BR5PccWRWKJspLXM8gvWsz/xs3aCfnx5pB+KOwdorydLOVSQKBgQDGFu8rpoPnx6LaSbknV5oYYOsN2oHmbkGq6Xnh6q0sSUvNrC97bvxtWwqNMdsmPh1MGx2r2/awhQrWxLWG87N6i23e6x2zfDzaQTUJGK/aFUQ+nmX0SQk1+82kr/CBCgl/1wtNiCHoOM2s/8MMkactk04om3XzJYB6btgxIQMefwKBgB5DAiYtw5qnd/ePsKYXDU/K8+FGJ4t88sQGg6tDUhxA98W+VIIeunh35RXUX0KQu7IVTGW44yYgfA17/WcWdYyhYqojbFHCAFoc7eTFedyq0NjowREn9PYLJYipAGDphyJ4wNBCLq2+3SzZtYCFlX9HQxYT+X9u9LETClQ0rS+xAoGAPqqwvVFvd1r71Szvi1e2YzH+CqLu53RICAbWzTbN1C3X8lgfqWACMaJUozh7iQyrfhEyANWUpGFifXE7sFbWl9UWTCh7e/W41p88ZQVPVKHXtiusO20DofVoKEqUvm3rdWsVo1CG0Y1u2+UJ0qcdiViJqGUOGn7pt1HryRcVgocCgYACxeW/glc9VdYWdRK5W7/zsH2+xUp80dK06Si5+oi7nxKoaFq2AalAFRgQIQqC5CgmcwoFE5T1T16IexQDI2hPO2AImiPoDBvCvib3KyojhRY/LQNH9OMlsQXELljTAE79vMg3HvlrKWNJg7siHA9cFmaJXRgFIxdpQ9fMRrJ7ng=='

    publicKeyWorker = KeyWorker(strPubKey)
    privateKeyWorker = KeyWorker(strPriKey)
    # message = 'hello python'
    message = '-!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!hello python!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!-'

    print('测试加密:')
    encrypted = publicKeyWorker.encrypt(message)
    print(encrypted)

    print('测试解密:')
    decrypted = privateKeyWorker.decrypt(encrypted)
    print(decrypted)

    print('测试签名:')
    signed = privateKeyWorker.sign(message)
    print(signed)

    print('测试验签:')
    signSuccess = publicKeyWorker.verify(message, signed)
    print(signSuccess)


    # print('私钥加密:')
    # encrypted2= privateKeyWorker.encrypt('hello2')
    # print(encrypted2)
    # print('公钥解密:')
    # decrypted2 = publicKeyWorker.decrypt(encrypted2)
    # print(decrypted2)
