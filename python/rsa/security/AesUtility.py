#! -*- coding:utf-8 -*-
import base64
from Crypto.Cipher import AES
import itertools

__author__ = 'sweet'


class AesUtility:
    def encrypt(self, data, key):
        """
        @summary:
            1. pkcs7padding
            2. aes encrypt
            3. base64 encrypt
        @return:
            string
        """
        byteKey = base64.decodebytes(bytes(self._base64_align(key), 'utf-8'))
        iv = '\x01\x02\x03\x04\x05\x06\x06\x05\x04\x03\x02\x01\x07\x07\x07\x07'

        cipher = AES.new(byteKey, AES.MODE_CBC, iv)
        encryptData = cipher.encrypt(self._pkcs7padding(data))
        return base64.b64encode(encryptData).decode('utf-8')

    def decrypt(self, encryptData, key):
        """
        1. base64 decode
        2. aes decode
        3. dpkcs7padding
        """
        byteKey = base64.decodebytes(bytes(self._base64_align(key), 'utf-8'))
        iv = '\x01\x02\x03\x04\x05\x06\x06\x05\x04\x03\x02\x01\x07\x07\x07\x07'

        cipher = AES.new(byteKey, AES.MODE_CBC, iv)
        decryptData = cipher.decrypt(base64.b64decode(encryptData)).decode('utf-8')
        return self._depkcs7padding(decryptData)

    @staticmethod
    def _pkcs7padding(data):
        """
        对齐块
        size 16
        999999999=>9999999997777777
        """
        size = AES.block_size
        count = size - len(data) % size
        if count:
            data += (chr(count) * count)
        return data

    @staticmethod
    def _depkcs7padding(data):
        """
        反对齐
        """
        newdata = ''
        for c in data:
            if ord(c) > AES.block_size:
                newdata += c
        return newdata

    @staticmethod
    def _base64_align(strBase64):
        """
        对齐base64格式
        :param strBase64:
        :return:
        """
        length = len(strBase64)
        modeX = length % 4
        if modeX != 0:
            return strBase64 + ''.join(itertools.repeat('=', 4 - modeX))
        return strBase64


if __name__ == "__main__":
    aes = AesUtility()
    key = "j0Hn0sdowMoOUxnSBVpxbl"
    message = 'hello python'

    print('测试AES加密:')
    encrypted = aes.encrypt(message, key)
    print(encrypted)

    print('测试AES解密:')
    decrypted = aes.decrypt(encrypted, key)
    print(decrypted)
