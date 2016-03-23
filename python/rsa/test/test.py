# -*- encoding:utf-8 -*-
import base64
import rsa

(pub, pri) = rsa.newkeys(1024)

print(pub._save_pkcs1_pem())
print(pri.save_pkcs1())
print('\n')

# exit()
# hbPubKey = "-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnaf6bHe76tz7yPQNj7TKmLiDk+ujB0jsJ9RDmxum0KMZVTFaphL8oWHncPBeih4Vt0F8pA6ian+kKd4AyO57W" \
#            "/0RBpSkCKoRVbeCKQM5yJ5fPovVAI+drBZDcqHVsPoauky86EhUGilAVulI+hByVddBZYMn+xg9WUI/7H1u+4p4nPzgO6PIIPWTDthnbfz7nsHtTa+9bfuDSLPTnV5lshn6GIrMmwAi2aNZICXyHuXpZS74pTnqbX" \
#            "FdZ/8iRnhz5DCmJBXFmxTdm7DY5mAmnhaGkaDScI+y7WTjGmxGEJxPdKIiES4IImnej9+G7BHrBCneSLDp994crQdHGXCdNwIDAQAB\n-----END RSA PUBLIC KEY-----\n";

hbPubKey = pub.save_pkcs1()
hbPriKey = pri.save_pkcs1();
rawData = 'hello'.encode('utf-8')
encryptData = 'ih03BfEHW5V1o/zKXF+yeriGfSOx/1hJZNNpQQ3qRZUQc5qJiV+/jb3rMdTCYyotMWHSOZqLjyBHE8CD4npunNHFuqcbhmqikGYaY9z28F5WzDVYnSM9quB9p0G0Z6jFF6bJ2AgIQApgYhAMOZ4OcmwR4otlxYOSy6rhH0z+C689ipKKH5kS8oxJZixy8Wgd4zGdPsB6GrJPXjs3hCkmnSSZEhxX73FfA1u2SlRruBPoqhkIfDjivIsH3ud+DBVw5Y0gsgXbL4dwy8ZabtlA3I0cWxY6yLB20ZGeWA0e0SV+kERBs1A1RBOo7h+wBvV3UyAgY8PfdlZZ5Gh+4sqBbA=='

publicKey = rsa.PublicKey.load_pkcs1(hbPubKey)
encryptData = rsa.encrypt(rawData, publicKey)
result = str(encryptData)
print(result)
print(base64.encodebytes(encryptData))

# 解密
privateKey = rsa.PrivateKey.load_pkcs1(hbPriKey)
result = rsa.decrypt(encryptData, privateKey)
print(result)
print('%s' % (result.decode('utf-8')))
