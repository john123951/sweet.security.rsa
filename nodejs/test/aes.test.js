var security = require('security')

var aesUtility = security.aesUtility;
console.log(Object.keys(aesUtility))

var key = "j0Hn0sdowMoOUxnSBVpxbl"
var message = 'hello nodejs'

console.log('测试AES加密')
var encrypted = aesUtility.encrypt(message,key);
console.log(encrypted)

console.log('测试AES解密')
var decrypted = aesUtility.decrypt(encrypted,key);
console.log(decrypted)

console.log('==== 测试通过 ====')