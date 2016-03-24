var crypto = require('crypto');
var constants = require('constants');

var strPubKey = '-----BEGIN PUBLIC KEY-----\n'+
'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnaf6bHe76tz7yPQNj7TK\n'+
'mLiDk+ujB0jsJ9RDmxum0KMZVTFaphL8oWHncPBeih4Vt0F8pA6ian+kKd4AyO57\n'+
'W/0RBpSkCKoRVbeCKQM5yJ5fPovVAI+drBZDcqHVsPoauky86EhUGilAVulI+hBy\n'+
'VddBZYMn+xg9WUI/7H1u+4p4nPzgO6PIIPWTDthnbfz7nsHtTa+9bfuDSLPTnV5l\n'+
'shn6GIrMmwAi2aNZICXyHuXpZS74pTnqbXFdZ/8iRnhz5DCmJBXFmxTdm7DY5mAm\n'+
'nhaGkaDScI+y7WTjGmxGEJxPdKIiES4IImnej9+G7BHrBCneSLDp994crQdHGXCd\n'+
'NwIDAQAB\n'+
'-----END PUBLIC KEY-----';

var strPriKey ='-----BEGIN PRIVATE KEY-----\n'+
'MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCdp/psd7vq3PvI\n'+
'9A2PtMqYuIOT66MHSOwn1EObG6bQoxlVMVqmEvyhYedw8F6KHhW3QXykDqJqf6Qp\n'+
'3gDI7ntb/REGlKQIqhFVt4IpAznInl8+i9UAj52sFkNyodWw+hq6TLzoSFQaKUBW\n'+
'6Uj6EHJV10Flgyf7GD1ZQj/sfW77inic/OA7o8gg9ZMO2Gdt/Puewe1Nr71t+4NI\n'+
's9OdXmWyGfoYisybACLZo1kgJfIe5ellLvilOeptcV1n/yJGeHPkMKYkFcWbFN2b\n'+
'sNjmYCaeFoaRoNJwj7LtZOMabEYQnE90oiIRLggiad6P34bsEesEKd5IsOn33hyt\n'+
'B0cZcJ03AgMBAAECggEAXatiFHQHSIHHbxvhutI11Qs70fUcxcVD2l45VLzXHfrp\n'+
'oD5Ul3uMce4TbnzCDtnVGS5leavgP9palS171eYrkPoI1ZoW47b32a/QO8HY4SOH\n'+
'f0fhZBXwHkCUDlWs+xt+KdZSHshqf6imu3ybiUegRvQ/vKpyZLOAL7o29LGJ8RTj\n'+
'2LzFIVgzllV6xoVEycLQdLp33VuiQcodsHy4Dv23Dr+6KwY0gJfXq3USlGpeGzW8\n'+
'Ezt7oxtPQJ+x+SosliGTAL6IUBUaJkkE1NBEshPAi9OymrOGAjy7LUAQnZPJEdzK\n'+
'ZBdVNI/cU1O7fRMqtDHJdv4thRM4oGvkBTO2jhs1YQKBgQDLvv+Ozet/UXCW2GX7\n'+
'46+ZH3+PEhAjdvxlcd59Dd6kFcbX7BJQ+4trT9VwpzBPh5uBKDLI9mWzZ/DMS9GV\n'+
'U0f7+XWL6n+95C2NydK0SxNcOV91z8QWVDbcZKnj36BR5PccWRWKJspLXM8gvWsz\n'+
'/xs3aCfnx5pB+KOwdorydLOVSQKBgQDGFu8rpoPnx6LaSbknV5oYYOsN2oHmbkGq\n'+
'6Xnh6q0sSUvNrC97bvxtWwqNMdsmPh1MGx2r2/awhQrWxLWG87N6i23e6x2zfDza\n'+
'QTUJGK/aFUQ+nmX0SQk1+82kr/CBCgl/1wtNiCHoOM2s/8MMkactk04om3XzJYB6\n'+
'btgxIQMefwKBgB5DAiYtw5qnd/ePsKYXDU/K8+FGJ4t88sQGg6tDUhxA98W+VIIe\n'+
'unh35RXUX0KQu7IVTGW44yYgfA17/WcWdYyhYqojbFHCAFoc7eTFedyq0NjowREn\n'+
'9PYLJYipAGDphyJ4wNBCLq2+3SzZtYCFlX9HQxYT+X9u9LETClQ0rS+xAoGAPqqw\n'+
'vVFvd1r71Szvi1e2YzH+CqLu53RICAbWzTbN1C3X8lgfqWACMaJUozh7iQyrfhEy\n'+
'ANWUpGFifXE7sFbWl9UWTCh7e/W41p88ZQVPVKHXtiusO20DofVoKEqUvm3rdWsV\n'+
'o1CG0Y1u2+UJ0qcdiViJqGUOGn7pt1HryRcVgocCgYACxeW/glc9VdYWdRK5W7/z\n'+
'sH2+xUp80dK06Si5+oi7nxKoaFq2AalAFRgQIQqC5CgmcwoFE5T1T16IexQDI2hP\n'+
'O2AImiPoDBvCvib3KyojhRY/LQNH9OMlsQXELljTAE79vMg3HvlrKWNJg7siHA9c\n'+
'FmaJXRgFIxdpQ9fMRrJ7ng==\n'+
'-----END PRIVATE KEY-----'

// console.log(crypto)
var message = 'hello nodejs';
var buffer = new Buffer(message);
console.log(message)

console.log('测试加密:')
var options = {
	key: strPubKey,
	padding: constants.RSA_PKCS1_PADDING
}
var encrypted = crypto.publicEncrypt(options, buffer)
console.log(encrypted.toString('base64'))

console.log('测试解密:')
var options = {
	key: strPriKey,
	padding: constants.RSA_PKCS1_PADDING
}
console.log(encrypted)
var decrypted = crypto.privateDecrypt(options, encrypted)
console.log(decrypted.toString())