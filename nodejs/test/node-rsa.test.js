var NodeRSA  = require('node-rsa');

// var key = new NodeRSA({b: 512});

// var text = 'Hello RSA!';
// var encrypted = key.encrypt(text, 'base64');
// console.log('encrypted: ', encrypted);
// var decrypted = key.decrypt(encrypted, 'utf8');
// console.log('decrypted: ', decrypted);

var strPubKey = '-----BEGIN PUBLIC KEY-----\n'+
'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnaf6bHe76tz7yPQNj7TK\n'+
'mLiDk+ujB0jsJ9RDmxum0KMZVTFaphL8oWHncPBeih4Vt0F8pA6ian+kKd4AyO57\n'+
'W/0RBpSkCKoRVbeCKQM5yJ5fPovVAI+drBZDcqHVsPoauky86EhUGilAVulI+hBy\n'+
'VddBZYMn+xg9WUI/7H1u+4p4nPzgO6PIIPWTDthnbfz7nsHtTa+9bfuDSLPTnV5l\n'+
'shn6GIrMmwAi2aNZICXyHuXpZS74pTnqbXFdZ/8iRnhz5DCmJBXFmxTdm7DY5mAm\n'+
'nhaGkaDScI+y7WTjGmxGEJxPdKIiES4IImnej9+G7BHrBCneSLDp994crQdHGXCd\n'+
'NwIDAQAB\n'+
'-----END PUBLIC KEY-----';

var strPriKey ='-----BEGIN PRIVATE KEY-----MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCdp/psd7vq3PvI9A2PtMqYuIOT66MHSOwn1EObG6bQoxlVMVqmEvyhYedw8F6KHhW3QXykDqJqf6Qp3gDI7ntb/REGlKQIqhFVt4IpAznInl8+i9UAj52sFkNyodWw+hq6TLzoSFQaKUBW6Uj6EHJV10Flgyf7GD1ZQj/sfW77inic/OA7o8gg9ZMO2Gdt/Puewe1Nr71t+4NIs9OdXmWyGfoYisybACLZo1kgJfIe5ellLvilOeptcV1n/yJGeHPkMKYkFcWbFN2bsNjmYCaeFoaRoNJwj7LtZOMabEYQnE90oiIRLggiad6P34bsEesEKd5IsOn33hytB0cZcJ03AgMBAAECggEAXatiFHQHSIHHbxvhutI11Qs70fUcxcVD2l45VLzXHfrpoD5Ul3uMce4TbnzCDtnVGS5leavgP9palS171eYrkPoI1ZoW47b32a/QO8HY4SOHf0fhZBXwHkCUDlWs+xt+KdZSHshqf6imu3ybiUegRvQ/vKpyZLOAL7o29LGJ8RTj2LzFIVgzllV6xoVEycLQdLp33VuiQcodsHy4Dv23Dr+6KwY0gJfXq3USlGpeGzW8Ezt7oxtPQJ+x+SosliGTAL6IUBUaJkkE1NBEshPAi9OymrOGAjy7LUAQnZPJEdzKZBdVNI/cU1O7fRMqtDHJdv4thRM4oGvkBTO2jhs1YQKBgQDLvv+Ozet/UXCW2GX746+ZH3+PEhAjdvxlcd59Dd6kFcbX7BJQ+4trT9VwpzBPh5uBKDLI9mWzZ/DMS9GVU0f7+XWL6n+95C2NydK0SxNcOV91z8QWVDbcZKnj36BR5PccWRWKJspLXM8gvWsz/xs3aCfnx5pB+KOwdorydLOVSQKBgQDGFu8rpoPnx6LaSbknV5oYYOsN2oHmbkGq6Xnh6q0sSUvNrC97bvxtWwqNMdsmPh1MGx2r2/awhQrWxLWG87N6i23e6x2zfDzaQTUJGK/aFUQ+nmX0SQk1+82kr/CBCgl/1wtNiCHoOM2s/8MMkactk04om3XzJYB6btgxIQMefwKBgB5DAiYtw5qnd/ePsKYXDU/K8+FGJ4t88sQGg6tDUhxA98W+VIIeunh35RXUX0KQu7IVTGW44yYgfA17/WcWdYyhYqojbFHCAFoc7eTFedyq0NjowREn9PYLJYipAGDphyJ4wNBCLq2+3SzZtYCFlX9HQxYT+X9u9LETClQ0rS+xAoGAPqqwvVFvd1r71Szvi1e2YzH+CqLu53RICAbWzTbN1C3X8lgfqWACMaJUozh7iQyrfhEyANWUpGFifXE7sFbWl9UWTCh7e/W41p88ZQVPVKHXtiusO20DofVoKEqUvm3rdWsVo1CG0Y1u2+UJ0qcdiViJqGUOGn7pt1HryRcVgocCgYACxeW/glc9VdYWdRK5W7/zsH2+xUp80dK06Si5+oi7nxKoaFq2AalAFRgQIQqC5CgmcwoFE5T1T16IexQDI2hPO2AImiPoDBvCvib3KyojhRY/LQNH9OMlsQXELljTAE79vMg3HvlrKWNJg7siHA9cFmaJXRgFIxdpQ9fMRrJ7ng==-----END PRIVATE KEY-----'

options = {
  encryptionScheme: {
    scheme: 'pkcs8', //scheme
    hash: 'md5', //hash using for scheme
    //mgf: function(...) {...} //mask generation function
  },
  signingScheme: {
    scheme: 'pss', //scheme
    hash: 'sha1', //hash using for scheme
    saltLength: 20 //salt length for pss sign
  }
}
var pubKey = new NodeRSA();
var priKey = new NodeRSA();
var message = 'hello nodejs'

pubKey.importKey(strPubKey);
priKey.importKey(strPriKey);

var pubSize = pubKey.getKeySize();
var priSize = pubKey.getKeySize();
console.log(pubSize)
console.log(priSize)

var encrypted = pubKey.encrypt(message);
console.log(encrypted.toString('base64'))

var decrypted = priKey.decrypt(encrypted)
console.log(decrypted.toString())

var signed = priKey.sign(message)
console.log(signed.toString('base64'))