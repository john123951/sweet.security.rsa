var crypto = require('crypto');
var constants = require('constants');

module.exports = function keyWorker(key){	
	function _base64encode(input){
		var buffer = new Buffer(input);
		return buffer.toString('base64');
	}
	function _base64decode(input){
		var buffer = new Buffer(input,'base64');
		return buffer.toString();
	}
	function _asn2pem(key){
		var isPrivate = key.length > 500
		var count = Math.ceil(key.length * 1.0 / 64)

		keyList = []
		for(var i = 0; i<count; i++){
			keyList.push(key.substring(i * 64, (i + 1) * 64))
		}
		
		var finalKey = ''

		if(isPrivate){
			finalKey = '-----BEGIN PRIVATE KEY-----\n';
			finalKey = finalKey + keyList.join('\n')
			finalKey = finalKey + '\n-----END PRIVATE KEY-----'

		}else{			
            finalKey = '-----BEGIN PUBLIC KEY-----\n'
            finalKey = finalKey + keyList.join('\n')
            finalKey = finalKey + '\n-----END PUBLIC KEY-----'
		}
		return finalKey
	}

	function encrypt(data){
		var options = {
			key: pri.key,
			padding: constants.RSA_PKCS1_PADDING
		}
		var source = new Buffer(_base64encode(data));

		var encrypted = crypto.publicEncrypt(options, source)
		return encrypted.toString('base64');
	}
	function decrypt(data){
		var options = {
			key: pri.key,
			padding: constants.RSA_PKCS1_PADDING
		}
		var source = new Buffer(data,'base64');

		var decrypted = crypto.privateDecrypt(options, source)
		return _base64decode(decrypted.toString())
	}
	function sign(data){
		const signer = crypto.createSign('SHA1');
		signer.update(data);

		return signer.sign(pri.key, 'base64')
	}
	function verify(rawData, signature){
		const verifier = crypto.createVerify('SHA1');
		verifier.update(rawData);

		return verifier.verify(pri.key, signature, 'base64');
	}

	var pri = {
		key: '',
		format: 'ASN'	//'ASN', 'PEM'
	}

	var pub = {
		//RSA加密
		encrypt: encrypt,
		//RSA解密
		decrypt: decrypt,
		//签名
		sign: sign,
		//验签
		verify: verify

	}

	//ctor
	if(pri.format == 'ASN'){
		pri.key = _asn2pem(key);
	}else{
		pri.key = key;
	}


	return pub;
}