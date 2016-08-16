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
	function _get_MAX_ENCRYPT_BLOCK(){
		return 2048 / 8 - 11;
	}
	function _get_MAX_DECRYPT_BLOCK(){
		return 2048 / 8;
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
		var encrypted = new Buffer(0);

		//分段加密
		var maxSize = _get_MAX_ENCRYPT_BLOCK();
		if(source.length > maxSize){
			var count = Math.ceil(source.length * 1.0 / maxSize);

			for(var i=0; i<count; i++){
				var bufferSize = maxSize;
				if(i+1 >= count){bufferSize = source.length - (i * maxSize)}

				var buffer = new Buffer(bufferSize);
				source.copy(buffer, 0, i * maxSize, (i + 1) * maxSize)
				var bufferEncrypted = crypto.publicEncrypt(options, buffer)
				encrypted = Buffer.concat([encrypted, bufferEncrypted])
			}
		}else{
			encrypted = crypto.publicEncrypt(options, source)
		}
		
		return encrypted.toString('base64');
	}
	function decrypt(data){
		var options = {
			key: pri.key,
			padding: constants.RSA_PKCS1_PADDING
		}
		var source = new Buffer(data,'base64');
		var decrypted = new Buffer(0);

		//分段解密
		var maxSize = _get_MAX_DECRYPT_BLOCK();
		if(source.length > maxSize){
			var count = Math.ceil(source.length * 1.0 / maxSize);

			for(var i=0; i<count; i++){
				var bufferSize = maxSize;
				if(i+1 >= count){bufferSize = source.length - (i * maxSize)}
					
				var buffer = new Buffer(bufferSize);
				source.copy(buffer, 0, i * maxSize, (i + 1) * maxSize)
				var bufferDecrypted = crypto.privateDecrypt(options, buffer)
				decrypted = Buffer.concat([decrypted, bufferDecrypted])
			}
		}else{
			decrypted = crypto.privateDecrypt(options, source)
		}		
		
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