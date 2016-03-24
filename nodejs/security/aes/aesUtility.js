var crypto = require('crypto');

// String.prototype.repeat = function(n){
function _repeat(char, n){
    return new Array(n + 1).join(char);
}

var _base64_align = function(strBase64){
	var length = strBase64.length
    var modeX = length % 4
    if (modeX != 0){
    	return strBase64 + _repeat('=',4 - modeX);
    }
    return strBase64
}

module.exports.encrypt = function (data, key){
	var alignKey = _base64_align(key);
	var bufferKey = new Buffer(alignKey, 'base64');
	var bufferIV = new Buffer([1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1, 7, 7, 7, 7]);

	var cipher = crypto.createCipheriv('AES-128-CBC', bufferKey, bufferIV);	
	cipher.update(data)
	var encrypted = cipher.final('base64')
	
	return encrypted;
}
module.exports.decrypt = function (data, key){
	var alignKey = _base64_align(key);
	var bufferKey = new Buffer(alignKey, 'base64');
	var bufferIV = new Buffer([1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1, 7, 7, 7, 7]);

	var decipher = crypto.createDecipheriv('AES-128-CBC', bufferKey, bufferIV);	
	decipher.update(data, 'base64')
	var decrypted = decipher.final()
	
	return decrypted.toString();
}