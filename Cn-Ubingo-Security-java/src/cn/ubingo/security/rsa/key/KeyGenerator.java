package cn.ubingo.security.rsa.key;

import java.security.NoSuchAlgorithmException;

import cn.ubingo.security.rsa.core.KeyFormat;
/*
³Â·þ½¨(fochen,j@ubingo.cn)
2015-01-23
*/
public class KeyGenerator {

	static public KeyPair generateKeyPair(KeyFormat format)
			throws NoSuchAlgorithmException {
		KeyPair keyPair = new KeyPair(format);

		return keyPair;
	}

	static public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		return generateKeyPair(KeyFormat.ASN);
	}
}
