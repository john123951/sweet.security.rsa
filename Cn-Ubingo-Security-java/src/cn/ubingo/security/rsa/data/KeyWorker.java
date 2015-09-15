package cn.ubingo.security.rsa.data;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import cn.ubingo.security.interop.XmlKeyBuilder;
import cn.ubingo.security.rsa.core.KeyFormat;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/*
 ³Â·þ½¨(fochen,j@ubingo.cn)
 2015-01-23
 */
public class KeyWorker {

	private String _key;
	private KeyFormat _format;
	private Cipher _decryptProvider;
	private Cipher _encryptProvider;

	public KeyWorker(String key) {
		this(key, KeyFormat.ASN);
	}

	public KeyWorker(String key, KeyFormat format) {
		this._key = key;
		this._format = format;
	}

	public String encrypt(String data) throws IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeySpecException, IOException,
			SAXException, ParserConfigurationException {
		this._makesureEncryptProvider();
		byte[] bytes = data.getBytes("UTF-8");
		bytes = this._encryptProvider.doFinal(bytes);
		return new BASE64Encoder().encode(bytes);
	}

	public String decrypt(String data) throws IOException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeySpecException, SAXException,
			ParserConfigurationException {
		this._makesureDecryptProvider();

		byte[] bytes = new BASE64Decoder().decodeBuffer(data);
		bytes = this._decryptProvider.doFinal(bytes);
		return new String(bytes, "UTF-8");
	}

	private void _makesureDecryptProvider() throws NoSuchAlgorithmException,
			NoSuchPaddingException, IOException, InvalidKeySpecException,
			InvalidKeyException, SAXException, ParserConfigurationException {
		if (this._decryptProvider != null)
			return;

		Cipher deCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		switch (this._format) {
		case XML: {
			Boolean isPrivate = this._key.indexOf("<P>") > -1;
			if (isPrivate) {
				PrivateKey privateKey = XmlKeyBuilder
						.xmlToPrivateKey(this._key);
				deCipher.init(Cipher.DECRYPT_MODE, privateKey);
			} else {
				PublicKey publicKey = XmlKeyBuilder.xmlToPublicKey(this._key);
				deCipher.init(Cipher.DECRYPT_MODE, publicKey);
			}
		}
			break;
		case PEM: {
			this._key = this._key.replace("-----BEGIN PUBLIC KEY-----", "")
					.replace("-----END PUBLIC KEY-----", "")
					.replace("-----BEGIN PRIVATE KEY-----", "")
					.replace("-----END PRIVATE KEY-----", "")
					.replaceAll("\r\n", "")
					.trim();
		}
		case ASN:
		default: {
			Boolean isPrivate = this._key.length() > 500;
			if (isPrivate) {
				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(
						new BASE64Decoder().decodeBuffer(this._key));

				KeyFactory factory = KeyFactory.getInstance("RSA");
				RSAPrivateKey privateKey = (RSAPrivateKey) factory
						.generatePrivate(spec);
				deCipher.init(Cipher.DECRYPT_MODE, privateKey);
			} else {
				X509EncodedKeySpec spec = new X509EncodedKeySpec(
						new BASE64Decoder().decodeBuffer(this._key));

				KeyFactory factory = KeyFactory.getInstance("RSA");
				RSAPublicKey publicKey = (RSAPublicKey) factory
						.generatePublic(spec);
				deCipher.init(Cipher.DECRYPT_MODE, publicKey);
			}
		}
			break;
		}

		this._decryptProvider = deCipher;
	}

	private void _makesureEncryptProvider() throws NoSuchAlgorithmException,
			NoSuchPaddingException, IOException, InvalidKeySpecException,
			InvalidKeyException, SAXException, ParserConfigurationException {
		if (this._encryptProvider != null)
			return;

		Cipher enCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		switch (this._format) {
		case XML: {
			Boolean isPrivate = this._key.indexOf("<P>") > -1;
			if (isPrivate) {
				PrivateKey privateKey = XmlKeyBuilder
						.xmlToPrivateKey(this._key);
				enCipher.init(Cipher.ENCRYPT_MODE, privateKey);
			} else {
				PublicKey publicKey = XmlKeyBuilder.xmlToPublicKey(this._key);
				enCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			}
		}
			break;
		case PEM: {
			this._key = this._key.replace("-----BEGIN PUBLIC KEY-----", "")
					.replace("-----END PUBLIC KEY-----", "")
					.replace("-----BEGIN PRIVATE KEY-----", "")
					.replace("-----END PRIVATE KEY-----", "")
					.replaceAll("\r\n", "")
					.trim();
		}
		case ASN:
		default: {
			Boolean isPrivate = this._key.length() > 500;
			if (isPrivate) {
				PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(
						new BASE64Decoder().decodeBuffer(this._key));

				KeyFactory factory = KeyFactory.getInstance("RSA");
				RSAPrivateKey privateKey = (RSAPrivateKey) factory
						.generatePrivate(spec);
				enCipher.init(Cipher.ENCRYPT_MODE, privateKey);

			} else {
				X509EncodedKeySpec spec = new X509EncodedKeySpec(
						new BASE64Decoder().decodeBuffer(this._key));

				KeyFactory factory = KeyFactory.getInstance("RSA");
				RSAPublicKey publicKey = (RSAPublicKey) factory
						.generatePublic(spec);
				enCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			}
		}
			break;
		}

		this._encryptProvider = enCipher;
	}

}
