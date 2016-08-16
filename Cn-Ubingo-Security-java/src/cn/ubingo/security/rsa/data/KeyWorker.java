package cn.ubingo.security.rsa.data;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import cn.ubingo.security.interop.XmlKeyBuilder;
import cn.ubingo.security.rsa.core.KeyFormat;

public class KeyWorker {

    private String _key;
    private int _keySize;
    private KeyFormat _format;
    private Cipher _decryptProvider;
    private Cipher _encryptProvider;

    private static final String CIPHER_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String SIGN_ALGORITHMS = "SHA1WithRSA";

    /**
     * RSA最大加密明文大小
     */
    public int getMAX_ENCRYPT_BLOCK() {
        return _keySize / 8 - 11;
    }

    /**
     * RSA最大解密密文大小
     */
    public int getMAX_DECRYPT_BLOCK() {
        return _keySize / 8;
    }

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

        BASE64Encoder bASE64Encoder = new BASE64Encoder();

        byte[] source = bASE64Encoder.encode(data.getBytes("UTF-8")).getBytes(
                "UTF-8");

        int length = source.length;
        int maxSize = getMAX_ENCRYPT_BLOCK();
        int offset = 0;
        byte[] cache;
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        int i = 0;
        while (length - offset > 0) {
            if (length - offset > maxSize) {
                cache = this._encryptProvider.doFinal(source, offset, maxSize);
            } else {
                cache = this._encryptProvider.doFinal(source, offset, length
                        - offset);
            }
            outStream.write(cache, 0, cache.length);
            i++;
            offset = i * maxSize;
        }

        byte[] encrypted = outStream.toByteArray();
        outStream.close();

        return bASE64Encoder.encode(encrypted);
    }

    public String decrypt(String data) throws IOException,
            IllegalBlockSizeException, BadPaddingException,
            InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeySpecException, SAXException,
            ParserConfigurationException {
        this._makesureDecryptProvider();

        BASE64Decoder base64Decoder = new BASE64Decoder();

        byte[] source = base64Decoder.decodeBuffer(data);

        int length = source.length;
        int maxSize = getMAX_DECRYPT_BLOCK();
        int offset = 0;
        int i = 0;
        byte[] cache;
        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        while (length - offset > 0) {
            if (length - offset > maxSize) {
                cache = this._decryptProvider.doFinal(source, offset, maxSize);
            } else {
                cache = this._decryptProvider.doFinal(source, offset, length
                        - offset);
            }
            outStream.write(cache, 0, cache.length);
            i++;
            offset = i * maxSize;
        }

        byte[] decrypted = outStream.toByteArray();
        decrypted = base64Decoder.decodeBuffer(new String(decrypted, "UTF-8"));

        return new String(decrypted, "UTF-8");
    }

    public String sign(String orgData) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException,
            InvalidKeyException, SignatureException {

        BASE64Decoder base64Decoder = new BASE64Decoder();
        BASE64Encoder bASE64Encoder = new BASE64Encoder();
        String privateKey = this._key;

        PKCS8EncodedKeySpec priPKCS8 = new PKCS8EncodedKeySpec(
                base64Decoder.decodeBuffer(privateKey));
        KeyFactory keyf = KeyFactory.getInstance("RSA");
        PrivateKey priKey = keyf.generatePrivate(priPKCS8);

        java.security.Signature signature = java.security.Signature
                .getInstance(SIGN_ALGORITHMS);

        signature.initSign(priKey);
        signature.update(orgData.getBytes("utf-8"));

        byte[] signed = signature.sign();
        return bASE64Encoder.encode(signed);

    }

    public boolean verify(String content, String sign) {
        try {
            BASE64Decoder base64Decoder = new BASE64Decoder();
            String publicKey = this._key;

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            byte[] encodedKey = base64Decoder.decodeBuffer(publicKey);
            PublicKey pubKey = keyFactory
                    .generatePublic(new X509EncodedKeySpec(encodedKey));

            java.security.Signature signature = java.security.Signature
                    .getInstance(SIGN_ALGORITHMS);

            signature.initVerify(pubKey);
            signature.update(content.getBytes("utf-8"));

            boolean bverify = signature
                    .verify(base64Decoder.decodeBuffer(sign));
            return bverify;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return false;
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
                        .replaceAll("\r\n", "").trim();
            }
            case ASN:
            default: {
                Boolean isPrivate = this._key.length() > 500;
                if (isPrivate) {
                    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(new BASE64Decoder().decodeBuffer(this._key));

                    KeyFactory factory = KeyFactory.getInstance("RSA");
                    RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(spec);
                    deCipher.init(Cipher.DECRYPT_MODE, privateKey);

                    this._keySize = getPrivateKeySize(privateKey);
                } else {
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(
                            new BASE64Decoder().decodeBuffer(this._key));

                    KeyFactory factory = KeyFactory.getInstance("RSA");
                    RSAPublicKey publicKey = (RSAPublicKey) factory
                            .generatePublic(spec);
                    deCipher.init(Cipher.DECRYPT_MODE, publicKey);

                    this._keySize = getPublicKeySize(publicKey);
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

        Cipher enCipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
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
                        .replaceAll("\r\n", "").trim();
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

                    this._keySize = getPrivateKeySize(privateKey);

                } else {
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(
                            new BASE64Decoder().decodeBuffer(this._key));

                    KeyFactory factory = KeyFactory.getInstance("RSA");
                    RSAPublicKey publicKey = (RSAPublicKey) factory
                            .generatePublic(spec);
                    enCipher.init(Cipher.ENCRYPT_MODE, publicKey);

                    this._keySize = getPublicKeySize(publicKey);
                }
            }
            break;
        }

        this._encryptProvider = enCipher;
    }


    private static int getPrivateKeySize(Key publickey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String algorithm = publickey.getAlgorithm(); // 获取算法
        KeyFactory keyFact = KeyFactory.getInstance(algorithm);
        BigInteger prime = null;
        if ("RSA".equals(algorithm)) { // 如果是RSA加密
            RSAPrivateKeySpec keySpec = (RSAPrivateKeySpec) keyFact.getKeySpec(
                    publickey, RSAPrivateKeySpec.class);
            prime = keySpec.getModulus();
            int len = prime.toString(2).length(); // 转换为二进制，获取公钥长度
            return len;
        }
        return 0;
    }

    private static int getPublicKeySize(Key publickey)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String algorithm = publickey.getAlgorithm(); // 获取算法
        KeyFactory keyFact = KeyFactory.getInstance(algorithm);
        BigInteger prime = null;
        if ("RSA".equals(algorithm)) { // 如果是RSA加密
            RSAPublicKeySpec keySpec = (RSAPublicKeySpec) keyFact.getKeySpec(
                    publickey, RSAPublicKeySpec.class);
            prime = keySpec.getModulus();
            int len = prime.toString(2).length(); // 转换为二进制，获取公钥长度
            return len;
        }
        return 0;
    }
}
