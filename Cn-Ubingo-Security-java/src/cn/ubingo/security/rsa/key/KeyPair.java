package cn.ubingo.security.rsa.key;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import cn.ubingo.security.interop.XmlKeyBuilder;
import cn.ubingo.security.rsa.core.KeyFormat;
import sun.misc.*; 
/*
³Â·þ½¨(fochen,j@ubingo.cn)
2015-01-23
*/
public class KeyPair {
    private java.security.KeyPair _rsa;
    private KeyFormat _format;
    private String _private;
    private String _public;

    public KeyFormat getFormat()
    {
        return this._format; 
    }

    KeyPair(KeyFormat format) throws NoSuchAlgorithmException
    {
    	KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);
        this._rsa = kpg.genKeyPair();;
        this._format = format;
    }

    private KeyPair(java.security.KeyPair rsa, KeyFormat format)
    {
        this._rsa = rsa;
        this._format = format;
    }

    public String getPrivateKey()
    {
            if (this._private == null)
            {
                switch (this._format)
                {
                    case ASN:
                        this._private = this._toASNPrivateKey();
                        break;
                    case XML:
                        this._private = this._toXMLPrivateKey();
                        break;
                    case PEM:
                        this._private = this._toPEMPrivateKey();
                        break;
                    default:
                        this._private = this._toXMLPrivateKey();
                        break;
                }
            }
            return this._private;
    }

    public String getPublicKey()
    {
        if (this._public == null)
        {
            switch (this._format)
            {
                case ASN:
                    this._public = this._toASNPublicKey();
                    break;
                case XML:
                    this._public = this._toXMLPublicKey();
                    break;
                case PEM:
                    this._public = this._toPEMPublicKey();
                    break;
                default:
                    this._public = this._toXMLPublicKey();
                    break;
            }
        }
        return this._public;
    }

    public KeyPair toASNKeyPair()
    {
        return new KeyPair(this._rsa, KeyFormat.ASN);
    }
    public KeyPair toXMLKeyPair()
    {
        return new KeyPair(this._rsa, KeyFormat.XML);
    }
    public KeyPair toPEMKeyPair()
    {
        return new KeyPair(this._rsa, KeyFormat.PEM);
    }


    private String _toASNPublicKey()
    {
        return (new BASE64Encoder()).encodeBuffer(this._rsa.getPublic().getEncoded());
    }
    private String _toASNPrivateKey()
    {
    	return (new BASE64Encoder()).encodeBuffer(this._rsa.getPrivate().getEncoded());
    }
    private String _toXMLPublicKey()
    {
    	return XmlKeyBuilder.publicKeyToXML(this._rsa.getPublic());
    }
    private String _toXMLPrivateKey()
    {
    	return XmlKeyBuilder.privateKeyToXML(this._rsa.getPrivate());
    }
    private String _toPEMPublicKey()
    {
        String publicKey = this._toASNPublicKey();
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PUBLIC KEY-----\r\n");
        int i = 0;
        while (i + 64 < publicKey.length())
        {
            sb.append(publicKey.substring(i, i+64)+"\r\n");
            i += 64;
        }
        sb.append(publicKey.substring(i, publicKey.length())+"\r\n");
        sb.append("-----END PUBLIC KEY-----\r\n");

        return sb.toString();
    }
    private String _toPEMPrivateKey()
    {
        String privateKey = this._toASNPrivateKey();
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN PRIVATE KEY-----\r\n");
        int i = 0;
        while (i + 64 < privateKey.length())
        {
            sb.append(privateKey.substring(i, i+64)+"\r\n");
            i += 64;
        }
        sb.append(privateKey.substring(i, privateKey.length())+"\r\n");
        sb.append("-----END PRIVATE KEY-----\r\n");

        return sb.toString();
    }
}
