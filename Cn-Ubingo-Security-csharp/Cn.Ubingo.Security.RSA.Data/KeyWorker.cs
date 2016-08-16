using Cn.Ubingo.Security.Interop;
using Cn.Ubingo.Security.RSA.Core;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cn.Ubingo.Security.RSA.Data
{
    /// <summary>
    /// 陈服建(fochen,j@ubingo.cn)
    /// 2015-01-23
    /// PKCS1填充
    /// </summary>
    public class KeyWorker
    {
        #region 设置

        /// <summary>
        /// RSA最大加密明文大小
        /// </summary>
        private int MAX_ENCRYPT_BLOCK { get { return this._provider.KeySize / 8 - 11; } } //117;

        /// <summary>
        /// RSA最大解密密文大小
        /// </summary>
        private int MAX_DECRYPT_BLOCK { get { return this._provider.KeySize / 8; } }

        /// <summary>
        /// 编码格式
        /// </summary>
        private static readonly Encoding Encoding = Encoding.UTF8;

        #endregion 设置

        private readonly KeyFormat _format;
        private string _key;
        private RSACryptoServiceProvider _provider;

        public KeyWorker(string key, KeyFormat format)
        {
            this._key = key;
            this._format = format;
        }

        private void _MakesureProvider()
        {
            if (this._provider != null) return;

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            switch (this._format)
            {
                case KeyFormat.PEM:
                    {
                        this._key = this._key.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "")
                                             .Replace("-----BEGIN PRIVATE KEY-----", "").Replace("-----END PRIVATE KEY-----", "")
                                             .Replace("\r", "").Replace("\n", "");
                        goto case KeyFormat.ASN;
                    }
                case KeyFormat.ASN:
                    {
                        bool isPrivate = this._key.Length > 500;

                        AsnKeyParser keyParser = new AsnKeyParser(this._key);
                        RSAParameters key = isPrivate ? keyParser.ParseRSAPrivateKey() : keyParser.ParseRSAPublicKey();
                        rsa.ImportParameters(key);

                        break;
                    }
                case KeyFormat.XML:
                    {
                        //_isPrivate = this._key.IndexOf("<D>") > -1;
                        rsa.FromXmlString(this._key);
                        break;
                    }
                default:
                    throw new Exception("no support format");
                    break;
            }

            this._provider = rsa;
        }

        #region 加密、解密

        public string Encrypt(string rawData)
        {
            this._MakesureProvider();

            byte[] source = Encoding.GetBytes(Convert.ToBase64String(Encoding.GetBytes(rawData)));
            //byte[] source = Encoding.GetBytes(rawData);

            //原生.NET不提供私钥加密，公钥解密的方法，所以只能自行实现，但性能不知道如何。
            Func<byte[], byte[]> encryptFunc = _provider.PublicOnly
                                                ? new Func<byte[], byte[]>(x => this._provider.Encrypt(x, false))
                                                : new Func<byte[], byte[]>(x => this._EncryptByPriKey(x, this._provider));

            //分段加解密
            int length = source.Length;
            int offset = 0;

            using (MemoryStream outStream = new MemoryStream())
            {
                int i = 0;
                while (length - offset > 0)
                {
                    byte[] buff;
                    if (length - offset > MAX_ENCRYPT_BLOCK)
                    {
                        byte[] encryptBytes = new byte[MAX_ENCRYPT_BLOCK];
                        Array.Copy(source, offset, encryptBytes, 0, MAX_ENCRYPT_BLOCK);

                        buff = encryptFunc(encryptBytes);
                    }
                    else
                    {
                        int len = length - offset;
                        byte[] encryptBytes = new byte[len];
                        Array.Copy(source, offset, encryptBytes, 0, len);

                        buff = encryptFunc(encryptBytes);
                    }
                    outStream.Write(buff, 0, buff.Length);
                    i++;
                    offset = i * MAX_ENCRYPT_BLOCK;
                }
                return Convert.ToBase64String(outStream.ToArray());
            }
        }

        public string Decrypt(string encryptString)
        {
            this._MakesureProvider();

            byte[] encryptData = Convert.FromBase64String(encryptString);

            //原生.NET不提供私钥加密，公钥解密的方法，所以只能自行实现，但性能不知道如何。
            Func<byte[], byte[]> decryptFunc = _provider.PublicOnly
                                                ? new Func<byte[], byte[]>(x => this._DecryptByPubKey(x, this._provider))
                                                : new Func<byte[], byte[]>(x => this._provider.Decrypt(x, false));

            //分段加解密
            int length = encryptData.Length;
            int offset = 0;

            using (MemoryStream outStream = new MemoryStream())
            {
                int i = 0;
                while (length - offset > 0)
                {
                    byte[] buff;
                    if (length - offset > MAX_DECRYPT_BLOCK)
                    {
                        byte[] decryptBytes = new byte[MAX_DECRYPT_BLOCK];
                        Array.Copy(encryptData, offset, decryptBytes, 0, MAX_DECRYPT_BLOCK);

                        buff = decryptFunc(decryptBytes);
                    }
                    else
                    {
                        int len = length - offset;
                        byte[] decryptBytes = new byte[len];
                        Array.Copy(encryptData, offset, decryptBytes, 0, len);

                        buff = decryptFunc(decryptBytes);
                    }
                    outStream.Write(buff, 0, buff.Length);
                    i++;
                    offset = i * MAX_DECRYPT_BLOCK;
                }

                using (var sReader = new StreamReader(outStream, Encoding))
                {
                    outStream.Position = 0;
                    string result = Encoding.GetString(Convert.FromBase64String(sReader.ReadToEnd()));

                    return result;
                }
            }
        }

        #endregion 加密、解密

        #region 签名、验签

        /// <summary>
        /// 加签 sign the data
        /// </summary>
        /// <param name="dataToBeSigned">要加签的数据</param>
        /// <returns></returns>
        public string SignDataMicrosoft(string dataToBeSigned)
        {
            this._MakesureProvider();

            if (_provider.PublicOnly)
            {
                throw new Exception("not a private key");
            }
            byte[] data = Encoding.GetBytes(dataToBeSigned);
            //byte[] data = Convert.FromBase64String(dataToBeSigned);

            byte[] endata = _provider.SignData(data, typeof(SHA1));

            return Convert.ToBase64String(endata);
        }

        /// <summary>
        /// 验签
        /// </summary>
        /// <param name="signature"> 要验证的签名数据（Base64）</param>
        /// <param name="signedData">签名前的原始数据（Base64）</param>
        /// <returns></returns>
        public bool VerifySignatureMicrosoft(string signature, string signedData)
        {
            this._MakesureProvider();

            byte[] buffer = Encoding.GetBytes(signedData);
            //byte[] buffer = Convert.FromBase64String(signedData);
            byte[] sign = Convert.FromBase64String(signature);

            // 参数:
            //   buffer:
            //     已签名的数据。
            //
            //   halg:
            //     用于创建数据的哈希值的哈希算法名称。
            //
            //   signature:
            //     要验证的签名数据。
            return _provider.VerifyData(buffer, typeof(SHA1), sign);
        }

        #endregion 签名、验签

        #region 格式转换

        public KeyPair ToKeyPair()
        {
            return new KeyPair(this._provider, this._format);
        }

        #endregion 格式转换

        #region 自行实现的RSA PKCS1填充方式的算法

        //填充
        private byte[] _AddPKCS1Padding(byte[] oText, int blockLen)
        {
            byte[] result = new byte[blockLen];
            result[0] = 0x00;
            result[1] = 0x01;
            int padLen = blockLen - 3 - oText.Length;
            for (int i = 0; i < padLen; i++)
            {
                result[i + 2] = 0xff;
            }
            result[padLen + 2] = 0x00;

            for (int j = 0, i = padLen + 3; i < blockLen; i++)
            {
                result[i] = oText[j++];
            }
            return result;
        }

        //私钥加密
        private byte[] _PriEncrypt(byte[] block, RSACryptoServiceProvider key)
        {
            RSAParameters param = key.ExportParameters(true);
            BigInteger d = new BigInteger(param.D);
            BigInteger n = new BigInteger(param.Modulus);
            BigInteger biText = new BigInteger(block);
            BigInteger biEnText = biText.modPow(d, n);
            return biEnText.getBytes();
        }

        private byte[] _EncryptByPriKey(byte[] oText, RSACryptoServiceProvider key)
        {
            //获得明文字节数组
            //byte[] oText = System.Text.Encoding.UTF8.GetBytes(src);

            //填充
            oText = this._AddPKCS1Padding(oText, MAX_DECRYPT_BLOCK);

            //加密
            byte[] result = this._PriEncrypt(oText, key);
            return result;
        }

        //公钥解密
        public byte[] _DecryptByPubKey(byte[] enc, RSACryptoServiceProvider key)
        {
            byte[] result = new byte[enc.Length];
            int k = 0;
            int blockLen = MAX_DECRYPT_BLOCK;
            int i = 0;
            do
            {
                //String temp = enc.Substring(i, blockLen);
                int length = (enc.Length - blockLen * i) > blockLen ? blockLen : (enc.Length - blockLen * i);
                byte[] oText = new byte[length];
                Array.Copy(enc, i * blockLen, oText, 0, length);

                //解密
                byte[] dec = _PubDecrypt(oText, key);

                //去除填充
                dec = _Remove_PKCS1_padding(dec);
                Array.Copy(dec, 0, result, k, dec.Length);
                k += dec.Length;

                i++;
            } while (i * blockLen < enc.Length);

            byte[] data = new byte[k];
            Array.Copy(result, 0, data, 0, k);
            return data;
        }

        //公钥解密
        private byte[] _PubDecrypt(byte[] block, RSACryptoServiceProvider key)
        {
            RSAParameters param = key.ExportParameters(false);
            BigInteger e = new BigInteger(param.Exponent);
            BigInteger n = new BigInteger(param.Modulus);
            BigInteger biText = new BigInteger(block);
            BigInteger biEnText = biText.modPow(e, n);
            return biEnText.getBytes();
        }

        //去除填充
        private byte[] _Remove_PKCS1_padding(byte[] oText)
        {
            int i = 2;
            byte b = (byte)(oText[i] & 0xff);
            while (b != 0)
            {
                i++;
                b = (byte)(oText[i] & 0xff);
            }
            i++;

            byte[] result = new byte[oText.Length - i];
            int j = 0;
            while (i < oText.Length)
            {
                result[j++] = oText[i++];
            }
            return result;
        }

        #endregion 自行实现的RSA PKCS1填充方式的算法
    }
}