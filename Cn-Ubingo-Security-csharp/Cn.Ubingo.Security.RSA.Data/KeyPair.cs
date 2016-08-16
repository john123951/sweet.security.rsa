using Cn.Ubingo.Security.Interop;
using Cn.Ubingo.Security.RSA.Core;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Cn.Ubingo.Security.RSA.Data
{
    /// <summary>
    /// 陈服建(fochen,j@ubingo.cn)
    /// 2015-01-23
    /// </summary>
    public class KeyPair
    {
        private readonly RSACryptoServiceProvider _rsa;
        private readonly KeyFormat _format;
        private string _private;
        private string _public;

        public KeyFormat Format
        {
            get { return this._format; }
        }

        public bool OnlyPublic
        {
            get { return _rsa != null && _rsa.PublicOnly; }
        }

        public string PrivateKey
        {
            get
            {
                if (this._private == null)
                {
                    switch (this._format)
                    {
                        case KeyFormat.ASN:
                            this._private = this._ToASNPrivateKey();
                            break;

                        case KeyFormat.XML:
                            this._private = this._ToXMLPrivateKey();
                            break;

                        case KeyFormat.PEM:
                            this._private = this._ToPEMPrivateKey();
                            break;

                        default:
                            this._private = this._ToXMLPrivateKey();
                            break;
                    }
                }
                return this._private;
            }
        }

        public string PublicKey
        {
            get
            {
                if (this._public == null)
                {
                    switch (this._format)
                    {
                        case KeyFormat.ASN:
                            this._public = this._ToASNPublicKey();
                            break;

                        case KeyFormat.XML:
                            this._public = this._ToXMLPublicKey();
                            break;

                        case KeyFormat.PEM:
                            this._public = this._ToPEMPublicKey();
                            break;

                        default:
                            this._public = this._ToXMLPublicKey();
                            break;
                    }
                }
                return this._public;
            }
        }

        internal KeyPair()
            : this(new RSACryptoServiceProvider(1024), KeyFormat.XML)
        {
        }

        internal KeyPair(RSACryptoServiceProvider rsa, KeyFormat format)
        {
            this._rsa = rsa;
            this._format = format;
        }

        #region 导入、导出密钥

        /// <summary>
        /// 导入ASN格式的密钥
        /// </summary>
        /// <param name="base64Key"></param>
        /// <returns></returns>
        public static KeyPair ImportASNKey(string base64Key)
        {
            var isPrivate = base64Key.Length > 500;

            var keyParser = new Cn.Ubingo.Security.Interop.AsnKeyParser(base64Key);

            RSAParameters rsaParameters = isPrivate ? keyParser.ParseRSAPrivateKey() : keyParser.ParseRSAPublicKey();

            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);

            return new KeyPair(rsa, KeyFormat.ASN);
        }

        /// <summary>
        /// 导入XML格式的密钥
        /// </summary>
        /// <param name="xmlKey"></param>
        /// <returns></returns>
        public static KeyPair ImportXMLKey(string xmlKey)
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(xmlKey);

            return new KeyPair(rsa, KeyFormat.XML);
        }

        public KeyPair ToASNKeyPair()
        {
            return new KeyPair(this._rsa, KeyFormat.ASN);
        }

        public KeyPair ToXMLKeyPair()
        {
            return new KeyPair(this._rsa, KeyFormat.XML);
        }

        public KeyPair ToPEMKeyPair()
        {
            return new KeyPair(this._rsa, KeyFormat.PEM);
        }

        private string _ToASNPublicKey()
        {
            RSAParameters publicKey = this._rsa.ExportParameters(false);
            AsnKeyBuilder.AsnMessage key = AsnKeyBuilder.PublicKeyToX509(publicKey);

            return Convert.ToBase64String(key.GetBytes());
        }

        private string _ToASNPrivateKey()
        {
            if (_rsa.PublicOnly)
            {
                throw new Exception("not a private key");
            }

            RSAParameters privateKey = this._rsa.ExportParameters(true);
            AsnKeyBuilder.AsnMessage key = AsnKeyBuilder.PrivateKeyToPKCS8(privateKey);

            return Convert.ToBase64String(key.GetBytes());
        }

        private string _ToXMLPublicKey()
        {
            return this._rsa.ToXmlString(false);
        }

        private string _ToXMLPrivateKey()
        {
            return this._rsa.ToXmlString(true);
        }

        private string _ToPEMPublicKey()
        {
            string publicKey = this._ToASNPublicKey();
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("-----BEGIN PUBLIC KEY-----");
            int i = 0;
            while (i + 64 < publicKey.Length)
            {
                sb.AppendLine(publicKey.Substring(i, 64));
                i += 64;
            }
            sb.AppendLine(publicKey.Substring(i, publicKey.Length - i));
            sb.AppendLine("-----END PUBLIC KEY-----");

            return sb.ToString();
        }

        private string _ToPEMPrivateKey()
        {
            string privateKey = this._ToASNPrivateKey();
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("-----BEGIN PRIVATE KEY-----");
            int i = 0;
            while (i + 64 < privateKey.Length)
            {
                sb.AppendLine(privateKey.Substring(i, 64));
                i += 64;
            }
            sb.AppendLine(privateKey.Substring(i, privateKey.Length - i));
            sb.AppendLine("-----END PRIVATE KEY-----");

            return sb.ToString();
        }

        #endregion 导入、导出密钥

        #region 加密、解密

        public KeyWorker GenerateWorker()
        {
            if (OnlyPublic)
            {
                KeyWorker pubWorker = new KeyWorker(this.PublicKey, this._format);

                return pubWorker;
            }
            else
            {
                KeyWorker priWorker = new KeyWorker(this.PrivateKey, this._format);

                return priWorker;
            }
        }

        #endregion 加密、解密
    }
}