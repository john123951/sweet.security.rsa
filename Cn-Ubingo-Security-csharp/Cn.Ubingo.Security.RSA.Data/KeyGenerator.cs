using System.Security.Cryptography;
using Cn.Ubingo.Security.RSA.Core;

namespace Cn.Ubingo.Security.RSA.Data
{
    /// <summary>
    /// 陈服建(fochen,j@ubingo.cn)
    /// 2015-01-23
    /// </summary>
    public class KeyGenerator
    {
        /// <summary>
        /// for java
        /// </summary>
        /// <returns></returns>
        static public KeyPair GenerateKeyPair(KeyFormat format = KeyFormat.XML, int keySize = 1024)
        {
            KeyPair keyPair = new KeyPair(new RSACryptoServiceProvider(keySize), format);

            return keyPair;
        }
    }
}