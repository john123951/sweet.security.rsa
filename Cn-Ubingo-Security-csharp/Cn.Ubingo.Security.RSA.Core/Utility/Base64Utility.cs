using System;
using System.Text;

namespace Cn.Ubingo.Security.RSA.Core.Utility
{
    /// <summary>
    /// 实现Base64编码解码
    /// </summary>
    public static class Base64Utility
    {
        /// <summary>
        /// Base64编码
        /// </summary>
        /// <param name="source">待编码的明文</param>
        /// <param name="encoding">编码采用的编码方式</param>
        /// <returns></returns>
        public static string EncodeBase64(string source, Encoding encoding)
        {
            byte[] bytes = encoding.GetBytes(source);
            return EncodeBase64(bytes);
        }

        /// <summary>
        /// Base64编码，采用utf8编码方式编码
        /// </summary>
        /// <param name="source">待编码的明文</param>
        /// <returns>编码后的字符串</returns>
        public static string EncodeBase64(string source)
        {
            return EncodeBase64(source, Encoding.UTF8);
        }

        /// <summary>
        /// Base64编码
        /// </summary>
        /// <param name="encoding"></param>
        /// <param name="source"></param>
        /// <returns></returns>
        public static byte[] EncodeBase64_byte(string source, Encoding encoding)
        {
            int modeX = source.Length % 4;
            if (modeX != 0)
            {
                for (int i = 0; i < 4 - modeX; i++)
                {
                    source = source + "=";
                }
            }

            byte[] bytes = encoding.GetBytes(source);

            return bytes;
        }

        /// <summary>
        /// Base64编码
        /// </summary>
        /// <param name="source"></param>
        /// <returns></returns>
        public static byte[] EncodeBase64_byte(string source)
        {
            return EncodeBase64_byte(source, Encoding.UTF8);
        }

        /// <summary>
        /// Base64解码
        /// </summary>
        /// <param name="encoding">解码采用的编码方式，注意和编码时采用的方式一致</param>
        /// <param name="result">待解码的密文</param>
        /// <returns>解码后的字符串</returns>
        public static string DecodeBase64(string result, Encoding encoding)
        {
            string decode;
            byte[] bytes = Convert.FromBase64String(result);

            try
            {
                decode = encoding.GetString(bytes);
            }
            catch
            {
                decode = result;
            }
            return decode;
        }

        /// <summary>
        /// Base64解码，采用utf8编码方式解码
        /// </summary>
        /// <param name="result">待解码的密文</param>
        /// <returns>解码后的字符串</returns>
        public static string DecodeBase64(string result)
        {
            int modeX = result.Length % 4;
            if (modeX != 0)
            {
                for (int i = 0; i < 4 - modeX; i++)
                {
                    result = result + "=";
                }
            }
            return DecodeBase64(result, Encoding.UTF8);
        }

        /// <summary>
        /// Base64解码 ///
        /// </summary>
        /// <param name="result"></param>
        /// <returns></returns>
        public static byte[] DecodeBase64_byte(string result)
        {
            int modeX = result.Length % 4;
            if (modeX != 0)
            {
                for (int i = 0; i < 4 - modeX; i++)
                {
                    result = result + "=";
                }
            }
            byte[] bytes = Convert.FromBase64String(result);
            return bytes;
        }

        /// <summary>
        /// Base64编码，采用utf8编码方式编码
        /// </summary>
        /// <param name="bytes">待编码的明文</param>
        /// <returns>编码后的字符串</returns>
        private static string EncodeBase64(byte[] bytes)
        {
            return Convert.ToBase64String(bytes);
        }
    }
}