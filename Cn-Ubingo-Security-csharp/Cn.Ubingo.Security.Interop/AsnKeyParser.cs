using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Cn.Ubingo.Security.Interop
{
    /// <remarks>
    /// Jeffrey Walton
    /// http://www.codeproject.com/Articles/25487/Cryptographic-Interoperability-Keys
    /// </remarks>
    public class AsnKeyParser
    {
        private readonly AsnParser _parser;

        /// <summary>
        /// 修改入参
        /// 陈服建(j@ubingo.cn)
        /// </summary>
        /// <param name="key">base64编码的密钥文本</param>
        public AsnKeyParser(String key)
        {
            _parser = new AsnParser(Convert.FromBase64String(key));
        }

        internal static byte[] TrimLeadingZero(byte[] values)
        {
            byte[] r = null;
            if ((0x00 == values[0]) && (values.Length > 1))
            {
                r = new byte[values.Length - 1];
                Array.Copy(values, 1, r, 0, values.Length - 1);
            }
            else
            {
                r = new byte[values.Length];
                Array.Copy(values, r, values.Length);
            }

            return r;
        }

        internal static bool EqualOid(byte[] first, byte[] second)
        {
            if (first.Length != second.Length)
            { return false; }

            for (int i = 0; i < first.Length; i++)
            {
                if (first[i] != second[i])
                { return false; }
            }

            return true;
        }

        public RSAParameters ParseRSAPublicKey()
        {
            RSAParameters parameters = new RSAParameters();

            // Current value
            byte[] value = null;

            // Sanity Check
            int length = 0;

            // Checkpoint
            int position = _parser.CurrentPosition();

            // Ignore Sequence - PublicKeyInfo
            length = _parser.NextSequence();
            if (length != _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect Sequence Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture),
                  _parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = _parser.CurrentPosition();

            // Ignore Sequence - AlgorithmIdentifier
            length = _parser.NextSequence();
            if (length > _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect AlgorithmIdentifier Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture),
                  _parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = _parser.CurrentPosition();
            // Grab the OID
            value = _parser.NextOID();
            byte[] oid = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
            if (!EqualOid(value, oid))
            { throw new BerDecodeException("Expected OID 1.2.840.113549.1.1.1", position); }

            // Optional Parameters
            if (_parser.IsNextNull())
            {
                _parser.NextNull();
                // Also OK: value = parser.Next();
            }
            else
            {
                // Gracefully skip the optional data
                value = _parser.Next();
            }

            // Checkpoint
            position = _parser.CurrentPosition();

            // Ignore BitString - PublicKey
            length = _parser.NextBitString();
            if (length > _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect PublicKey Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture),
                  (_parser.RemainingBytes()).ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = _parser.CurrentPosition();

            // Ignore Sequence - RSAPublicKey
            length = _parser.NextSequence();
            if (length < _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect RSAPublicKey Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture),
                  _parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            parameters.Modulus = TrimLeadingZero(_parser.NextInteger());
            parameters.Exponent = TrimLeadingZero(_parser.NextInteger());

            Debug.Assert(0 == _parser.RemainingBytes());

            return parameters;
        }

        public RSAParameters ParseRSAPrivateKey()
        {
            RSAParameters parameters = new RSAParameters();

            // Current value
            byte[] value = null;

            // Checkpoint
            int position = _parser.CurrentPosition();

            // Sanity Check
            int length = 0;

            // Ignore Sequence - PrivateKeyInfo
            length = _parser.NextSequence();
            if (length != _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect Sequence Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture), _parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = _parser.CurrentPosition();
            // Version
            value = _parser.NextInteger();
            if (0x00 != value[0])
            {
                StringBuilder sb = new StringBuilder("Incorrect PrivateKeyInfo Version. ");
                BigInteger v = new BigInteger(value);
                sb.AppendFormat("Expected: 0, Specified: {0}", v.ToString(10));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = _parser.CurrentPosition();

            // Ignore Sequence - AlgorithmIdentifier
            length = _parser.NextSequence();
            if (length > _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect AlgorithmIdentifier Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture),
                  _parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = _parser.CurrentPosition();

            // Grab the OID
            value = _parser.NextOID();
            byte[] oid = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
            if (!EqualOid(value, oid))
            { throw new BerDecodeException("Expected OID 1.2.840.113549.1.1.1", position); }

            // Optional Parameters
            if (_parser.IsNextNull())
            {
                _parser.NextNull();
                // Also OK: value = parser.Next();
            }
            else
            {
                // Gracefully skip the optional data
                value = _parser.Next();
            }

            // Checkpoint
            position = _parser.CurrentPosition();

            // Ignore OctetString - PrivateKey
            length = _parser.NextOctetString();
            if (length > _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect PrivateKey Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture),
                  _parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = _parser.CurrentPosition();

            // Ignore Sequence - RSAPrivateKey
            length = _parser.NextSequence();
            if (length < _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect RSAPrivateKey Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture),
                  _parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = _parser.CurrentPosition();
            // Version
            value = _parser.NextInteger();
            if (0x00 != value[0])
            {
                StringBuilder sb = new StringBuilder("Incorrect RSAPrivateKey Version. ");
                BigInteger v = new BigInteger(value);
                sb.AppendFormat("Expected: 0, Specified: {0}", v.ToString(10));
                throw new BerDecodeException(sb.ToString(), position);
            }

            parameters.Modulus = TrimLeadingZero(_parser.NextInteger());
            parameters.Exponent = TrimLeadingZero(_parser.NextInteger());
            parameters.D = TrimLeadingZero(_parser.NextInteger());
            parameters.P = TrimLeadingZero(_parser.NextInteger());
            parameters.Q = TrimLeadingZero(_parser.NextInteger());
            parameters.DP = TrimLeadingZero(_parser.NextInteger());
            parameters.DQ = TrimLeadingZero(_parser.NextInteger());
            parameters.InverseQ = TrimLeadingZero(_parser.NextInteger());

            Debug.Assert(0 == _parser.RemainingBytes());

            return parameters;
        }

        internal DSAParameters ParseDSAPublicKey()
        {
            DSAParameters parameters = new DSAParameters();

            // Current value
            byte[] value = null;

            // Current Position
            int position = _parser.CurrentPosition();
            // Sanity Checks
            int length = 0;

            // Ignore Sequence - PublicKeyInfo
            length = _parser.NextSequence();
            if (length != _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect Sequence Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture), _parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = _parser.CurrentPosition();

            // Ignore Sequence - AlgorithmIdentifier
            length = _parser.NextSequence();
            if (length > _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect AlgorithmIdentifier Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture), _parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = _parser.CurrentPosition();

            // Grab the OID
            value = _parser.NextOID();
            byte[] oid = { 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01 };
            if (!EqualOid(value, oid))
            { throw new BerDecodeException("Expected OID 1.2.840.10040.4.1", position); }

            // Checkpoint
            position = _parser.CurrentPosition();

            // Ignore Sequence - DSS-Params
            length = _parser.NextSequence();
            if (length > _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect DSS-Params Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture), _parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Next three are curve parameters
            parameters.P = TrimLeadingZero(_parser.NextInteger());
            parameters.Q = TrimLeadingZero(_parser.NextInteger());
            parameters.G = TrimLeadingZero(_parser.NextInteger());

            // Ignore BitString - PrivateKey
            _parser.NextBitString();

            // Public Key
            parameters.Y = TrimLeadingZero(_parser.NextInteger());

            Debug.Assert(0 == _parser.RemainingBytes());

            return parameters;
        }

        internal DSAParameters ParseDSAPrivateKey()
        {
            DSAParameters parameters = new DSAParameters();

            // Current value
            byte[] value = null;

            // Current Position
            int position = _parser.CurrentPosition();
            // Sanity Checks
            int length = 0;

            // Ignore Sequence - PrivateKeyInfo
            length = _parser.NextSequence();
            if (length != _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect Sequence Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture), _parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = _parser.CurrentPosition();
            // Version
            value = _parser.NextInteger();
            if (0x00 != value[0])
            {
                throw new BerDecodeException("Incorrect PrivateKeyInfo Version", position);
            }

            // Checkpoint
            position = _parser.CurrentPosition();

            // Ignore Sequence - AlgorithmIdentifier
            length = _parser.NextSequence();
            if (length > _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect AlgorithmIdentifier Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture), _parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Checkpoint
            position = _parser.CurrentPosition();
            // Grab the OID
            value = _parser.NextOID();
            byte[] oid = { 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01 };
            if (!EqualOid(value, oid))
            { throw new BerDecodeException("Expected OID 1.2.840.10040.4.1", position); }

            // Checkpoint
            position = _parser.CurrentPosition();

            // Ignore Sequence - DSS-Params
            length = _parser.NextSequence();
            if (length > _parser.RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect DSS-Params Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  length.ToString(CultureInfo.InvariantCulture), _parser.RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            // Next three are curve parameters
            parameters.P = TrimLeadingZero(_parser.NextInteger());
            parameters.Q = TrimLeadingZero(_parser.NextInteger());
            parameters.G = TrimLeadingZero(_parser.NextInteger());

            // Ignore OctetString - PrivateKey
            _parser.NextOctetString();

            // Private Key
            parameters.X = TrimLeadingZero(_parser.NextInteger());

            Debug.Assert(0 == _parser.RemainingBytes());

            return parameters;
        }
    }

    internal class AsnParser
    {
        private readonly List<byte> _octets;
        private readonly int _initialCount;

        internal AsnParser(byte[] values)
        {
            _octets = new List<byte>(values.Length);
            _octets.AddRange(values);

            _initialCount = _octets.Count;
        }

        internal int CurrentPosition()
        {
            return _initialCount - _octets.Count;
        }

        internal int RemainingBytes()
        {
            return _octets.Count;
        }

        private int GetLength()
        {
            int length = 0;

            // Checkpoint
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();

                if (b == (b & 0x7f)) { return b; }
                int i = b & 0x7f;

                if (i > 4)
                {
                    StringBuilder sb = new StringBuilder("Invalid Length Encoding. ");
                    sb.AppendFormat("Length uses {0} octets",
                      i.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                while (0 != i--)
                {
                    // shift left
                    length <<= 8;

                    length |= GetNextOctet();
                }
            }
            catch (ArgumentOutOfRangeException ex)
            { throw new BerDecodeException("Error Parsing Key", position, ex); }

            return length;
        }

        internal byte[] Next()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();

                int length = GetLength();
                if (length > RemainingBytes())
                {
                    StringBuilder sb = new StringBuilder("Incorrect Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                      length.ToString(CultureInfo.InvariantCulture),
                      RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                return GetOctets(length);
            }
            catch (ArgumentOutOfRangeException ex)
            { throw new BerDecodeException("Error Parsing Key", position, ex); }
        }

        internal byte GetNextOctet()
        {
            int position = CurrentPosition();

            if (0 == RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  1.ToString(CultureInfo.InvariantCulture),
                  RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            byte b = GetOctets(1)[0];

            return b;
        }

        internal byte[] GetOctets(int octetCount)
        {
            int position = CurrentPosition();

            if (octetCount > RemainingBytes())
            {
                StringBuilder sb = new StringBuilder("Incorrect Size. ");
                sb.AppendFormat("Specified: {0}, Remaining: {1}",
                  octetCount.ToString(CultureInfo.InvariantCulture),
                  RemainingBytes().ToString(CultureInfo.InvariantCulture));
                throw new BerDecodeException(sb.ToString(), position);
            }

            byte[] values = new byte[octetCount];

            try
            {
                _octets.CopyTo(0, values, 0, octetCount);
                _octets.RemoveRange(0, octetCount);
            }
            catch (ArgumentOutOfRangeException ex)
            { throw new BerDecodeException("Error Parsing Key", position, ex); }

            return values;
        }

        internal bool IsNextNull()
        {
            return 0x05 == _octets[0];
        }

        internal int NextNull()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();
                if (0x05 != b)
                {
                    StringBuilder sb = new StringBuilder("Expected Null. ");
                    sb.AppendFormat("Specified Identifier: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                // Next octet must be 0
                b = GetNextOctet();
                if (0x00 != b)
                {
                    StringBuilder sb = new StringBuilder("Null has non-zero size. ");
                    sb.AppendFormat("Size: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                return 0;
            }
            catch (ArgumentOutOfRangeException ex)
            { throw new BerDecodeException("Error Parsing Key", position, ex); }
        }

        internal bool IsNextSequence()
        {
            return 0x30 == _octets[0];
        }

        internal int NextSequence()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();
                if (0x30 != b)
                {
                    StringBuilder sb = new StringBuilder("Expected Sequence. ");
                    sb.AppendFormat("Specified Identifier: {0}",
                      b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                int length = GetLength();
                if (length > RemainingBytes())
                {
                    StringBuilder sb = new StringBuilder("Incorrect Sequence Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                      length.ToString(CultureInfo.InvariantCulture),
                      RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                return length;
            }
            catch (ArgumentOutOfRangeException ex)
            { throw new BerDecodeException("Error Parsing Key", position, ex); }
        }

        internal bool IsNextOctetString()
        {
            return 0x04 == _octets[0];
        }

        internal int NextOctetString()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();
                if (0x04 != b)
                {
                    StringBuilder sb = new StringBuilder("Expected Octet String. ");
                    sb.AppendFormat("Specified Identifier: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                int length = GetLength();
                if (length > RemainingBytes())
                {
                    StringBuilder sb = new StringBuilder("Incorrect Octet String Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                      length.ToString(CultureInfo.InvariantCulture),
                      RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                return length;
            }
            catch (ArgumentOutOfRangeException ex)
            { throw new BerDecodeException("Error Parsing Key", position, ex); }
        }

        internal bool IsNextBitString()
        {
            return 0x03 == _octets[0];
        }

        internal int NextBitString()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();
                if (0x03 != b)
                {
                    StringBuilder sb = new StringBuilder("Expected Bit String. ");
                    sb.AppendFormat("Specified Identifier: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                int length = GetLength();

                // We need to consume unused bits, which is the first
                //   octet of the remaing values
                b = _octets[0];
                _octets.RemoveAt(0);
                length--;

                if (0x00 != b)
                { throw new BerDecodeException("The first octet of BitString must be 0", position); }

                return length;
            }
            catch (ArgumentOutOfRangeException ex)
            { throw new BerDecodeException("Error Parsing Key", position, ex); }
        }

        internal bool IsNextInteger()
        {
            return 0x02 == _octets[0];
        }

        internal byte[] NextInteger()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();
                if (0x02 != b)
                {
                    StringBuilder sb = new StringBuilder("Expected Integer. ");
                    sb.AppendFormat("Specified Identifier: {0}", b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                int length = GetLength();
                if (length > RemainingBytes())
                {
                    StringBuilder sb = new StringBuilder("Incorrect Integer Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                      length.ToString(CultureInfo.InvariantCulture),
                      RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                return GetOctets(length);
            }
            catch (ArgumentOutOfRangeException ex)
            { throw new BerDecodeException("Error Parsing Key", position, ex); }
        }

        internal byte[] NextOID()
        {
            int position = CurrentPosition();

            try
            {
                byte b = GetNextOctet();
                if (0x06 != b)
                {
                    StringBuilder sb = new StringBuilder("Expected Object Identifier. ");
                    sb.AppendFormat("Specified Identifier: {0}",
                      b.ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                int length = GetLength();
                if (length > RemainingBytes())
                {
                    StringBuilder sb = new StringBuilder("Incorrect Object Identifier Size. ");
                    sb.AppendFormat("Specified: {0}, Remaining: {1}",
                      length.ToString(CultureInfo.InvariantCulture),
                      RemainingBytes().ToString(CultureInfo.InvariantCulture));
                    throw new BerDecodeException(sb.ToString(), position);
                }

                byte[] values = new byte[length];

                for (int i = 0; i < length; i++)
                {
                    values[i] = _octets[0];
                    _octets.RemoveAt(0);
                }

                return values;
            }
            catch (ArgumentOutOfRangeException ex)
            { throw new BerDecodeException("Error Parsing Key", position, ex); }
        }
    }
}