using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoN
{
    public class Key
    {
        private byte[] _underlyingBytes;

        public int LengthInBits
        {
            get
            {
                return _underlyingBytes.Length * 8;
            }
        }

        public Key(byte[] keyAsBytes)
        {
            if (null == keyAsBytes || keyAsBytes.Length == 0)
            {
                throw new ArgumentNullException(nameof(keyAsBytes));
            }

            var validKey = Validate(keyAsBytes);

            if (!validKey)
            {
                throw new ArgumentException("Key should only be 128, 192 or 256 bits long", nameof(keyAsBytes));
            }

            _underlyingBytes = keyAsBytes;
        }

        private bool Validate(byte[] keyAsBytes)
        {
            var ivBitLength = keyAsBytes.Length * 8;

            var valid = ivBitLength == 128 || ivBitLength == 192 || ivBitLength == 256;

            return valid;
        }

        public byte[] GetBytes()
        {
            return _underlyingBytes;
        }

        public override string ToString()
        {
            return _underlyingBytes.ToHexString();
        }
    }
}
