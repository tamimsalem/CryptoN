using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoN
{
    public static class GeneralExtensions
    {
        public static string ToBase64String(this byte[] data)
        {
            if (null == data || data.Length == 0)
            {
                throw new ArgumentNullException(nameof(data));
            }

            return Convert.ToBase64String(data);
        }

        public static byte[] FromBase64String(this string base64String)
        {
            return Convert.FromBase64String(base64String);
        }

        public static string ToHexString(this byte[] data)
        {
            if (null == data || data.Length == 0)
            {
                throw new ArgumentNullException(nameof(data));
            }

            string hex = BitConverter.ToString(data);

            return hex.Replace("-", "");
        }

        public static byte[] FromHexString(this string hexString)
        {
            if (null == hexString || hexString.Length == 0)
            {
                throw new ArgumentNullException(nameof(hexString));
            }

            var numebrOfCharacters = hexString.Length;

            var bytes = new byte[numebrOfCharacters / 2];

            for (int i = 0; i < numebrOfCharacters; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }

            return bytes;
        }
    }
}
