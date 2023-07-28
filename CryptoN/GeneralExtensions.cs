using System;

namespace CryptoN;

public static class GeneralExtensions {
    public static string ToBase64String(this byte[] data) {
        if (null == data || data.Length == 0)
            throw new ArgumentNullException(nameof(data));

        return Convert.ToBase64String(data);
    }

    public static byte[] FromBase64String(this string base64String) =>
        Convert.FromBase64String(base64String);

    public static string ToHexString(this byte[] data) {
        if (null == data || data.Length == 0)
            throw new ArgumentNullException(nameof(data));

        var hex = BitConverter.ToString(data);

        return hex.Replace("-", "");
    }

    public static byte[] FromHexString(this string hexString) {
        if (string.IsNullOrEmpty(hexString))
            throw new ArgumentNullException(nameof(hexString));

        var numberOfCharacters = hexString.Length;

        var bytes = new byte[numberOfCharacters / 2];

        for (var i = 0; i < numberOfCharacters; i += 2)
            bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
        
        return bytes;
    }
}
