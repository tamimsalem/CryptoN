using System;
using System.Diagnostics.CodeAnalysis;
// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable MemberCanBeMadeStatic.Local

namespace CryptoN;

public class Key {
    
    private byte[] _underlyingBytes;

    public int LengthInBits => _underlyingBytes.Length * 8;

    public Key(byte[] keyAsBytes) {
        if (null == keyAsBytes || keyAsBytes.Length == 0)
            throw new ArgumentNullException(nameof(keyAsBytes));

        var validKey = Validate(keyAsBytes);

        if (!validKey)
            throw new ArgumentException("Key should only be 128, 192 or 256 bits long", nameof(keyAsBytes));

        _underlyingBytes = keyAsBytes;
    }

    [SuppressMessage("Performance", "CA1822:Mark members as static")]
    private bool Validate(byte[] keyAsBytes) {
        var ivBitLength = keyAsBytes.Length * 8;

        var valid = ivBitLength is 128 or 192 or 256;

        return valid;
    }

    public byte[] GetBytes() => _underlyingBytes;

    public override string ToString() => _underlyingBytes.ToHexString();
}