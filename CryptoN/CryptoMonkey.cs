using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
// ReSharper disable InconsistentNaming
// ReSharper disable MemberCanBePrivate.Global
// ReSharper disable IdentifierTypo
#pragma warning disable SYSLIB0022

namespace CryptoN;

public enum AllowedKeySizes {
    KL_128 = 128,
    KL_192 = 192,
    KL_256 = 256
}

public enum AllowedBlockSizes {
    BL_128 = 128,
    BL_160 = 160,
    BL_192 = 192,
    BL_224 = 224,
    BL_256 = 256
}

public class CryptoMonkey {
    private readonly int _keySize;
    private readonly int _blockSize;
    private readonly PaddingMode _paddingMode;
    private readonly CipherMode _cipherMode;

    private readonly Key _key;
    private readonly IV _iv;

    public CryptoMonkey(Key key, IV iv, PaddingMode paddingMode = PaddingMode.PKCS7, CipherMode cipherMode = CipherMode.CBC) {
        _key = key ?? throw new ArgumentNullException(nameof(key));
        _iv  = iv ?? throw new ArgumentNullException(nameof(iv));

        _keySize = _key.LengthInBits;
        _blockSize = _iv.LengthInBits;
        _paddingMode = paddingMode;
        _cipherMode = cipherMode;
    }

    private RijndaelManaged GetAlgorithmObject() {
        var algorithm = new RijndaelManaged() {
            KeySize = _keySize,
            BlockSize = _blockSize,
            Padding = _paddingMode,
            Mode = _cipherMode
        };

        return algorithm;
    }

    public static IV GenerateRandomIv(AllowedBlockSizes blockSize) {
        byte[] ivBytes = new byte[(int)blockSize / 8];

        using (var rijndael = new RijndaelManaged())
        {
            rijndael.BlockSize = (int)blockSize;

            rijndael.GenerateIV();

            rijndael.IV.CopyTo(ivBytes, 0);
        }

        return new IV(ivBytes);
    }

    public static Key GenerateRandomKey(AllowedKeySizes keySize) {
        var keyBytes = new byte[(int)keySize / 8];

        using (var rijndael = new RijndaelManaged())
        {
            rijndael.KeySize = (int)keySize;

            rijndael.GenerateKey();

            rijndael.Key.CopyTo(keyBytes, 0);
        }

        return new Key(keyBytes);
    }

    public string EncryptString(string value) {
        if (null == value)
            throw new ArgumentNullException(nameof(value));

        var bytes = Encoding.UTF8.GetBytes(value);

        var encrypted = Encrypt(bytes);

        return encrypted.ToBase64String();
    }

    public string DecryptString(string base64String) {
        if (null == base64String)
        {
            throw new ArgumentNullException(nameof(base64String));
        }

        var bytes = Convert.FromBase64String(base64String);

        var decrypted = Decrypt(bytes);

        var result = Encoding.UTF8.GetString(decrypted);

        return result;
    }

    public byte[] Encrypt(byte[] data) {
        if (null == data)
            throw new ArgumentNullException(nameof(data));

        var encryptedData = EncryptToBytes(data);

        return encryptedData;
    }

    public byte[] Decrypt(byte[] data) {
        if (null == data)
            throw new ArgumentNullException(nameof(data));

        var encryptedData = DecryptFromBytes(data);

        return encryptedData;
    }

    public void EncryptFile(string plainFilePath, string encryptedOutputPath) {
        EncryptStream(
                  plain: File.Open(plainFilePath, FileMode.Open),
                  encrypted: File.Open(encryptedOutputPath, FileMode.Create),
                  disposeWhenDone: true
                );
    }

    public void DecryptFile(string encryptedFilePath, string plainOutputPath) {
        DecryptStream(
                  encrypted: File.Open(encryptedFilePath, FileMode.Open),
                  plain: File.Open(plainOutputPath, FileMode.Create),
                  disposeWhenDone: true
              );
    }

    public void EncryptStream(Stream plain, Stream encrypted, bool disposeWhenDone) {
        using var encryptedData = GetEncryptingStream(encrypted);
        plain.CopyTo(encryptedData);

        encryptedData.FlushFinalBlock();

        if (!disposeWhenDone) return;
        encrypted.Flush();
        encrypted.Dispose();

        plain.Flush();
        plain.Dispose();
    }

    public void DecryptStream(Stream encrypted, Stream plain, bool disposeWhenDone) {
        using var encryptedData = GetDecryptionStream(encrypted);
        encryptedData.CopyTo(plain);

        if (!disposeWhenDone) return;
        encrypted.Flush();
        encrypted.Dispose();

        plain.Flush();
        plain.Dispose();
    }

    private byte[] EncryptToBytes(byte[] data) {
        using var memStream = new MemoryStream();
        using var csEncrypt = GetEncryptingStream(memStream);
        csEncrypt.Write(data, 0, data.Length);
        csEncrypt.FlushFinalBlock();

        memStream.Position = 0;
        var encrypted = memStream.ToArray();

        return encrypted;
    }

    private byte[] DecryptFromBytes(byte[] encryptedData) {
        using var memStream = new MemoryStream(encryptedData);
        using var csDecrypt = GetDecryptionStream(memStream);
        using var output    = new MemoryStream();
        var       buffer    = new byte[1024];

        var read = csDecrypt.Read(buffer, 0, buffer.Length);

        while (read > 0) {
            output.Write(buffer, 0, read);

            read = csDecrypt.Read(buffer, 0, buffer.Length);
        }

        csDecrypt.Flush();

        var decrypted = output.ToArray();

        return decrypted;
    }

    private CryptoStream GetEncryptingStream(Stream data) {
        using var rijndael = GetAlgorithmObject();
        rijndael.Key = _key.GetBytes();
        rijndael.IV  = _iv.GetBytes();
            
        var encryptor = rijndael.CreateEncryptor(rijndael.Key, rijndael.IV);

        var csEncrypt = new CryptoStream(data, encryptor, CryptoStreamMode.Write);

        return csEncrypt;
    }

    private CryptoStream GetDecryptionStream(Stream data) {
        using var rijndael = GetAlgorithmObject();
        rijndael.KeySize = _keySize;

        rijndael.Key = _key.GetBytes();
        rijndael.IV  = _iv.GetBytes();

        var decryptor = rijndael.CreateDecryptor(rijndael.Key, rijndael.IV);

        var csDecrypt = new CryptoStream(data, decryptor, CryptoStreamMode.Read);

        return csDecrypt;
    }
}

