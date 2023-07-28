using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptoN.Test;

[TestClass]
public class CryptoMonkeyTest {
    [TestMethod]
    public void TestEncryptString() {
        var key = CryptoMonkey.GenerateRandomKey(AllowedKeySizes.KL_192);
        var iv = CryptoMonkey.GenerateRandomIv(AllowedBlockSizes.BL_128);

        var monkey = new CryptoMonkey(key, iv);

        var testString = "Hello World";

        var encryptedBase64String = monkey.EncryptString(testString);

        var decryptedString = monkey.DecryptString(encryptedBase64String);

        Assert.AreEqual(testString, decryptedString);
    }
}