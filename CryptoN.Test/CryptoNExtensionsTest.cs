using System;
using CryptoN;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptoN.Test;

[TestClass]
public class CryptoNExtensionsTest
{
    public CryptoNExtensionsTest() {
        //
        // TODO: Add constructor logic here
        //
    }

    private TestContext testContextInstance;

    /// <summary>
    ///Gets or sets the test context which provides
    ///information about and functionality for the current test run.
    ///</summary>
    public TestContext TestContext {
        get => testContextInstance;
        set => testContextInstance = value;
    }

    #region Additional test attributes
    //
    // You can use the following additional attributes as you write your tests:
    //
    // Use ClassInitialize to run code before running the first test in the class
    // [ClassInitialize()]
    // public static void MyClassInitialize(TestContext testContext) { }
    //
    // Use ClassCleanup to run code after all tests in a class have run
    // [ClassCleanup()]
    // public static void MyClassCleanup() { }
    //
    // Use TestInitialize to run code before running each test 
    // [TestInitialize()]
    // public void MyTestInitialize() { }
    //
    // Use TestCleanup to run code after each test has run
    // [TestCleanup()]
    // public void MyTestCleanup() { }
    //
    #endregion

    [TestMethod]
    public void TestBase64Conversion() {
        var testBytes = new byte[] { 1, 2, 3 };

        var base64 = testBytes.ToBase64String();

        var properBase64 = !string.IsNullOrWhiteSpace(base64);

        Assert.IsTrue(properBase64);
    }


    [TestMethod]
    public void TestHexConversion() {
        var testBytes = new byte[] { 1, 2, 3 };

        var hex = testBytes.ToHexString();

        var properHex = !string.IsNullOrWhiteSpace(hex);

        Assert.IsTrue(properHex);
    }

    [TestMethod]
    public void TestBase64RoundTrip() {
        var testBytes = new byte[] { 1, 2, 3 };

        var base64 = testBytes.ToBase64String();

        var roundTripBytes = base64.FromBase64String();

        var arrayEqual = testBytes.Length == roundTripBytes.Length &&
                            roundTripBytes.Length == 3 &&
                            testBytes[0] == roundTripBytes[0] &&
                            testBytes[1] == roundTripBytes[1] &&
                            testBytes[2] == roundTripBytes[2];

        Assert.IsTrue(arrayEqual);
    }

    [TestMethod]
    public void TestHexRoundTrip() {
        var testBytes = new byte[] { 1, 2, 3 };

        var hex = testBytes.ToHexString();

        var roundTripBytes = hex.FromHexString();

        var arrayEqual = testBytes.Length == roundTripBytes.Length &&
                            roundTripBytes.Length == 3 &&
                            testBytes[0] == roundTripBytes[0] &&
                            testBytes[1] == roundTripBytes[1] &&
                            testBytes[2] == roundTripBytes[2];

        Assert.IsTrue(arrayEqual);
    }
}
