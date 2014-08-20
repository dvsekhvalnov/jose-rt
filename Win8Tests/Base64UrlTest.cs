using JoseRT.Serialization;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Win8Tests
{
    [TestClass]
    public class Base64UrlTest
    {
        [TestMethod]
        public void Encode()
        {
            //when
            var test = Base64Url.Encode(new byte[] { 72, 101, 108, 108, 111, 32, 66, 97, 115, 101, 54, 52, 85, 114, 108, 32, 101, 110, 99, 111, 100, 105, 110, 103, 33 });

            //then
            Assert.AreEqual(test, "SGVsbG8gQmFzZTY0VXJsIGVuY29kaW5nIQ");
        }

        [TestMethod]
        public void Decode()
        {
            //when
            var test = Base64Url.Decode("SGVsbG8gQmFzZTY0VXJsIGVuY29kaW5nIQ");

            //then
            CollectionAssert.AreEqual(test, new byte[] { 72, 101, 108, 108, 111, 32, 66, 97, 115, 101, 54, 52, 85, 114, 108, 32, 101, 110, 99, 111, 100, 105, 110, 103, 33 });
        }

 
    }
}