using System.Diagnostics;
using System.Runtime.InteropServices;
using JoseRT;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Win8Tests
{
    [TestClass]
    public class CompatibilityTestSuite
    {
        [TestMethod]
        public void DecodePlaintext()
        {
            //given
            string token = "eyJhbGciOiJub25lIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.";

            //when
            var test = JoseRT.Jwt.Decode(token,null);

            Debug.WriteLine("test = {0}", test);

            //then
            Assert.AreEqual(@"{""hello"": ""world""}", test);
        }
        
        [TestMethod]
        public void EncodePlaintext()
        {
            //given
            string payload = @"{""hello"" : ""world""}";

            //when
            var test = JoseRT.Jwt.Encode(payload, JwsAlgorithm.None, null);

            Debug.WriteLine("test = {0}", test);

            //then
            Assert.AreEqual("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJoZWxsbyIgOiAid29ybGQifQ.", test);
        }

        private static byte[] shaKey = { 97, 48, 97, 50, 97, 98, 100, 56, 45, 54, 49, 54, 50, 45, 52, 49, 99, 51, 45, 56, 51, 100, 54, 45, 49, 99, 102,53, 53, 57, 98, 52, 54, 97, 102, 99 };

        [TestMethod]
        public void DecodeHS256()
        {
            //given
            string token =
                "eyJhbGciOiJIUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.chIoYWrQMA8XL5nFz6oLDJyvgHk2KA4BrFGrKymjC8E";

            //when
            var test = JoseRT.Jwt.Decode(token,shaKey);

            //then
            Assert.AreEqual(@"{""hello"": ""world""}", test);
        }

        [TestMethod]
        public void EncodeHS256()
        {
            //given
            string payload = @"{""hello"": ""world""}";

            //when
            var test = JoseRT.Jwt.Encode(payload, JwsAlgorithm.HS256, shaKey);

            Debug.WriteLine("test = {0}", test);

            //then
            Assert.AreEqual("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.KmLWPfxC3JGopWImDgYg9IUpgAi8gwimviUfr6eJyFI", test);
        }

    }
}
