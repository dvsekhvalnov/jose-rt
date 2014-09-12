using System.Diagnostics;
using JoseRT;
using JoseRT.Rsa;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Win8Tests
{
    [TestClass]
    public class CompatibilityTestSuite
    {
        private static readonly byte[] shaKey = { 97, 48, 97, 50, 97, 98, 100, 56, 45, 54, 49, 54, 50, 45, 52, 49, 99, 51, 45, 56, 51, 100, 54, 45, 49, 99, 102, 53, 53, 57, 98, 52, 54, 97, 102, 99 };

        private string privateKey =
@"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqFZv0pea/jn5Mo4qEUmStuhlulso8n1inXbEotd/zTrQp9K0
RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO/0N97dMBz/7fmvyv0hgHaBdQ
5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxG
BlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8
/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu/ve0v7LiLT4G/OxYGzpOQcC
nimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI2QIDAQABAoIBAQCUmHBvSkqUHaK/
IMU7q2FqOi0KWswDefEiJKQhRu9Wv5NOgW2FrfqDIXrDp7pg1dBezgeExHLX9v6d
FAOTwbj9/m6t3+r6k6fm7gp+ao3dfD6VgPd12L2oXQ0t5NVQ1UUBJ4/QUWps9h90
3AP4vK/COG1P+CAw4DDeZi9TlwF/Pr7e492GXcLBAUJODA6538ED2nYw8xQcbzbA
wr+w07UjRNimObtOfA0HCIpsx/6LkIqe6iGChisQNgt4yDd/fZ4GWOUIU1hqgK1P
6avVl7Q5Mk0PTi9t8ui1X4EEq6Uils45J5WkobuAnFkea/uKfs8Tn9bNrEoVWgdb
fBHq/8bNAoGBANKmjpE9e+L0RtxP+u4FN5YDoKE+i96VR7ru8H6yBKMcnD2uf5mV
RueEoL0FKHxlGBBo0dJWr1AIwpcPbTs3Dgx1/EQMZLg57QBZ7QcYETPiMwMvEM3k
Zf3G4YFYwUwIQXMYPt1ckr+RncRcq0GiKPDsvzzyNS+BBSmR5onAXd7bAoGBAMyT
6ggyqmiR/UwBn87em+GjbfX6YqxHHaQBdWwnnRX0JlGTNCxt6zLTgCIYxF4AA7eR
gfGTStwUJfAScjJirOe6Cpm1XDgxEQrT6oxAl17MR/ms/Z88WrT73G+4phVvDpVr
JcK+CCESnRI8xGLOLMkCc+5NpLajqWCOf1H2J8NbAoGAKTWmTGmf092AA1euOmRQ
5IsfIIxQ5qGDn+FgsRh4acSOGE8L7WrTrTU4EOJyciuA0qz+50xIDbs4/j5pWx1B
JVTrnhBin9vNLrVo9mtR6jmFS0ko226kOUpwEVLgtdQjobWLjtiuaMW+/Iw4gKWN
ptxZ6T1lBD8UWHaPiEFW2+MCgYAmfSWoyS96YQ0QwbV5TDRzrTXA84yg8PhIpOWc
pY9OVBLpghJs0XlQpK4UvCglr0cDwGJ8OsP4x+mjUzUc+aeiKURZSt/Ayqp0KQ6V
uIlCEpjwBnXpAYfnSQNeGZVVrwFFZ1VBYFNTNZdLmRcxp6yRXN7G1ODKY9w4CFc3
6mHsxQKBgQCxEA+KAmmXxL++x/XOElOscz3vFHC4HbpHpOb4nywpE9vunnHE2WY4
EEW9aZbF22jx0ESU2XJ1JlqffvfIEvHNb5tmBWn4HZEpPUHdaFNhb9WjkMuFaLzh
cydwnEftq+3G0X3KSxp4p7R7afcnpNNqfneYODgoXxTQ4Q7ZyKo72A==
-----END RSA PRIVATE KEY-----";

        private string publicKey =
@"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqFZv0pea/jn5Mo4qEUmS
tuhlulso8n1inXbEotd/zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1
MmnO/0N97dMBz/7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXob
DPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9Rra
ShsIDzeefOcKibcAaKeeVI3rkAU8/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXI
khvNu/ve0v7LiLT4G/OxYGzpOQcCnimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI
2QIDAQAB
-----END PUBLIC KEY-----";

        [TestMethod]
        public void DecodePlaintext()
        {
            //given
            string token = "eyJhbGciOiJub25lIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.";

            //when
            string test = Jwt.Decode(token, null);

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
            string test = Jwt.Encode(payload, JwsAlgorithm.None, null);

            Debug.WriteLine("test = {0}", test);

            //then
            Assert.AreEqual("eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJoZWxsbyIgOiAid29ybGQifQ.", test);
        }

        [TestMethod]
        public void DecodeHS256()
        {
            //given
            string token = "eyJhbGciOiJIUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.chIoYWrQMA8XL5nFz6oLDJyvgHk2KA4BrFGrKymjC8E";

            //when
            string test = Jwt.Decode(token, shaKey);

            //then
            Assert.AreEqual(@"{""hello"": ""world""}", test);
        }

        [TestMethod]
        public void DecodeHS384()
        {
            //given
            string token = "eyJhbGciOiJIUzM4NCIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.McDgk0h4mRdhPM0yDUtFG_omRUwwqVS2_679Yeivj-a7l6bHs_ahWiKl1KoX_hU_";

            //when
            string test = Jwt.Decode(token, shaKey);

            //then
            Assert.AreEqual(@"{""hello"": ""world""}", test);
        }

        [TestMethod]
        public void DecodeHS512()
        {
            //given
            string token = "eyJhbGciOiJIUzUxMiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.9KirTNe8IRwFCBLjO8BZuXf3U2ZVagdsg7F9ZsvMwG3FuqY9W0vqwjzPOjLqPN-GkjPm6C3qWPnINhpr5bEDJQ";

            //when
            string test = Jwt.Decode(token, shaKey);

            //then
            Assert.AreEqual(@"{""hello"": ""world""}", test);
        }

        [TestMethod]
        public void EncodeHS256()
        {
            //given
            string payload = @"{""hello"": ""world""}";

            //when
            string test = Jwt.Encode(payload, JwsAlgorithm.HS256, shaKey);

            Debug.WriteLine("HS256 = {0}", test);

            //then
            Assert.AreEqual("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.KmLWPfxC3JGopWImDgYg9IUpgAi8gwimviUfr6eJyFI", test);
        }

        [TestMethod]
        public void EncodeHS384()
        {
            //given
            string payload = @"{""hello"": ""world""}";

            //when
            string test = Jwt.Encode(payload, JwsAlgorithm.HS384, shaKey);

            Debug.WriteLine("HS384 = {0}", test);

            //then
            Assert.AreEqual("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.Be1KYCRGFbv0uQwelaRj0a5SYDdbk_sYsXkfrbRI6TmYpuWBga_RsiU2TyyyjoXR",test);
        }

        [TestMethod]
        public void EncodeHS512()
        {
            //given
            string payload = @"{""hello"": ""world""}";

            //when
            string test = Jwt.Encode(payload, JwsAlgorithm.HS512, shaKey);

            Debug.WriteLine("HS512 = {0}", test);

            //then
            Assert.AreEqual("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9._1m5AmI1xbSfVpykAm9PMXYuQLIdqWuRN8Lz6hFMDq0beqLAaH4Dh2VQNlXzoBG7Nk4vHx2gZgVuhF62cnXcKQ",test);
        }

        [TestMethod]
        public void DecodeRS256()
        {
            //given
            string token = "eyJhbGciOiJSUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.NL_dfVpZkhNn4bZpCyMq5TmnXbT4yiyecuB6Kax_lV8Yq2dG8wLfea-T4UKnrjLOwxlbwLwuKzffWcnWv3LVAWfeBxhGTa0c4_0TX_wzLnsgLuU6s9M2GBkAIuSMHY6UTFumJlEeRBeiqZNrlqvmAzQ9ppJHfWWkW4stcgLCLMAZbTqvRSppC1SMxnvPXnZSWn_Fk_q3oGKWw6Nf0-j-aOhK0S0Lcr0PV69ZE4xBYM9PUS1MpMe2zF5J3Tqlc1VBcJ94fjDj1F7y8twmMT3H1PI9RozO-21R0SiXZ_a93fxhE_l_dj5drgOek7jUN9uBDjkXUwJPAyp9YPehrjyLdw";

            //when
            string test = Jwt.Decode(token, PublicKey.Load(publicKey));

            Debug.WriteLine("json = {0}", test);

            //then
            Assert.AreEqual(test, @"{""hello"": ""world""}");
        }

        [TestMethod]
        public void DecodeRS384()
        {
            //given
            string token = "eyJhbGciOiJSUzM4NCIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.cOPca7YEOxnXVdIi7cJqfgRMmDFPCrZG1M7WCJ23U57rAWvCTaQgEFdLjs7aeRAPY5Su_MVWV7YixcawKKYOGVG9eMmjdGiKHVoRcfjwVywGIb-nuD1IBzGesrQe7mFQrcWKtYD9FurjCY1WuI2FzGPp5YhW5Zf4TwmBvOKz6j2D1vOFfGsogzAyH4lqaMpkHpUAXddQxzu8rmFhZ54Rg4T-jMGVlsdrlAAlGA-fdRZ-V3F2PJjHQYUcyS6n1ULcy6ljEOgT5fY-_8DDLLpI8jAIdIhcHUAynuwvvnDr9bJ4xIy4olFRqcUQIHbcb5-WDeWul_cSGzTJdxDZsnDuvg";

            //when
            string test = Jwt.Decode(token, PublicKey.Load(publicKey));

            Debug.WriteLine("json = {0}", test);

            //then
            Assert.AreEqual(test, @"{""hello"": ""world""}");
        }

        [TestMethod]
        public void DecodeRS512()
        {
            //given
            string token = "eyJhbGciOiJSUzUxMiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.KP_mwCVRIxcF6ErdrzNcXZQDFGcL-Hlyocc4tIl3tJfzSfc7rz7qOLPjHpZ6UFH1ncd5TlpRc1B_pgvY-l0BNtx_s7n_QA55X4c1oeD8csrIoXQ6A6mtvdVGoSlGu2JnP6N2aqlDmlcefKqjl_Z-8nwDMGTMkDNhHKfHlIb2_Dliwxeq8LmNMREEdvNH2XVp_ffxBjiaKv2Eqbwc6I17241GCEmjDCvnagSgjX_5uu-da2H7TK2gtPJYUo8r9nzC7uzZJ5SB8suZH0COSofsP-9wvH0FESO40evCyEBylqg3bh9M9dIzeq8_bdTiC5kG93Fal44OEY8_Zm88wB_VjQ";

            //when
            string test = Jwt.Decode(token, PublicKey.Load(publicKey));

            Debug.WriteLine("json = {0}", test);

            //then
            Assert.AreEqual(test, @"{""hello"": ""world""}");
        }

        [TestMethod]
        public void EncodeRS256()
        {
            //given
            string json = @"{""hello"": ""world""}";

            //when
            string test = Jwt.Encode(json, JwsAlgorithm.RS256, PrivateKey.Load(privateKey));

            //then
            Debug.WriteLine("RS256 = {0}", test);

            Assert.AreEqual(test,"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.M3uJ9g4_e_lCyd0LtSJuSPMHe_s0Bj6LDA2kqf041SA3Les8aUmRQGlkG3ng63Thw6q06hF6r5bXX8tamku8AOyc45TIfPY9caNKKcVJ6RtXBxRWSY3r3Uh9o5zg3EOElfMWuekz0jfVfOaRgMO358ARsKW5BY6jfgmKsVyG1n3uYm8ESpzPlWWLcgUEjUSq3_m5t-COKySXa_zPPtFnA__159kSKCQRm4OcbYWzJD3-xl2i2GRQFLP7npLAuGPv42t5zf8snJvBWbROsdvvs7qzZ5v6bJy8wuBe9mGXmnbRsMFCzooZQ4H8LFrSnT3DakPVdLcDWE5HxZ-Ikr9l0A");
            Assert.AreEqual(Jwt.Decode(test, PublicKey.Load(publicKey)), json);
        }

        [TestMethod]
        public void EncodeRS384()
        {
            //given
            string json = @"{""hello"": ""world""}";

            //when
            string test = Jwt.Encode(json, JwsAlgorithm.RS384, PrivateKey.Load(privateKey));

            //then
            Debug.WriteLine("RS384 = {0}", test);

            Assert.AreEqual(test, "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.Tsq02ZIAOOK8ck0NS7VJ2NOmL6VpATGTb5hVUQC9_DJqiyrp2Vs8KGw9ahRjvIQMElkcFuWRPg-MGgHd7XUPVbhm7jK3cBvQ4y9hal6VNFfsL_DWhijLYgFpBj2nEw_qqZbChrPNRn-B1BrMKuRHOqu-7D3PPPMv9hvSg80WOLlkOUgIhp3a64saPJ8rDEibowdNNXw0k0H2i1D6WLK59Ew-6v6qO8OI9bkVc7SDV9qZSx3n0hm_JfyZbkCb-KKacJnkfVcnlNIRXRbk7cdlp90uYJ1aJDZrcIVTUOOAHQCQ4uaGwxhmH_NNHiY-sjWybP7xQCSq-Ip0yNVstWfUTQ");
            Assert.AreEqual(Jwt.Decode(test, PublicKey.Load(publicKey)), json);
        }

        [TestMethod]
        public void EncodeRS512()
        {
            //given
            string json = @"{""hello"": ""world""}";

            //when
            string test = Jwt.Encode(json, JwsAlgorithm.RS512, PrivateKey.Load(privateKey));

            //then
            Debug.WriteLine("RS512 = {0}", test);

            Assert.AreEqual(test, "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.YJ_5bDkZUgZj1ZoyTbSeYerUnahjt4Llbj6IwUQUY-zH_mMpywJHs2IT8wteUyX32lCCGr4NfNKpkC-zMMq7aDsklSKIg8sdGYDMheGsEw9YD0QRBF1Ovt4yuSZjWsgmdGSapXKc8CBqSzPCr9S1Rns8YhVHAYMfzHrahXuroYK35gVPQKKLbYQGcwnhpgvxMx0EfGyFbSc6r6XYK-fJ5lSqBh4wSxVMBy_5CkTVWpmnDjRuycE_j4c-yuTYUEAsj5o0sW2ahPf8aomBUC5I1ZG2yTAz8BX7dud6s2VPJQRRsUKlMNrUcMGEooJMoL_vmek9z3t_z9KFyyVHuY5XUA");
            Assert.AreEqual(Jwt.Decode(test, PublicKey.Load(publicKey)), json);
        }
    }
}