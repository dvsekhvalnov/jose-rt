using System.Diagnostics;
using Windows.Security.Cryptography.Core;
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

        private byte[] aes256Key = { 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234 };
        private byte[] aes384Key = { 185, 30, 233, 199, 32, 98, 209, 3, 114, 250, 30, 124, 207, 173, 227, 152, 243, 202, 238, 165, 227, 199, 202, 230, 218, 185, 216, 113, 13, 53, 40, 100, 100, 20, 59, 67, 88, 97, 191, 3, 161, 37, 147, 223, 149, 237, 190, 156 };
        private byte[] aes512Key = { 238, 71, 183, 66, 57, 207, 194, 93, 82, 80, 80, 152, 92, 242, 84, 206, 194, 46, 67, 43, 231, 118, 208, 168, 156, 212, 33, 105, 27, 45, 60, 160, 232, 63, 61, 235, 68, 171, 206, 35, 152, 11, 142, 121, 174, 165, 140, 11, 172, 212, 13, 101, 13, 190, 82, 244, 109, 113, 70, 150, 251, 82, 215, 226 };

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

        // RSA-PSS Implementation is broken!

//        [TestMethod]
//        public void DecodePS256()
//        {
//            //given
//            string token = "eyJhbGciOiJQUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.S9xuR-IGfXEj5qsHcMtK-jcj1lezvVstw1AISp8dEQVRNgwOMZhUQnSCx9i1CA-pMucxR-lv4e7zd6h3cYCfMnyv7iuxraxNiNAgREhOT-bkBCZMNgb5t15xEtDSJ3MuBlK3YBtXyVcDDIdKH_Bwj-u363y6LuvZ8FEOGmIK5WSFi18Xjg-ihhvH1C6UzH1G82wrRbX6DyJKqrUnHAg8yzUJVP1AdgjWRt5BKpuYbXSib-MKZZkaE4q_hCb-j25xCzn8Ez8a7PO7p0fDGvZuOk_yzSfvXSavg7iE0GLuUTNv3nQ_xW-rfbrpYeyXNtstoK3JPFpdtORTyH1iIh7VVA";
//
//            //when
//            string json = JoseRT.Jwt.Decode(token, PublicKey.Load(publicKey));
//
//            Debug.WriteLine("token = {0}", json);
//
//            //then
//            Assert.AreEqual(json, @"{""hello"": ""world""}");
//        }
//
//        [TestMethod]
//        public void DecodePS384()
//        {
//            //given
//            string token = "eyJhbGciOiJQUzM4NCIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.EKqVLw6nLGNt1h7KNFZbzkKhf788VBYCfnigYc0dBZBa64MrfbIFHtJuFgIGkCVSDYH-qs-i4w9ke6mD8mxTZFniMgzFXXaCFIrv6QZeMbKh6VYtSEPp7l0B1zMZiQw6egZbZ6a8VBkCRipuZggSlUTg5tHMMTj_jNVxxlY4uUwXlz7vakpbqgXe19pCDJrzEoXE0cNKV13eRCNA1tXOHx0dFL7Jm9NUq7blvhJ8iTw1jMFzK8bV6g6L7GclHBMoJ3MIvRp71m6idir-QeW1KCUfVtBs3HRn3a822LW02vGqopSkaGdRzQZOI28136AMeW4679UXE852srA2v3mWHQ";
//
//            //when
//            string json = JoseRT.Jwt.Decode(token, PublicKey.Load(publicKey));
//
//            Debug.WriteLine("token = {0}", json);
//
//            //then
//            Assert.AreEqual(json, @"{""hello"": ""world""}");
//        }
//
//        [TestMethod]
//        public void DecodePS512()
//        {
//            //given
//            string token = "eyJhbGciOiJQUzUxMiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.IvbnmxhKvM70C0n0grkF807wOQLyPOBwJOee-p7JHCQcSstNeml3Owdyw9C3HGHzOdK9db51yAkjJ2TCojxqHW4OR5Apna8tvafYgD2femn1V3GdkGj6ZvYdV3q4ldnmahVeO36vHYy5P0zFcEGU1_j3S3DwGmhw2ktZ4p5fLZ2up2qwhzlOjbtsQpWywHj7cLdeA32MLId9MTAPVGUHIZHw_W0xwjJRS6TgxD9vPQQnP70MY-q_2pVAhfRCM_pauPYO1XH5ldizrTvVr27q_-Uqtw-wV-UDUnyWYQUDDiMTpLBoX1EEXmsbvUGx0OH3yWEaNINoCsepgZvTKbiEQQ";
//
//            //when
//            string json = JoseRT.Jwt.Decode(token, PublicKey.Load(publicKey));
//
//            Debug.WriteLine("token = {0}", json);
//
//            //then
//            Assert.AreEqual(json, @"{""hello"": ""world""}");
//        }


//        [TestMethod]
//        public void EncodePS256()
//        {
//            //given
//            string json = @"{""hello"": ""world""}";
//
//            //when
//            string test = Jwt.Encode(json, JwsAlgorithm.PS256, PrivateKey.Load(privateKey));
//
//            //then
//            Debug.WriteLine("PS256 = {0}", test);
//
////            Assert.AreEqual(test, "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.YJ_5bDkZUgZj1ZoyTbSeYerUnahjt4Llbj6IwUQUY-zH_mMpywJHs2IT8wteUyX32lCCGr4NfNKpkC-zMMq7aDsklSKIg8sdGYDMheGsEw9YD0QRBF1Ovt4yuSZjWsgmdGSapXKc8CBqSzPCr9S1Rns8YhVHAYMfzHrahXuroYK35gVPQKKLbYQGcwnhpgvxMx0EfGyFbSc6r6XYK-fJ5lSqBh4wSxVMBy_5CkTVWpmnDjRuycE_j4c-yuTYUEAsj5o0sW2ahPf8aomBUC5I1ZG2yTAz8BX7dud6s2VPJQRRsUKlMNrUcMGEooJMoL_vmek9z3t_z9KFyyVHuY5XUA");
////            Assert.AreEqual(Jwt.Decode(test, PublicKey.Load(publicKey)), json);
//        }

        [TestMethod]
        public void DecodeES256()
        {
            //given
            string token = "eyJhbGciOiJFUzI1NiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.EVnmDMlz-oi05AQzts-R3aqWvaBlwVZddWkmaaHyMx5Phb2NSLgyI0kccpgjjAyo1S5KCB3LIMPfmxCX_obMKA";

            //when
            string test = Jwt.Decode(token, Ecc256Public());

            //then
            Assert.AreEqual(test, @"{""hello"": ""world""}");
        }

        [TestMethod]
        public void DecodeES384()
        {
            //given
            string token = "eyJhbGciOiJFUzM4NCIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.jVTHd9T0fIQDJLNvAq3LPpgj_npXtWb64FfEK8Sm65Nr9q2goUWASrM9jv3h-71UrP4cBpM3on3yN--o6B-Tl6bscVUfpm1swPp94f7XD9VYLEjGMjQOaozr13iBZJCY";

            //when
            string test = Jwt.Decode(token, Ecc384Public());

            //then
            Assert.AreEqual(test, @"{""hello"": ""world""}");
        }

        [TestMethod]
        public void DecodeES521()
        {
            //given
            string token = "eyJhbGciOiJFUzUxMiIsImN0eSI6InRleHRcL3BsYWluIn0.eyJoZWxsbyI6ICJ3b3JsZCJ9.AHxJYFeTVpZmrfZsltpQKkkplmbkycQKFOFucD7hE4Sm3rCswUDi8hlSCfeYByugySYLFzogTQGk79PHP6vdl39sAUc9k2bhnv-NxRmJsN8ZxEx09qYKbc14qiNWZztLweQg0U-pU0DQ66rwJ0HikzSqgmyD1bJ6RxitJwceYLAovv0v";

            //when
            string test = Jwt.Decode(token, Ecc521Public());

            //then
            Assert.AreEqual(test, @"{""hello"": ""world""}");
        }

        [TestMethod]
        public void EncodeES256()
        {
            //given
            string json = @"{""hello"": ""world""}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwsAlgorithm.ES256, Ecc256Private());

            //then
            Debug.WriteLine("ES256 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 3, "Make sure 3 parts");
            Assert.AreEqual(parts[0], "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1], "eyJoZWxsbyI6ICJ3b3JsZCJ9", "Pyaload is non encrypted and static text");
            Assert.AreEqual(parts[2].Length, 86, "signature size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, Ecc256Public()), json, "Make sure we are consistent with ourselves");
        }

        [TestMethod]
        public void EncodeES384()
        {
            //given
            string json = @"{""hello"": ""world""}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwsAlgorithm.ES384, Ecc384Private());

            //then
            Debug.WriteLine("ES384 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 3, "Make sure 3 parts");
            Assert.AreEqual(parts[0], "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCJ9", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1], "eyJoZWxsbyI6ICJ3b3JsZCJ9", "Pyaload is non encrypted and static text");
            Assert.AreEqual(parts[2].Length, 128, "signature size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, Ecc384Public()), json, "Make sure we are consistent with ourselves");
        }
 
        [TestMethod]
        public void EncodeES512()
        {
            //given
            string json = @"{""hello"": ""world""}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwsAlgorithm.ES512, Ecc521Private());

            //then
            Debug.WriteLine("ES512 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 3, "Make sure 3 parts");
            Assert.AreEqual(parts[0], "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzUxMiJ9", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1], "eyJoZWxsbyI6ICJ3b3JsZCJ9", "Pyaload is non encrypted and static text");
            Assert.AreEqual(parts[2].Length, 176, "signature size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, Ecc521Public()), json, "Make sure we are consistent with ourselves");
        }

        [TestMethod]
        public void Decrypt_DIR_A128CBC_HS256()
        {
            //given
            string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..3lClLoerWhxIc811QXDLbg.iFd5MNk2eWDlW3hbq7vTFLPJlC0Od_MSyWGakEn5kfYbbPk7BM_SxUMptwcvDnZ5uBKwwPAYOsHIm5IjZ79LKZul9ZnOtJONRvxWLeS9WZiX4CghOLZL7dLypKn-mB22xsmSUbtizMuNSdgJwUCxEmms7vYOpL0Che-0_YrOu3NmBCLBiZzdWVtSSvYw6Ltzbch4OAaX2ye_IIemJoU1VnrdW0y-AjPgnAUA-GY7CAKJ70leS1LyjTW8H_ecB4sDCkLpxNOUsWZs3DN0vxxSQw.bxrZkcOeBgFAo3t0585ZdQ";

            //when
            string json = JoseRT.Jwt.Decode(token, aes256Key);

            //then
            Assert.AreEqual(json, @"{""exp"":1392553211,""sub"":""alice"",""nbf"":1392552611,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""586dd129-a29f-49c8-9de7-454af1155e27"",""iat"":1392552611}");
        }

        [TestMethod]
        public void Decrypt_DIR_A192CBC_HS384()
        {
            //given
            string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0..fX42Nn8ABHClA0UfbpkX_g.ClZzxQIzg40GpTETaLejGNhCN0mqSM1BNCIU5NldeF-hGS7_u_5uFsJoWK8BLCoWRtQ3cWIeaHgOa5njCftEK1AoHvechgNCQgme-fuF3f2v5DOphU-tveYzN-uvrUthS0LIrAYrwQW0c0DKcJZ-9vQmC__EzesZgUHiDB8SnoEROPTvJcsBKI4zhFT7wOgqnFS7P7_BQZj_UnbJkzTAiE5MURBBpCYR-OS3zn--QftbdGVJ2CWmwH3HuDO9-IE2IQ5cKYHnzSwu1vyME_SpZA.qd8ZGKzmOzzPhFV-Po8KgJ5jZb5xUQtU";

            //when
            string json = JoseRT.Jwt.Decode(token, aes384Key);

            //then
            Assert.AreEqual(json, @"{""exp"":1392553372,""sub"":""alice"",""nbf"":1392552772,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""f81648e9-e9b3-4e37-a655-fcfacace0ef0"",""iat"":1392552772}");
        }

        [TestMethod]
        public void Decrypt_DIR_A256CBC_HS512()
        {
            //given
            string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..ZD93XtD7TOa2WMbqSuaY9g.1J5BAuxNRMWaw43s7hR82gqLiaZOHBmfD3_B9k4I2VIDKzS9oEF_NS2o7UIBa6t_fWHU7vDm9lNAN4rqq7OvtCBHJpFk31dcruQHxwYKn5xNefG7YP-o6QtpyNioNWJpaSD5VRcRO5ufRrw2bu4_nOth00yJU5jjN3O3n9f-0ewrN2UXDJIbZM-NiSuEDEgOVHImQXoOtOQd0BuaDx6xTJydw_rW5-_wtiOH2k-3YGlibfOWNu51kApGarRsAhhqKIPetYf5Mgmpv1bkUo6HJw.nVpOmg3Sxri0rh6nQXaIx5X0fBtCt7Kscg6c66NugHY";

            //when
            string json = JoseRT.Jwt.Decode(token, aes512Key);

            //then
            Assert.AreEqual(json, @"{""exp"":1392553617,""sub"":""alice"",""nbf"":1392553017,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""029ea059-b8aa-44eb-a5ad-59458de678f8"",""iat"":1392553017}");
        }

        [TestMethod]
        public void Encrypt_DIR_A128CBC_HS256()
        {
            //given
            string json =
                @"{""hello"":""world""}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.DIR, JweAlgorithms.A128CBC_HS256, aes256Key);

            //then
            Debug.WriteLine("DIR_A128CBC_HS256 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 0, "CEK size");
            Assert.AreEqual(parts[2].Length, 22, "IV size");
            Assert.AreEqual(parts[3].Length, 43, "cipher text size");
            Assert.AreEqual(parts[4].Length, 22, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, aes256Key), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Encrypt_DIR_A192CBC_HS384()
        {
            //given
            string json =
                @"{""hello"":""world""}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.DIR, JweAlgorithms.A192CBC_HS384, aes384Key);

            //then
            Debug.WriteLine("DIR_A192CBC_HS384 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwiYWxnIjoiZGlyIn0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 0, "CEK size");
            Assert.AreEqual(parts[2].Length, 22, "IV size");
            Assert.AreEqual(parts[3].Length, 43, "cipher text size");
            Assert.AreEqual(parts[4].Length, 32, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, aes384Key), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Encrypt_DIR_A256CBC_HS512()
        {
            //given
            string json =
                @"{""hello"":""world""}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.DIR, JweAlgorithms.A256CBC_HS512, aes512Key);

            //then
            Debug.WriteLine("DIR_A256CBC_HS512 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiZGlyIn0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 0, "CEK size");
            Assert.AreEqual(parts[2].Length, 22, "IV size");
            Assert.AreEqual(parts[3].Length, 43, "cipher text size");
            Assert.AreEqual(parts[4].Length, 43, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, aes512Key), json, "Make sure we are consistent with ourselfs");
        }


        #region Test Utils

        private CryptographicKey Ecc256Public()
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };

            return JoseRT.Ecc.PublicKey.New(x, y);
        }

        private CryptographicKey Ecc256Private()
        {
            byte[] x = { 4, 114, 29, 223, 58, 3, 191, 170, 67, 128, 229, 33, 242, 178, 157, 150, 133, 25, 209, 139, 166, 69, 55, 26, 84, 48, 169, 165, 67, 232, 98, 9 };
            byte[] y = { 131, 116, 8, 14, 22, 150, 18, 75, 24, 181, 159, 78, 90, 51, 71, 159, 214, 186, 250, 47, 207, 246, 142, 127, 54, 183, 72, 72, 253, 21, 88, 53 };
            byte[] d = { 42, 148, 231, 48, 225, 196, 166, 201, 23, 190, 229, 199, 20, 39, 226, 70, 209, 148, 29, 70, 125, 14, 174, 66, 9, 198, 80, 251, 95, 107, 98, 206 };

            return JoseRT.Ecc.PrivateKey.New(x, y, d);
        }


        private CryptographicKey Ecc384Private()
        {
            byte[] x = { 70, 151, 220, 179, 62, 0, 79, 232, 114, 64, 58, 75, 91, 209, 232, 128, 7, 137, 151, 42, 13, 148, 15, 133, 93, 215, 7, 3, 136, 124, 14, 101, 242, 207, 192, 69, 212, 145, 88, 59, 222, 33, 127, 46, 30, 218, 175, 79 };
            byte[] y = { 189, 202, 196, 30, 153, 53, 22, 122, 171, 4, 188, 42, 71, 2, 9, 193, 191, 17, 111, 180, 78, 6, 110, 153, 240, 147, 203, 45, 152, 236, 181, 156, 232, 223, 227, 148, 68, 148, 221, 176, 57, 149, 44, 203, 83, 85, 75, 55 };
            byte[] d = { 137, 199, 183, 105, 188, 90, 128, 82, 116, 47, 161, 100, 221, 97, 208, 64, 173, 247, 9, 42, 186, 189, 181, 110, 24, 225, 254, 136, 75, 156, 242, 209, 94, 218, 58, 14, 33, 190, 15, 82, 141, 238, 207, 214, 159, 140, 247, 139 };

            return JoseRT.Ecc.PrivateKey.New(x, y, d);
        }

        private CryptographicKey Ecc521Private()
        {
            byte[] x = { 0, 248, 73, 203, 53, 184, 34, 69, 111, 217, 230, 255, 108, 212, 241, 229, 95, 239, 93, 131, 100, 37, 86, 152, 87, 98, 170, 43, 25, 35, 80, 137, 62, 112, 197, 113, 138, 116, 114, 55, 165, 128, 8, 139, 148, 237, 109, 121, 40, 205, 3, 61, 127, 28, 195, 58, 43, 228, 224, 228, 82, 224, 219, 148, 204, 96 };
            byte[] y = { 0, 60, 71, 97, 112, 106, 35, 121, 80, 182, 20, 167, 143, 8, 246, 108, 234, 160, 193, 10, 3, 148, 45, 11, 58, 177, 190, 172, 26, 178, 188, 240, 91, 25, 67, 79, 64, 241, 203, 65, 223, 218, 12, 227, 82, 178, 66, 160, 19, 194, 217, 172, 61, 250, 23, 78, 218, 130, 160, 105, 216, 208, 235, 124, 46, 32 };
            byte[] d = { 0, 222, 129, 9, 133, 207, 123, 116, 176, 83, 95, 169, 29, 121, 160, 137, 22, 21, 176, 59, 203, 129, 62, 111, 19, 78, 14, 174, 20, 211, 56, 160, 83, 42, 74, 219, 208, 39, 231, 33, 84, 114, 71, 106, 109, 161, 116, 243, 166, 146, 252, 231, 137, 228, 99, 149, 152, 123, 201, 157, 155, 131, 181, 106, 179, 112 };

            return JoseRT.Ecc.PrivateKey.New(x, y, d);
        }

        private CryptographicKey Ecc384Public()
        {
            byte[] x = { 70, 151, 220, 179, 62, 0, 79, 232, 114, 64, 58, 75, 91, 209, 232, 128, 7, 137, 151, 42, 13, 148, 15, 133, 93, 215, 7, 3, 136, 124, 14, 101, 242, 207, 192, 69, 212, 145, 88, 59, 222, 33, 127, 46, 30, 218, 175, 79 };
            byte[] y = { 189, 202, 196, 30, 153, 53, 22, 122, 171, 4, 188, 42, 71, 2, 9, 193, 191, 17, 111, 180, 78, 6, 110, 153, 240, 147, 203, 45, 152, 236, 181, 156, 232, 223, 227, 148, 68, 148, 221, 176, 57, 149, 44, 203, 83, 85, 75, 55 };

            return JoseRT.Ecc.PublicKey.New(x, y);
        }

        private CryptographicKey Ecc521Public()
        {
            byte[] x = { 0, 248, 73, 203, 53, 184, 34, 69, 111, 217, 230, 255, 108, 212, 241, 229, 95, 239, 93, 131, 100, 37, 86, 152, 87, 98, 170, 43, 25, 35, 80, 137, 62, 112, 197, 113, 138, 116, 114, 55, 165, 128, 8, 139, 148, 237, 109, 121, 40, 205, 3, 61, 127, 28, 195, 58, 43, 228, 224, 228, 82, 224, 219, 148, 204, 96 };
            byte[] y = { 0, 60, 71, 97, 112, 106, 35, 121, 80, 182, 20, 167, 143, 8, 246, 108, 234, 160, 193, 10, 3, 148, 45, 11, 58, 177, 190, 172, 26, 178, 188, 240, 91, 25, 67, 79, 64, 241, 203, 65, 223, 218, 12, 227, 82, 178, 66, 160, 19, 194, 217, 172, 61, 250, 23, 78, 218, 130, 160, 105, 216, 208, 235, 124, 46, 32 };

            return JoseRT.Ecc.PublicKey.New(x, y);
        }

        #endregion

    }
}