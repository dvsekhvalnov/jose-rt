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

        private byte[] aes128Key = { 194, 164, 235, 6, 138, 248, 171, 239, 24, 216, 11, 22, 137, 199, 215, 133 };
        private byte[] aes192Key = { 139, 156, 136, 148, 17, 147, 27, 233, 145, 80, 115, 197, 223, 11, 100, 221, 5, 50, 155, 226, 136, 222, 216, 14 };
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
            string test = Jwt.Encode(payload, JwsAlgorithms.None, null);

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
            string test = Jwt.Encode(payload, JwsAlgorithms.HS256, shaKey);

            //then
            Assert.AreEqual("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.KmLWPfxC3JGopWImDgYg9IUpgAi8gwimviUfr6eJyFI", test);
        }

        [TestMethod]
        public void EncodeHS384()
        {
            //given
            string payload = @"{""hello"": ""world""}";

            //when
            string test = Jwt.Encode(payload, JwsAlgorithms.HS384, shaKey);

            //then
            Assert.AreEqual("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJoZWxsbyI6ICJ3b3JsZCJ9.Be1KYCRGFbv0uQwelaRj0a5SYDdbk_sYsXkfrbRI6TmYpuWBga_RsiU2TyyyjoXR",test);
        }

        [TestMethod]
        public void EncodeHS512()
        {
            //given
            string payload = @"{""hello"": ""world""}";

            //when
            string test = Jwt.Encode(payload, JwsAlgorithms.HS512, shaKey);

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
            string test = Jwt.Encode(json, JwsAlgorithms.RS256, PrivateKey.Load(privateKey));

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
            string test = Jwt.Encode(json, JwsAlgorithms.RS384, PrivateKey.Load(privateKey));

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
            string test = Jwt.Encode(json, JwsAlgorithms.RS512, PrivateKey.Load(privateKey));

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
            string token = JoseRT.Jwt.Encode(json, JwsAlgorithms.ES256, Ecc256Private());

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
            string token = JoseRT.Jwt.Encode(json, JwsAlgorithms.ES384, Ecc384Private());

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
            string token = JoseRT.Jwt.Encode(json, JwsAlgorithms.ES512, Ecc521Private());

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

        [TestMethod]
        public void Decrypt_DIR_A128GCM()
        {
            //given
            string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIn0..yVi-LdQQngN0C5WS.1McwSmhZzAtmmLp9y-OdnJwaJFo1nj_4ashmzl2LhubGf0Jl1OTEVJzsHZb7bkup7cGTkuxh6Vfv10ljHsjWf_URXoxP3stQqQeViVcuPV0y2Q_WHYzTNGZpmHGe-hM6gjDhyZyvu3yeXGFSvfPQmp9pWVOgDjI4RC0MQ83rzzn-rRdnZkznWjbmOPxwPrR72Qng0BISsEwbkPn4oO8-vlHkVmPpuDTaYzCT2ZR5K9JnIU8d8QdxEAGb7-s8GEJ1yqtd_w._umbK59DAKA3O89h15VoKQ";

            //when
            string json = JoseRT.Jwt.Decode(token, aes128Key);

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1392548520,""sub"":""alice"",""nbf"":1392547920,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""0e659a67-1cd3-438b-8888-217e72951ec9"",""iat"":1392547920}");
        }

        [TestMethod]
        public void Decrypt_DIR_A192GCM()
        {
            //given
            string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTkyR0NNIn0..YW2WB0afVronbgSz.tfk1VADGjBnViYD7He5mbhxpbogoT1cmhKiDKzzoBV2AxfsgJ2Eq-vtEqPi9eY9H52FLLtht26rc5fPz9ZKOUH2hYeFdaRyKYXlpEnUR2cCT9_3TYcaFhpYBH4HCa59NruKlJHMBqM2ssWZLSEblFX9srUHFtu2OQz2ydMy1fr8ABDTdVYgaqyBoYRGykTkEsgayEyfAMz9u095N2J0JTCB5Q0IiXNdBzBSxZXG-i9f5HFEb6IliaTwFTNFnhDL66O4rsg._dh02z25W7HA6b1XiFVpUw";

            //when
            string json = JoseRT.Jwt.Decode(token, aes192Key);

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1392552631,""sub"":""alice"",""nbf"":1392552031,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""a3fea096-2e96-4d8b-b7cd-070e08b533fb"",""iat"":1392552031}");
        }

        [TestMethod]
        public void Decrypt_DIR_A256GCM()
        {
            //given
            string token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..Fmz3PLVfv-ySl4IJ.LMZpXMDoBIll5yuEs81Bws2-iUUaBSpucJPL-GtDKXkPhFpJmES2T136Vd8xzvp-3JW-fvpRZtlhluqGHjywPctol71Zuz9uFQjuejIU4axA_XiAy-BadbRUm1-25FRT30WtrrxKltSkulmIS5N-Nsi_zmCz5xicB1ZnzneRXGaXY4B444_IHxGBIS_wdurPAN0OEGw4xIi2DAD1Ikc99a90L7rUZfbHNg_iTBr-OshZqDbR6C5KhmMgk5KqDJEN8Ik-Yw.Jbk8ZmO901fqECYVPKOAzg";

            //when
            string json = JoseRT.Jwt.Decode(token, aes256Key);

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1392552841,""sub"":""alice"",""nbf"":1392552241,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""efdfc02f-945e-4e1f-85a6-9f240f6cf153"",""iat"":1392552241}");
        }

        [TestMethod]
        public void Encrypt_DIR_A128GCM()
        {
            //given
            string json = @"{""hello"": ""world""}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.DIR, JweAlgorithms.A128GCM, aes128Key);

            //then
            Debug.WriteLine("DIR_A128GCM = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiZGlyIn0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 0, "CEK size");
            Assert.AreEqual(parts[2].Length, 16, "IV size, 96 bits");
            Assert.AreEqual(parts[3].Length, 24, "cipher text size");
            Assert.AreEqual(parts[4].Length, 22, "auth tag size");
            Assert.AreEqual(JoseRT.Jwt.Decode(token, aes128Key), json, "Make sure we are consistent with ourselfs");
        }


        [TestMethod]
        public void Encrypt_DIR_A192GCM()
        {
            //given
            string json = @"{""hello"": ""world""}";                

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.DIR, JweAlgorithms.A192GCM, aes192Key);

            //then
            Debug.WriteLine("DIR_A192GCM = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiZGlyIn0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 0, "CEK size");
            Assert.AreEqual(parts[2].Length, 16, "IV size, 96 bits");
            Assert.AreEqual(parts[3].Length, 24, "cipher text size");
            Assert.AreEqual(parts[4].Length, 22, "auth tag size");
            Assert.AreEqual(JoseRT.Jwt.Decode(token, aes192Key), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Encrypt_DIR_A256GCM()
        {
            //given
            string json = @"{""hello"": ""world""}";               

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.DIR, JweAlgorithms.A256GCM, aes256Key);

            //then
            Debug.WriteLine("DIR_A256GCM = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiZGlyIn0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 0, "CEK size");
            Assert.AreEqual(parts[2].Length, 16, "IV size, 96 bits");
            Assert.AreEqual(parts[3].Length, 24, "cipher text size");
            Assert.AreEqual(parts[4].Length, 22, "auth tag size");
            Assert.AreEqual(JoseRT.Jwt.Decode(token, aes256Key), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Decrypt_RSA_1_5_A128CBC_HS256()
        {
            //given
            string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bx_4TL7gh14IeM3EClP3iVfY9pbT81pflXd1lEZOVPJR6PaewRFXWmiJcaqH9fcU9IjGGQ19BS-UPtpErenL5kw7KORFgIBm4hObCYxLoAadMy8A-qQeOWyjnxbE0mbQIdoFI4nGK5qWTEQUWZCMwosvyeHLqEZDzr9CNLAAFTujvsZJJ7NLTkA0cTUzz64b57uSvMTaOK6j7Ap9ZaAgF2uaqBdZ1NzqofLeU4XYCG8pWc5Qd-Ri_1KsksjaDHk12ZU4vKIJWJ-puEnpXBLoHuko92BnN8_LXx4sfDdK7wRiXk0LU_iwoT5zb1ro7KaM0hcfidWoz95vfhPhACIsXQ.YcVAPLJ061gvPpVB-zMm4A.PveUBLejLzMjA4tViHTRXbYnxMHFu8W2ECwj9b6sF2u2azi0TbxxMhs65j-t3qm-8EKBJM7LKIlkAtQ1XBeZl4zuTeMFxsQ0VShQfwlN2r8dPFgUzb4f_MzBuFFYfP5hBs-jugm89l2ZTj8oAOOSpAlC7uTmwha3dNaDOzlJniqAl_729q5EvSjaYXMtaET9wSTNSDfMUVFcMERbB50VOhc134JDUVPTuriD0rd4tQm8Do8obFKtFeZ5l3jT73-f1tPZwZ6CmFVxUMh6gSdY5A.tR8bNx9WErquthpWZBeMaw";

            //when
            string json = JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey));

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1391196668,""sub"":""alice"",""nbf"":1391196068,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""3814fff3-db66-45d9-a29a-d2cc2407bdcf"",""iat"":1391196068}");
        }

        [TestMethod]
        public void Decrypt_RSA_1_5_A192CBC_HS384()
        {
            //given
            string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.ApUpt1SGilnXuqvFSHdTV0K9QKSf0P6wEEOTrAqWMwyEOLlyb6VR8o6fdd4wXMTkkL5Bp9BH1x0oibTrVwVa50rxbPDlRJQe0yvBm0w02nkzl3Tt4fE3sGjEXGgI8w8ZxSVAN0EkaXLqzsG1rQ631ptzqyNzg9BWfy53cHhuzh9w00ZOXZtNc7GFBQ1LRvhK1EyLS2_my8KD091KwsjvXC-_J0eOp2W8NkycP_jCIrUzAOSwz--NZyRXt9V2o609HGItKajHplbE1PJVShaXO84MdJl3X6ef8ZXz7mCP3dRlsYfK-tlnFVeEKwC1Oy_zdFsdiY4j41Mj3usvG2j7xQ.GY4Em2zkSGMZsDLNr9pnDw.GZYJSpeQHmOtx34dk4WxEPCnt7l8R5oLKd3IyoMYbjZrWRtomyTufOKfiOVT-nY9ad0Vs5w5Imr2ysy6DnkAFoOnINV_Bzq1hQU4oFfUd_9bFfHZvGuW9H-NTUVBLDhok6NHosSBaY8xLdwHL_GiztRsX_rU4I88bmWBIFiu8T_IRskrX_kSKQ_iGpIJiDy5psIxY4il9dPihLJhcI_JqysW0pIMHB9ij_JSrCnVPs4ngXBHrQoxeDv3HiHFTGXziZ8k79LZ9LywanzC0-ZC5Q.1cmUwl7MnFl__CS9Y__a8t5aVyI9IKOY";

            //when
            string json = JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey));

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1391196668,""sub"":""alice"",""nbf"":1391196068,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""c9d44ff8-ff1e-4490-8454-941e45766152"",""iat"":1391196068}");
        }

        [TestMethod]
        public void Decrypt_RSA_1_5_A256CBC_HS512()
        {
            //given
            string token = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.GVXwkd5rfqffr4ue26IGHXuiV6r-rQa9OQ4B1LtodsTpWfraOLyhyHYseEKpXV4aSMWWN0q2HS0myj73BuGsDMP-xiIM04QxWD7dbP2OticXzktcHHhMFUx0OK_IOmc21qshTqbb0yKWizMnCuVosQqw2tg_up2sgjqIyiwzpgvC5_l9ddxnTBV334LF_nXTnL22vqrUO92rH_3YmoJ6khHUYVSXhd0fXTKqwm9liULW43prDWkex0N8a8MfgdaFPq0rGw4gRA8HvS7aFn3xCeKAO9Q_q-g32DCDwbfqYhvGZCbS49ObwfPD-fKaFS94VFSMb_Cy-WalZwrIz-aWkQ.zh6hViRORvk4b-2io1vUSA.Us26-89QEOWb85TsOZJpH6QB5_GR3wZo49rR38X1daG_kmyfzIUQQ12wBwmxFwHluNvqStVj4YUIvPgC4oZEh1L-r3Tm81Q2PctdMrwl9fRDR6uH1Hqfx-K25vEhlk_A60s060wezUa5eSttjwEHGTY0FpoQvyOmdfmnOdtW_LLyRWoRzmGocD_N4z6BxK-cVTbbTvAYVbWaZNW_eEMLL4qAnKNAhXJzAtUTqJQIn0Fbh3EE3j827hKrtcRbrwqr1BmoOtaQdYUO4VZKIJ7SNw.Zkt6yXlSu9BdknCr32uyu7uH6HVwGFOV48xc4Z7wF9Y";

            //when
            string json = JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey));

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1391196668,""sub"":""alice"",""nbf"":1391196068,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""7efcdbc6-b2b5-4480-985d-bdf741b376bb"",""iat"":1391196068}");
        }

        [TestMethod]
        public void Decrypt_RSA_OAEP_A128CBC_HS256()
        {
            //given
            string token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhDQkMtSFMyNTYifQ.dgIoddBRTBLi8b6fwjaIU5uUP_J-6jL5AtIvoNZDwN0JSmsXkm9SIFz7kQfwavBz_PPG6h0yId55YVFnCqrB5qCIbifmBQPEcB5acKCybHuoHhEBCnQpqxVtHLXZ0dUyd6Xs5h9ymgbbZMjpAoCUK7si90m4O5BCSdedZNQvdXWQW599CRftFVVe_mZOcgABuNIDMfIwyxmi2DVR5c2bSA0ji2Sy27SE_X0lCVHqrAwI-8Rlz1WTWLI6bhRh2jsUPK-6958E4fsXOWsTOp9fW97eW85InZPniv8B5HSG_D0NALhu5AIMsNt-ENeR0sefcphZGUzfyFoxK7EMpY7gAQ.jNw5xfYCvwHvviSuUFYpfw.0_Rvs5cA_QKSVMGbPr5ntFrd_BQhTql-hB9fzLhndAy9vLeHBLtv-bXeZatw4QJIufnpsSnXmRYjKqvWVCp-x-AKpPWzkaj6fvsQ8Mns1kWw5XZr-8SJrbT72LOnRBcTd4qjOYXEJZad8uIwQHDFkkmpm4d7FQ6PhW0-1gOS8FGuYjUupYDQX2ia-4jzqWisv2bE-mKn65q5wy_dT0w04rF-Mk_USyOG5d09kne3ZBv42stpS_xyDS3euVtPuxhQT5TzfPpBkG3CNwwm_HvTTg.E2opVK9nQXPXJbDKb06FBg";

            //when
            string json = JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey));

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1391196668,""sub"":""alice"",""nbf"":1391196068,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""03ac026e-55aa-4475-a806-f09e83048922"",""iat"":1391196068}");
        }

        [TestMethod]
        public void Decrypt_RSA_OAEP_A192CBC_HS384()
        {
            //given
            string token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExOTJDQkMtSFMzODQifQ.BZ8MgMgby05auOw-Gb4ii-fgcRWAlCHd6pMZNFafle6BAT1accRGUsMGRzJRETUFFqoy3rzfdSdFcqgc7lmUQUXrVei6XCRei5VZJo1YlzIPN9rEig3sSJ99hg1mrXh3ezFX_JczTn7xEaRRzdatnkSvWBMMmbMWVjqlpkXSOr7P7x2Ctf-GQwXOKEVUrRFwe2D0qXC0ynWKrm7mkV-tlRHJf5NRdWLT5Tmxka8OJZ0W1MyJKNEemEMt1dThcnedPMBjb8y0IwPZ8Aiam87fWdqk20MDknNyxRoC_epBFZFaWFpZ383mKI2Ev-EqO2lCnFOkSvwcNmhnlOPXHJ40qQ.1aAvdZ8g580VUE55RqRBVw.IkoVJF73DSzi-ebiErrCAtpWPepbFZS6DX0S9Ka85aRfgmLQRQxBucxm48MixkRJ5QYCPGmtXRPyiQQE9zT1aA5Js6BoV8U2JK44HWga4cNkyUUr0Wpu0uz6GEBU620i9DmJasTb4iA3iTMboCpdrCTlzhJrYhSYc09Jo0WJRM83LjorxRjpUmLGqR4SgV1WYFKaben4iSqOVPThzQc7HEGrkbycZRNKj-BAkll7qRtN_1e5k83W9Wlf5taAWwSXMF2VL6XqR0bZXpPcpLi_vw.kePqK6KpRWohWEpSg8vfeCd0PQAqBmjW";

            //when
            string json = JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey));

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1391196668,""sub"":""alice"",""nbf"":1391196068,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""59f54c91-5224-4484-9c3a-e57b87b6f212"",""iat"":1391196068}");
        }

        [TestMethod]
        public void Decrypt_RSA_OAEP_A256CBC_HS512()
        {
            //given
            string token = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZDQkMtSFM1MTIifQ.gCLatpLEIHdwqXGNQ6pI2azteXmksiGvHZoXaFmGjvN6T71ky5Ov8DHmXyaFdxWVPxiPAf6RDpJlokSR34e1W9ey0m9xWELJ_hH_bEoH4s7-wI74edS06i35let0YvCubl3eIemuQNkaJEqoEaHx8sLZ-SsoRxi7tRAIABl4f_THC8CDLw7SXrVcp_b6xRtB9oSI2_y_vSAZXOTZPJBw_t4jwZLnsOUbBXXGKAGIpG0rrL8qMt1KwRW_79qQie2U1kDclD7EVMQ-ji5upayxaXOMLkPqfISgvyGKyaLs-8e_aRyVKbMpkCZNWaLnSAA6aJHynNsnuM8O4iEN-wRXmw.r2SOQ2k_YqZRpoIB6wSbqA.DeYxdBzfRiiJeAm8H58SO8NJCa4yg3beciqZRGiAqQDrFYdp9q1RHuNrd0UY7DfzBChW5Gp37FqMA3eRpZ_ERbMiYMSgBtqJgUTKWyXGYItThpg92-1Nm7LN_Sp16UOSBHMJmbXeS30NMEfudgk3qUzE2Qmec7msk3X3ylbgn8EIwSIeVpGcEi6OWFCX1lTIRm1bqV2JDxY3gbWUB2H2YVtgL7AaioMttBM8Mm5plDY1pTHXZzgSBrTCtqtmysCothzGkRRzuHDzeaWYbznkVg.Hpk41zlPhLX4UQvb_lbCLZ0zAhOI8A0dA-V31KFGs6A";

            //when
            string json = JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey));

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1391196668,""sub"":""alice"",""nbf"":1391196068,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""19539b79-e5cf-4f99-a66e-00a980e1b0a9"",""iat"":1391196068}");
        }

        [TestMethod]
        public void Decrypt_RSA_OAEP_256_A128CBC_HS256()
        {
            //given
            string token = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.bje66yTjMUpyGzbt3QvPNOmCmUPowgEmoBHXw-pByhST2VBSs0_67JKDymKW0VpmQC5Qb7ZLC6nNG8YW5pxTZDOeTQLodhAvzoNAsrx4M2R_N58ZVqBPLKTq7FKi1NNd8oJ80dwWbOJ13dkLH68SlhOK5bhqKFgtbzalnglL2kq8Fki1GkN4YyFnS8-chC-mlrS5bJrPSHUF7oAsG_flL_e9-KzYqYTQgGCB3GYSo_pgalsp2rUO3Oz2Pfe9IEJNlX7R9wOT1nTT0UUg-lSzQ2oOaXNvNyaPgEa76mJ1nk7ZQq7ZNix1m8snjk0Vizd8EOFCSRyOGcp4mHMn7-s00Q.tMFMCdFNQXbhEnwE6mP_XQ.E_O_ZBtJ8P0FvhKOV_W98oxIySDgdd0up0c8FAjo-3OVZ_6XMEQYFDKVG_Zc3zkbaz1Z2hmc7D7M28RbhRdya3yJN6Hcv1KuXeZ9ociI7o739Ni_bPvv8xCmGxlASS5AF7N4JR7XjrWL-SYKGNL1p0XNTlPo3B3qYqgAY6jFNvlcjWupim-pQbWKNqPbO2KmSCtUzyKE5oHjsomH0hnQs0_DXv3cgQ_ZFLFZBc1tC4AjQ8QZex5kWg5BmlJDM5F_jD7QRhb7B1u4Mi563-AKVA.0lraw3IXMM6wPqUZVYA8pg";

            //when
            string json = JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey));

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1392553211,""sub"":""alice"",""nbf"":1392552611,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""586dd129-a29f-49c8-9de7-454af1155e27"",""iat"":1392552611}");
        }

        [TestMethod]
        public void Decrypt_RSA_OAEP_256_A192CBC_HS384()
        {
            //given
            string token = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.COuKvozBVi2vkEPpFdx0HTMpU9tmpP1lLngbmGn8RVphY-vjhVaduv8D_Ay_1j8LuMz4tgP98xWtbJkTyhxY1kBwXe0CgqFUOSJ1mTEPRkKSXpdFR7rT1Pv68qug2yKaXT_qcviyBerIcUVFbXBmtiYAosYO4kaPSOE1IvLadFOrMkxdZv6QiiCROzWgJNCCMgNQZGRoPhqLe3wrcxi86DhNO7Bpqq_yeNVyHdU_qObMuMVZIWWEQIDhiU4nE8WGJLG_NtKElc_nQwbmclL_YYgTiHsIAKWZCdj0nwfLe5mwJQN4r7pjakiUVzCbNNgI1-iBH1vJD5VCPxgWldzfYA.7cDs4wzbNDt1Kq40Q5ae4w.u1bR6ChVd90QkFIp3H6IkOCIMwf5aIKsQOvqgFangRLrDjctl5qO5jTHr1o1GwBQvAkRmaGSE7fRIwWB_l-Ayx2c2WDFOkVXFSR_D23GrWaLMLbugPItQd2Mny6H4QOzO3O0EK_Qm7frqwKQI3og72SB8DUqzEaKsrz7HR2z_qMa2CEEApxai_R6NIlAdMUbYvOfZx262MWFGrITBDmma-Mnqiz9WJUv2wexfwjROaaS4wXfkGy5B6ltESifpZZk5NerExR3GA6yX7cFqJc4pQ.FKcbLyB9eP1UXmxyliTu1_GQrnS-JtAB";

            //when
            string json = JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey));

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1392553211,""sub"":""alice"",""nbf"":1392552611,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""586dd129-a29f-49c8-9de7-454af1155e27"",""iat"":1392552611}");
        }

        [TestMethod]
        public void Decrypt_RSA_OAEP_256_A256CBC_HS512()
        {
            //given
            string token = "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.Pt1q6MNdaiVWhMnY7r6DVpkYQmzyIjhb0cj10LowP_FgMu1dOQVuNwhK14MO1ki1y1Pvxouct9wwmb5gE7jNJBy6vU-FrrY62WNr_hKL3Cq2030LlJwauv1XQrEE-GCw1srxOAsw6LNT14v4f0qjeW46mIHNX4CZMEO9ntwojWsHTNsh4Qk6SU1QlS3WbbVl7gjjfqTP54j2ZwZM38s7Cs4pSAChP04UbW6Uhrm65JSi0lyg25OBXIxMEt1z9WY8lnjuh3iL_WttnFn9lf5fUuuR2N70HwANz2mxH3CxjO0ygXJtV-FhFzz3HqI2-ELrve4Igj_2f2_S6OrRTWRucA.er5K9Gk0wp3wF_sq7ib7BQ.L80B9FGSjUbEblpJ6tuiaq6NAsW89YQGD0awxtE-irKN65PT8nndBd0hlel8RRThXRF0kiYYor2GpgvVVaoOzSQcwL-aDgNO7BeRsaOL5ku2NlyT1erbg_8jEVG5BFMM0-jCb4kD0jBKWYCGoB7qs_QQxZ394H5GPwG68vlizKEa8PoaNIM0at5oFT7EHPdmGmwQyQCHR43e6uN4k28PWNxjN9Ndo5lvlYnxnAyDGVDu8lCjozaA_ZTrEPS-UBb6lOEW39CXdwVk1MgvyQfswQ.yuDMf_77Wr9Er3FG1_0FwHXJTOVQPjzBwGoKEg81mQo";

            //when
            string json = JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey));

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1392553211,""sub"":""alice"",""nbf"":1392552611,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""586dd129-a29f-49c8-9de7-454af1155e27"",""iat"":1392552611}");
        }

        [TestMethod]
        public void Encrypt_RSA_OAEP_256_A128GCM()
        {
            //given
            string json = @"{""hello"": ""world""}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.RSA_OAEP_256, JweAlgorithms.A128GCM, PublicKey.Load(publicKey));

            //then
            Debug.WriteLine("RSA_OAEP_256_A128GCM={0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMTI4R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 342, "CEK size");
            Assert.AreEqual(parts[2].Length, 16, "IV size");
            Assert.AreEqual(parts[3].Length, 24, "cipher text size");
            Assert.AreEqual(parts[4].Length, 22, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey)), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Encrypt_RSA_OAEP_256_A192GCM()
        {
            //given
            string json = @"{""hello"": ""world""}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.RSA_OAEP_256, JweAlgorithms.A192GCM, PublicKey.Load(publicKey));

            //then
            Debug.WriteLine("RSA_OAEP_256_A192GCM={0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMTkyR0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 342, "CEK size");
            Assert.AreEqual(parts[2].Length, 16, "IV size");
            Assert.AreEqual(parts[3].Length, 24, "cipher text size");
            Assert.AreEqual(parts[4].Length, 22, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey)), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Encrypt_RSA_OAEP_256_A256GCM()
        {
            //given
            string json = @"{""hello"": ""world""}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.RSA_OAEP_256, JweAlgorithms.A256GCM, PublicKey.Load(publicKey));

            //then
            Debug.WriteLine("RSA_OAEP_256_A256GCM={0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 342, "CEK size");
            Assert.AreEqual(parts[2].Length, 16, "IV size");
            Assert.AreEqual(parts[3].Length, 24, "cipher text size");
            Assert.AreEqual(parts[4].Length, 22, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey)), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Encrypt_RSA_OAEP_A128CBC_HS256()
        {
            //given
            string json = @"{""hello"": ""world""}"; 

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.RSA_OAEP, JweAlgorithms.A128CBC_HS256, PublicKey.Load(publicKey));

            //then
            Debug.WriteLine("RSA_OAEP_A128CBC_HS256 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBLU9BRVAifQ", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 342, "CEK size");
            Assert.AreEqual(parts[2].Length, 22, "IV size");
            Assert.AreEqual(parts[3].Length, 43, "cipher text size");
            Assert.AreEqual(parts[4].Length, 22, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey)), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Encrypt_RSA_OAEP_A192CBC_HS384()
        {
            //given
            var json = @"{""hello"": ""world""}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.RSA_OAEP, JweAlgorithms.A192CBC_HS384, PublicKey.Load(publicKey));

            //then
            Debug.WriteLine("RSA_OAEP_A192CBC_HS384 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwiYWxnIjoiUlNBLU9BRVAifQ", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 342, "CEK size");
            Assert.AreEqual(parts[2].Length, 22, "IV size");
            Assert.AreEqual(parts[3].Length, 43, "cipher text size");
            Assert.AreEqual(parts[4].Length, 32, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey)), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Encrypt_RSA_OAEP_A256CBC_HS512()
        {
            //given
            var json = @"{""hello"": ""world""}";

            //when            
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.RSA_OAEP, JweAlgorithms.A256CBC_HS512, PublicKey.Load(publicKey));

            //then
            Debug.WriteLine("RSA_OAEP_A256CBC_HS512 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBLU9BRVAifQ", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 342, "CEK size");
            Assert.AreEqual(parts[2].Length, 22, "IV size");
            Assert.AreEqual(parts[3].Length, 43, "cipher text size");
            Assert.AreEqual(parts[4].Length, 43, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey)), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Encrypt_RSA1_5_A128CBC_HS256()
        {
            //given
            string json = @"{""hello"": ""world""}";               

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.RSA1_5, JweAlgorithms.A128CBC_HS256, PublicKey.Load(publicKey));

            //then
            Debug.WriteLine("RSA1_5_A128CBC_HS256 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUlNBMV81In0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 342, "CEK size");
            Assert.AreEqual(parts[2].Length, 22, "IV size");
            Assert.AreEqual(parts[3].Length, 43, "cipher text size");
            Assert.AreEqual(parts[4].Length, 22, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey)), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Encrypt_RSA1_5_A192CBC_HS384()
        {
            //given
            var json = @"{""hello"": ""world""}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.RSA1_5, JweAlgorithms.A192CBC_HS384, PublicKey.Load(publicKey));

            //then
            Debug.WriteLine("RSA1_5_A192CBC_HS384 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwiYWxnIjoiUlNBMV81In0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 342, "CEK size");
            Assert.AreEqual(parts[2].Length, 22, "IV size");
            Assert.AreEqual(parts[3].Length, 43, "cipher text size");
            Assert.AreEqual(parts[4].Length, 32, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey)), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Encrypt_RSA1_5_A256CBC_HS512()
        {
            //given
            string json = @"{""hello"": ""world""}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.RSA1_5, JweAlgorithms.A256CBC_HS512, PublicKey.Load(publicKey));

            //then
            Debug.WriteLine("RSA1_5_A256CBC_HS512 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiUlNBMV81In0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 342, "CEK size");
            Assert.AreEqual(parts[2].Length, 22, "IV size");
            Assert.AreEqual(parts[3].Length, 43, "cipher text size");
            Assert.AreEqual(parts[4].Length, 43, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, PrivateKey.Load(privateKey)), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Decrypt_A128KW_A128CBC_HS256()
        {
            //given
            string token = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.DPRoUHQ3Ac8duyD32nUNH3eNUKzUIMYgEdf5GwJ8rW4MYQdl2PCIHA.B1dR6t93aUPcFC1c1aUjeA.lHPKTK0ehgzq70_Ihdh-svI2icUa9usgqP8sF5j50fsQAGizITZpTTXKOKd9-GSEVmJo07551hq9xscZj4vXsDEx-z-akxg0nlL5fFE24km7l4T3LfAeG17gmrMcJuLP55mFUg-F98j9duV2UCyKJPXP6RwOQ5X17VNw29c4k-_AxYM0EjTv3Fww1o3AGuVa07PfpLWE-GdJeJF9RLgaP_6Pua_mdVJud77bYXOsVxsweVtKIaBeLswMUUSU6PoC5oYURP_ybW76GOCjmgXpjA.avU8f5LK_tbJOyKW6-fRnw";

            //when
            string json = JoseRT.Jwt.Decode(token, aes128Key);

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1392553211,""sub"":""alice"",""nbf"":1392552611,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""586dd129-a29f-49c8-9de7-454af1155e27"",""iat"":1392552611}");
        }

        [TestMethod]
        public void Decrypt_A192KW_A192CBC_HS384()
        {
            //given
            string token = "eyJhbGciOiJBMTkyS1ciLCJlbmMiOiJBMTkyQ0JDLUhTMzg0In0.OLwgc7EaQdvsf54GfU69qH143C79H_eETvM_yGBgJzEB5367k9tbw6qW4TlQ56GMj__5QDJBvAg.BvYY_v4_dxxsK4M8A0T_TA.V0jBe7o-OahMkqGDgWW0Lxq1eTKPJYix7hjKmmqaKlhdVcnT0cdOU0ahdg82Ls-Vg_NaWKas8MhahHspz18Gx2abDSwLIKbU0jcaf0LxWZkEuMmFJs5dodq0ZqQeaEldDsHe9De_V_TQwPFkcMOPYqWhx2XEb13bmFTPtxNST18Cwm_j263Y_Ouz2YNyC4uZENZDWeOXfJLy7c8jt_ToOvXEVpXj7oZN7Ik1S9bGAenTcvUDORP-gdFdJ3stLe9FmKulOlb94Y-KvP_meyIZ7Q.XPPqS5YVJu2utJcAIRTUxlBHlECGRaM5";

            //when
            string json = JoseRT.Jwt.Decode(token, aes192Key);

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1392553211,""sub"":""alice"",""nbf"":1392552611,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""586dd129-a29f-49c8-9de7-454af1155e27"",""iat"":1392552611}");
        }

        [TestMethod]
        public void Decrypt_A256KW_A256CBC_HS512()
        {
            //given
            string token = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0.91z9VM1VLIA_qyTbqeInFoit7c4PWVuQ5mHcDyNsfofDGXS1qUDdPCWRdLC8ybvJflqHej7SCjEUMxuzOtPOUOgo-8rcdeHi.rsx7FYNTunzditC8XTMJXg.k88BLb0qs8g0UnKjSq9rs2PcrhpafEaUEX2kT-wMdmviZ9UEJrECoQY7MmJgCyQYO30hnnay2psJcr_yaDhV-NpctBZ793Xf9tztLZZndIjz5omV9HjcFgheQZj4g1tbNcRLwxod5uYz-OLrKORzeROEM-wkLgHVEqs90wN98NAiyhGyVMw7CXVX5NdU2KFUacbflkJc5AcaiAZYAts1t9bo2877XLYSO1qBoI5k5QKv6ijjM8I03Uyr3H0p0tdF6EB-cdYNcxq68GvA5CTkOw.DBtOuSJTFu5AAIdcgymUR-JflpwfcXJ2AnZU8LNB3UA";

            //when
            string json = JoseRT.Jwt.Decode(token, aes256Key);

            //then
            Debug.WriteLine("json = {0}", json);

            Assert.AreEqual(json, @"{""exp"":1392553211,""sub"":""alice"",""nbf"":1392552611,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""586dd129-a29f-49c8-9de7-454af1155e27"",""iat"":1392552611}");
        }

        [TestMethod]
        public void Encrypt_A128KW_A128CBC_HS256()
        {
            //given
            string json =
                @"{""exp"":1389189552,""sub"":""alice"",""nbf"":1389188952,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""e543edf6-edf0-4348-8940-c4e28614d463"",""iat"":1389188952}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.A128KW, JweAlgorithms.A128CBC_HS256, aes128Key);

            //then
            Debug.WriteLine("A128KW_A128CBC_HS256 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiQTEyOEtXIn0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 54, "CEK size");
            Assert.AreEqual(parts[2].Length, 22, "IV size");
            Assert.AreEqual(parts[3].Length, 278, "cipher text size");
            Assert.AreEqual(parts[4].Length, 22, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, aes128Key), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Encrypt_A192KW_A192CBC_HS384()
        {
            //given
            string json =
                @"{""exp"":1389189552,""sub"":""alice"",""nbf"":1389188952,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""e543edf6-edf0-4348-8940-c4e28614d463"",""iat"":1389188952}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.A192KW, JweAlgorithms.A192CBC_HS384, aes192Key);

            //then
            Debug.WriteLine("A192KW_A192CBC_HS384 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMTkyQ0JDLUhTMzg0IiwiYWxnIjoiQTE5MktXIn0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 75, "CEK size");
            Assert.AreEqual(parts[2].Length, 22, "IV size");
            Assert.AreEqual(parts[3].Length, 278, "cipher text size");
            Assert.AreEqual(parts[4].Length, 32, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, aes192Key), json, "Make sure we are consistent with ourselfs");
        }

        [TestMethod]
        public void Encrypt_A256KW_A256CBC_HS512()
        {
            //given
            string json =
                @"{""exp"":1389189552,""sub"":""alice"",""nbf"":1389188952,""aud"":[""https:\/\/app-one.com"",""https:\/\/app-two.com""],""iss"":""https:\/\/openid.net"",""jti"":""e543edf6-edf0-4348-8940-c4e28614d463"",""iat"":1389188952}";

            //when
            string token = JoseRT.Jwt.Encode(json, JwaAlgorithms.A256KW, JweAlgorithms.A256CBC_HS512, aes256Key);

            //then
            Debug.WriteLine("A256KW_A256CBC_HS512 = {0}", token);

            string[] parts = token.Split('.');

            Assert.AreEqual(parts.Length, 5, "Make sure 5 parts");
            Assert.AreEqual(parts[0], "eyJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYWxnIjoiQTI1NktXIn0", "Header is non-encrypted and static text");
            Assert.AreEqual(parts[1].Length, 96, "CEK size");
            Assert.AreEqual(parts[2].Length, 22, "IV size");
            Assert.AreEqual(parts[3].Length, 278, "cipher text size");
            Assert.AreEqual(parts[4].Length, 43, "auth tag size");

            Assert.AreEqual(JoseRT.Jwt.Decode(token, aes256Key), json, "Make sure we are consistent with ourselfs");
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