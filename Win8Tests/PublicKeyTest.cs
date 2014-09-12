using System;
using Windows.Security.Cryptography.Core;
using JoseRT.Rsa;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using Buffer = JoseRT.util.Buffer;

namespace Win8Tests
{
    [TestClass]
    public class PublicKeyTest
    {
        private const string Pkcs1 = @"MIIBCgKCAQEAqFZv0pea/jn5Mo4qEUmStuhlulso8n1inXbEotd/zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO/0N97dMBz/7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu/ve0v7LiLT4G/OxYGzpOQcCnimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI2QIDAQAB";
        private const string X509Pki = @"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqFZv0pea/jn5Mo4qEUmStuhlulso8n1inXbEotd/zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1MmnO/0N97dMBz/7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXobDPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9RraShsIDzeefOcKibcAaKeeVI3rkAU8/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXIkhvNu/ve0v7LiLT4G/OxYGzpOQcCnimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI2QIDAQAB";

        private const string PemPubKey =
@"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqFZv0pea/jn5Mo4qEUmS
tuhlulso8n1inXbEotd/zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1
MmnO/0N97dMBz/7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXob
DPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9Rra
ShsIDzeefOcKibcAaKeeVI3rkAU8/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXI
khvNu/ve0v7LiLT4G/OxYGzpOQcCnimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI
2QIDAQAB
-----END PUBLIC KEY-----";

        private const string PemRsaPubKey =
@"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAqFZv0pea/jn5Mo4qEUmS
tuhlulso8n1inXbEotd/zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1
MmnO/0N97dMBz/7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXob
DPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9Rra
ShsIDzeefOcKibcAaKeeVI3rkAU8/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXI
khvNu/ve0v7LiLT4G/OxYGzpOQcCnimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI
2QIDAQAB
-----END RSA PUBLIC KEY-----";

        [TestMethod]
        public void LoadPubKeyPemEncoded()
        {          
            //when
            var test = PublicKey.Load(PemPubKey);
            var roundtrip = Convert.ToBase64String(Buffer.ToBytes(test.ExportPublicKey(CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey)));

            //then
            Assert.AreEqual((uint)2048,test.KeySize);
            Assert.AreEqual(Pkcs1, roundtrip);
        }

        [TestMethod]
        public void LoadRsaPubKeyPemEncoded()
        {
            //when
            var test = PublicKey.Load(PemRsaPubKey);
            var roundtrip = Convert.ToBase64String(Buffer.ToBytes(test.ExportPublicKey(CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey)));

            //then
            Assert.AreEqual((uint)2048, test.KeySize);
            Assert.AreEqual(Pkcs1, roundtrip);
        }

        [TestMethod]
        public void LoadPubKeyRaw()
        {
            //when
            var test = PublicKey.Load(Pkcs1);
            var roundtrip = Convert.ToBase64String(Buffer.ToBytes(test.ExportPublicKey(CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey)));
            //then
            Assert.AreEqual((uint)2048, test.KeySize);
            Assert.AreEqual(Pkcs1, roundtrip);
        }

        [TestMethod]
        public void LoadRsaPubKeyRaw()
        {
            //when
            var test = PublicKey.Load(X509Pki);
            var roundtrip=Convert.ToBase64String(Buffer.ToBytes(test.ExportPublicKey(CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey)));

            //then
            Assert.AreEqual((uint)2048, test.KeySize);
            Assert.AreEqual(Pkcs1, roundtrip);
        }
    }
}