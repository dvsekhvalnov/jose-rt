using System;
using System.Diagnostics;
using JoseRT.keys.pem;
using JoseRT.util;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;

namespace Win8Tests
{
    [TestClass]
    public class PemTest
    {
        private string PEM_ENCODED = @"

-----BEGIN CERTIFICATE-----
MIIBjTCB9wIEchk3tjANBgkqhkiG9w0BAQUFADAOMQwwCgYDVQQDEwNqd3QwHhcN
MTQwMTA4MTM0NDUxWhcNMTUwMjA3MjAwMDAwWjAOMQwwCgYDVQQDEwNqd3QwgZ8w
DQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALx97GSHCGkevvUSsXMscNd+08MjO8Bb
krzzlDuokJzVvQQprSEFYCO1ojp1UheAImeQvMe1wAWrGNfbFw34jQCSkv8liWLh
5aHqHPrU8DTgKsL+XjHGaMwsg8y68pEmZrpyV/N49yXKlh3C1PLnFJrTmZq0PHLq
OXINNvMWFv7jAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAJcAJ4zK0ZZLUHRdxhQdj
e0Xv7fPYosE7gV0apbPJXnuhU1XH4XKFQQNYWyxjwfFSjghAyyZqlfcWgl0STOXx
JnFfEbSQL1EB5xKj9e1taMd+84mFXkVNvhN3wphe3EbPr9M99BRLic/MSGAqnJRS
OPIdhqg16dZmPJ4kCG8lLmc=
-----END CERTIFICATE-----

";

        private string RAW = @"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqFZv0pea/jn5Mo4qEUmS
tuhlulso8n1inXbEotd/zTrQp9K0RK0hf7t0K4BjKVhaiqIam4tVVQvkmYeBeYr1
MmnO/0N97dMBz/7fmvyv0hgHaBdQ5mR5u3LTlHo8tjRE7+GzZmGs6jMcyj7HbXob
DPQJZpqNy6JjliDVXxW8nWJDetxGBlqmTj1E1fr2RCsZLreDOPSDIedG1upz9Rra
ShsIDzeefOcKibcAaKeeVI3rkAU8/mOauLSXv37hlk0h6sStJb3qZQXyOUkVkjXI
khvNu/ve0v7LiLT4G/OxYGzpOQcCnimKdojzNP6GtVDaMPh+QkSJE32UCos9R3wI
2QIDAQAB";

        [TestMethod]
        public void NewPem()
        {
            //when
            var test = new Pem(PEM_ENCODED);

            Debug.WriteLine(test.Decoded);
            Debug.WriteLine(test.Type);

            Debug.WriteLine(Arrays.Dump(test.Decoded));

            //then
            Assert.AreEqual("CERTIFICATE",test.Type);
            CollectionAssert.AreEqual(new byte[] { 48, 130, 1, 141, 48, 129, 247, 2, 4, 114, 25, 55, 182, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 5, 5, 0, 48, 14, 49, 12, 48, 10, 6, 3, 85, 4, 3, 19, 3, 106, 119, 116, 48, 30, 23, 13, 49, 52, 48, 49, 48, 56, 49, 51, 52, 52, 53, 49, 90, 23, 13, 49, 53, 48, 50, 48, 55, 50, 48, 48, 48, 48, 48, 90, 48, 14, 49, 12, 48, 10, 6, 3, 85, 4, 3, 19, 3, 106, 119, 116, 48, 129, 159, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 129, 141, 0, 48, 129, 137, 2, 129, 129, 0, 188, 125, 236, 100, 135, 8, 105, 30, 190, 245, 18, 177, 115, 44, 112, 215, 126, 211, 195, 35, 59, 192, 91, 146, 188, 243, 148, 59, 168, 144, 156, 213, 189, 4, 41, 173, 33, 5, 96, 35, 181, 162, 58, 117, 82, 23, 128, 34, 103, 144, 188, 199, 181, 192, 5, 171, 24, 215, 219, 23, 13, 248, 141, 0, 146, 146, 255, 37, 137, 98, 225, 229, 161, 234, 28, 250, 212, 240, 52, 224, 42, 194, 254, 94, 49, 198, 104, 204, 44, 131, 204, 186, 242, 145, 38, 102, 186, 114, 87, 243, 120, 247, 37, 202, 150, 29, 194, 212, 242, 231, 20, 154, 211, 153, 154, 180, 60, 114, 234, 57, 114, 13, 54, 243, 22, 22, 254, 227, 2, 3, 1, 0, 1, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 5, 5, 0, 3, 129, 129, 0, 37, 192, 9, 227, 50, 180, 101, 146, 212, 29, 23, 113, 133, 7, 99, 123, 69, 239, 237, 243, 216, 162, 193, 59, 129, 93, 26, 165, 179, 201, 94, 123, 161, 83, 85, 199, 225, 114, 133, 65, 3, 88, 91, 44, 99, 193, 241, 82, 142, 8, 64, 203, 38, 106, 149, 247, 22, 130, 93, 18, 76, 229, 241, 38, 113, 95, 17, 180, 144, 47, 81, 1, 231, 18, 163, 245, 237, 109, 104, 199, 126, 243, 137, 133, 94, 69, 77, 190, 19, 119, 194, 152, 94, 220, 70, 207, 175, 211, 61, 244, 20, 75, 137, 207, 204, 72, 96, 42, 156, 148, 82, 56, 242, 29, 134, 168, 53, 233, 214, 102, 60, 158, 36, 8, 111, 37, 46, 103 }, test.Decoded);
        }

        [TestMethod]
        public void NewNonPemEncoded()
        {
            //when
            var test = new Pem(RAW);

            Debug.WriteLine(test.Decoded);
            Debug.WriteLine(test.Type);

            Debug.WriteLine(Arrays.Dump(test.Decoded));

            //then
            Assert.IsNull(test.Type);
            CollectionAssert.AreEqual(new byte[] { 48, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1, 15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 168, 86, 111, 210, 151, 154, 254, 57, 249, 50, 142, 42, 17, 73, 146, 182, 232, 101, 186, 91, 40, 242, 125, 98, 157, 118, 196, 162, 215, 127, 205, 58, 208, 167, 210, 180, 68, 173, 33, 127, 187, 116, 43, 128, 99, 41, 88, 90, 138, 162, 26, 155, 139, 85, 85, 11, 228, 153, 135, 129, 121, 138, 245, 50, 105, 206, 255, 67, 125, 237, 211, 1, 207, 254, 223, 154, 252, 175, 210, 24, 7, 104, 23, 80, 230, 100, 121, 187, 114, 211, 148, 122, 60, 182, 52, 68, 239, 225, 179, 102, 97, 172, 234, 51, 28, 202, 62, 199, 109, 122, 27, 12, 244, 9, 102, 154, 141, 203, 162, 99, 150, 32, 213, 95, 21, 188, 157, 98, 67, 122, 220, 70, 6, 90, 166, 78, 61, 68, 213, 250, 246, 68, 43, 25, 46, 183, 131, 56, 244, 131, 33, 231, 70, 214, 234, 115, 245, 26, 218, 74, 27, 8, 15, 55, 158, 124, 231, 10, 137, 183, 0, 104, 167, 158, 84, 141, 235, 144, 5, 60, 254, 99, 154, 184, 180, 151, 191, 126, 225, 150, 77, 33, 234, 196, 173, 37, 189, 234, 101, 5, 242, 57, 73, 21, 146, 53, 200, 146, 27, 205, 187, 251, 222, 210, 254, 203, 136, 180, 248, 27, 243, 177, 96, 108, 233, 57, 7, 2, 158, 41, 138, 118, 136, 243, 52, 254, 134, 181, 80, 218, 48, 248, 126, 66, 68, 137, 19, 125, 148, 10, 139, 61, 71, 124, 8, 217, 2, 3, 1, 0, 1 }, test.Decoded);
        }


    }
}