using System;
using System.Diagnostics;
using Windows.Security.Cryptography.Core;
using JoseRT.Rsa;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using Buffer = JoseRT.util.Buffer;

namespace Win8Tests
{
    [TestClass]
    public class PrivateKeyTests
    {
        private const string PemPrivKey =
@"-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALx97GSHCGkevvUS
sXMscNd+08MjO8BbkrzzlDuokJzVvQQprSEFYCO1ojp1UheAImeQvMe1wAWrGNfb
Fw34jQCSkv8liWLh5aHqHPrU8DTgKsL+XjHGaMwsg8y68pEmZrpyV/N49yXKlh3C
1PLnFJrTmZq0PHLqOXINNvMWFv7jAgMBAAECgYEAsYc0RzY7AK7ZkX7KrLw1h3FH
R2n+09wrp1UOzuWjVmOkw6/xBMHIW7mtkrt+1u1y+fIDK2GN+oi8PEl4PEtVmI8L
jaExLu5fsp/Z+BbHfcs4L5So9pdGZn5Dhfh606LWRZ0qqSjdtXitpNMrjx736+Jt
J6/kHlCdmYDyThtljbECQQDoDDAznyi6Yl2T+taoi2VcCP7wFAIYf3Mu6nqiEBhc
p1lVOuWjyR+mBU8+o6hDs40oVAOdpCdqtDJ3ppWABKKZAkEAz/LIq8Uwq8ephNwn
WOSuhkjUz+O01v74GHyS6tc7WGckFR7JS1cughXlRRq7hD1z1dhTYq0W2g4Yrujf
GFTW2wJBAIwtQLkOfqYJYgpQz3fFrZdpf8g77gAqjcRbtXVNT8o49gg8qhjFGK9M
KdDnQHCVeMJR7lU+oukcrhgFs+4/3pECQBcvX5ZfPwT4Fvt8PFrZ7GeGeUvQfJo4
BVtdkFfktXYu0cQVEaZ3yvSwEkb5Kw0ceOzP2MQ4vkKDrdbamf0xgF8CQFiz2P8h
Vq/Q3fFKCWamZ1olx08zo4x4y2kYKO275GSZabhiVoulVhUtRgi9BcPfW9kakqps
wEe4//EeSbl38Bk=
-----END PRIVATE KEY-----
";

        private const string PemRsaPrivKey =
@"-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC8fexkhwhpHr71ErFzLHDXftPDIzvAW5K885Q7qJCc1b0EKa0h
BWAjtaI6dVIXgCJnkLzHtcAFqxjX2xcN+I0AkpL/JYli4eWh6hz61PA04CrC/l4x
xmjMLIPMuvKRJma6clfzePclypYdwtTy5xSa05matDxy6jlyDTbzFhb+4wIDAQAB
AoGBALGHNEc2OwCu2ZF+yqy8NYdxR0dp/tPcK6dVDs7lo1ZjpMOv8QTByFu5rZK7
ftbtcvnyAythjfqIvDxJeDxLVZiPC42hMS7uX7Kf2fgWx33LOC+UqPaXRmZ+Q4X4
etOi1kWdKqko3bV4raTTK48e9+vibSev5B5QnZmA8k4bZY2xAkEA6AwwM58oumJd
k/rWqItlXAj+8BQCGH9zLup6ohAYXKdZVTrlo8kfpgVPPqOoQ7ONKFQDnaQnarQy
d6aVgASimQJBAM/yyKvFMKvHqYTcJ1jkroZI1M/jtNb++Bh8kurXO1hnJBUeyUtX
LoIV5UUau4Q9c9XYU2KtFtoOGK7o3xhU1tsCQQCMLUC5Dn6mCWIKUM93xa2XaX/I
O+4AKo3EW7V1TU/KOPYIPKoYxRivTCnQ50BwlXjCUe5VPqLpHK4YBbPuP96RAkAX
L1+WXz8E+Bb7fDxa2exnhnlL0HyaOAVbXZBX5LV2LtHEFRGmd8r0sBJG+SsNHHjs
z9jEOL5Cg63W2pn9MYBfAkBYs9j/IVav0N3xSglmpmdaJcdPM6OMeMtpGCjtu+Rk
mWm4YlaLpVYVLUYIvQXD31vZGpKqbMBHuP/xHkm5d/AZ
-----END RSA PRIVATE KEY-----";

        private const string privKeyRaw = "MIICXAIBAAKBgQC8fexkhwhpHr71ErFzLHDXftPDIzvAW5K885Q7qJCc1b0EKa0hBWAjtaI6dVIXgCJnkLzHtcAFqxjX2xcN+I0AkpL/JYli4eWh6hz61PA04CrC/l4xxmjMLIPMuvKRJma6clfzePclypYdwtTy5xSa05matDxy6jlyDTbzFhb+4wIDAQABAoGAFHOZ83BeqRU6b+82zMHXfoeWz3dNCOUxXzS98oPVflwx6uKLaT1Nk0z7t1m6bgKro6QQhPTDSyTSMxLlBfw1btjliGa8/FyYsZwfpWaHYk0DaDX+OuQtwGoA5qdxdcRiEsEsGrYAAcacjR6YwoUE67CSGe9Kx8a6TmtmugfySSkCQQDoDDAznyi6Yl2T+taoi2VcCP7wFAIYf3Mu6nqiEBhcp1lVOuWjyR+mBU8+o6hDs40oVAOdpCdqtDJ3ppWABKKZAkEAz/LIq8Uwq8ephNwnWOSuhkjUz+O01v74GHyS6tc7WGckFR7JS1cughXlRRq7hD1z1dhTYq0W2g4YrujfGFTW2wJBAIwtQLkOfqYJYgpQz3fFrZdpf8g77gAqjcRbtXVNT8o49gg8qhjFGK9MKdDnQHCVeMJR7lU+oukcrhgFs+4/3pECQBcvX5ZfPwT4Fvt8PFrZ7GeGeUvQfJo4BVtdkFfktXYu0cQVEaZ3yvSwEkb5Kw0ceOzP2MQ4vkKDrdbamf0xgF8CQFiz2P8hVq/Q3fFKCWamZ1olx08zo4x4y2kYKO275GSZabhiVoulVhUtRgi9BcPfW9kakqpswEe4//EeSbl38Bk=";

        [TestMethod]
        public void LoadPrivKeyPemEncoded()
        {
            //when
            var test = PrivateKey.Load(PemPrivKey);
            var roundtrip = Convert.ToBase64String(Buffer.ToBytes(test.Export(CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey)));

            //then
            Assert.AreEqual((uint)1024, test.KeySize);
            Assert.AreEqual(privKeyRaw, roundtrip);
        }

        [TestMethod]
        public void LoadRsaPrivKeyPemEncoded()
        {
            //when
            var test = PrivateKey.Load(PemRsaPrivKey);
            var roundtrip = Convert.ToBase64String(Buffer.ToBytes(test.Export(CryptographicPrivateKeyBlobType.Pkcs1RsaPrivateKey)));

            Debug.WriteLine(roundtrip);

            //then
            Assert.AreEqual((uint)1024, test.KeySize);
            Assert.AreEqual(privKeyRaw,roundtrip);
        }
    }
}