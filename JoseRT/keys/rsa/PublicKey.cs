using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace JoseRT.Rsa
{
    public sealed class PublicKey
    {
        public static CryptographicKey Load(string pubKeyContent)
        {
            AsymmetricKeyAlgorithmProvider alg = AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaPkcs1);

            IBuffer keyBlob = CryptographicBuffer.DecodeFromBase64String(pubKeyContent);

            return alg.ImportPublicKey(keyBlob, CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo);
        }
    }
}