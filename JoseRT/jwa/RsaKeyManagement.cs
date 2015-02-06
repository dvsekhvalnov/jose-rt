using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Data.Json;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using JoseRT.Serialization;
using JoseRT.Util;
using Buffer = JoseRT.Util.Buffer;

namespace JoseRT.Jwa
{
    public sealed class RsaKeyManagement : IJwaAlgorithm
    {
        private bool useRsaOaepPadding; //true for RSA-OAEP, false for RSA-PKCS#1 v1.5
        private bool useSha256; //true for RSA-OAEP-256

        public RsaKeyManagement(bool useRsaOaepPadding, bool useSha256)
        {
            this.useRsaOaepPadding = useRsaOaepPadding;
            this.useSha256 = useSha256;
        }

        public Part[] WrapNewKey(uint cekSizeBits, object key, JsonObject header)
        {
            var publicKey = Ensure.Type<CryptographicKey>(key, "RsaUsingSha expects key to be of type 'CryptographicKey'");

            IBuffer cek = CryptographicBuffer.GenerateRandom(cekSizeBits >> 3);

            //reattach key to alg provider
            IBuffer keyBlob = publicKey.ExportPublicKey(CryptographicPublicKeyBlobType.BCryptPublicKey);

            CryptographicKey cKey = AlgProvider.ImportPublicKey(keyBlob, CryptographicPublicKeyBlobType.BCryptPublicKey);

            IBuffer encryptedCek = CryptographicEngine.Encrypt(cKey, cek, null);

            return new [] {new Part(Buffer.ToBytes(cek)), new Part(Buffer.ToBytes(encryptedCek))};
        }

        public byte[] Unwrap([ReadOnlyArray] byte[] encryptedCek, object key, uint cekSizeBits, JsonObject header)
        {
            var privateKey = Ensure.Type<CryptographicKey>(key, "RsaUsingSha expects key to be of type 'CryptographicKey'");

            IBuffer msg = CryptographicBuffer.CreateFromByteArray(encryptedCek);

            //reattach key to alg provider
            IBuffer keyBlob = privateKey.Export(CryptographicPrivateKeyBlobType.BCryptPrivateKey);

            CryptographicKey cKey = AlgProvider.ImportKeyPair(keyBlob, CryptographicPrivateKeyBlobType.BCryptPrivateKey);

            return Buffer.ToBytes(CryptographicEngine.Decrypt(cKey, msg, null));
        }

        private AsymmetricKeyAlgorithmProvider AlgProvider
        {
            get
            {
               if(!useRsaOaepPadding) return AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaPkcs1);

               if(useSha256) return AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaOaepSha256);

               return AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaOaepSha1);
            }
        }

        public string Name
        {
            get
            {
                if (!useRsaOaepPadding) return JwaAlgorithms.RSA1_5;

                if (useSha256) return JwaAlgorithms.RSA_OAEP_256;

                return JwaAlgorithms.RSA_OAEP;
            }
        }
    }
}