using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using JoseRT.Serialization;
using JoseRT.Util;
using Buffer = JoseRT.Util.Buffer;

namespace JoseRT.Jwe
{
    public sealed class AesGcmEncryptor : IJweEncryptor
    {
        private uint keySizeBits;

        public AesGcmEncryptor(uint keySizeBits)
        {
            this.keySizeBits = keySizeBits;
        }

        public Part[] Encrypt([ReadOnlyArray] byte[] aad, [ReadOnlyArray] byte[] plainText, [ReadOnlyArray] byte[] cek)
        {
            Ensure.BitSize(cek, keySizeBits, string.Format("AesGcmEncryptor expected key of size {0} bits, but was given {1} bits", keySizeBits, cek.Length * 8));

            IBuffer iv = CryptographicBuffer.GenerateRandom(12);

            SymmetricKeyAlgorithmProvider alg = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesGcm);

            CryptographicKey key = alg.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(cek));

            EncryptedAndAuthenticatedData eaad = CryptographicEngine.EncryptAndAuthenticate(key,
                                                                CryptographicBuffer.CreateFromByteArray(plainText),iv,CryptographicBuffer.CreateFromByteArray(aad));

            return new[] { new Part(Buffer.ToBytes(iv)), new Part(Buffer.ToBytes(eaad.EncryptedData)), new Part(Buffer.ToBytes(eaad.AuthenticationTag)) };
        }

        public byte[] Decrypt([ReadOnlyArray] byte[] aad, [ReadOnlyArray] byte[] cek, [ReadOnlyArray] byte[] iv, [ReadOnlyArray] byte[] cipherText, [ReadOnlyArray] byte[] authTag)
        {
            Ensure.BitSize(cek, keySizeBits, string.Format("AesGcmEncryptor expected key of size {0} bits, but was given {1} bits", keySizeBits, cek.Length * 8));

            SymmetricKeyAlgorithmProvider alg = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesGcm);

            CryptographicKey key = alg.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(cek));

            return Buffer.ToBytes(
                    CryptographicEngine.DecryptAndAuthenticate(key, 
                                                               CryptographicBuffer.CreateFromByteArray(cipherText), 
                                                               CryptographicBuffer.CreateFromByteArray(iv),
                                                               CryptographicBuffer.CreateFromByteArray(authTag),
                                                               CryptographicBuffer.CreateFromByteArray(aad)));
        }

        public uint KeySize
        {
            get { return keySizeBits; }
        }

        public string Name
        {
            get
            {
                switch (keySizeBits)
                {
                    case 128: return JweAlgorithms.A128GCM;
                    case 192: return JweAlgorithms.A192GCM;
                    default: return JweAlgorithms.A256GCM;
                }
            }
        }
    }
}