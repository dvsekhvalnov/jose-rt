using System;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using JoseRT.Serialization;
using JoseRT.util;
using Buffer = JoseRT.util.Buffer;

namespace JoseRT.Jwe
{
    public sealed class AesCbcHmacEncryptor : IJweEncryptor
    {
        private int keySizeBits;

        public AesCbcHmacEncryptor(int keySizeBits)
        {
            this.keySizeBits = keySizeBits;
        }

        public Part[] Encrypt([ReadOnlyArray] byte[] aad, [ReadOnlyArray] byte[] plainText, [ReadOnlyArray] byte[] cek)
        {
            Ensure.BitSize(cek, keySizeBits, string.Format("AesCbcHmacEncryptor expected key of size {0} bits, but was given {1} bits", keySizeBits, cek.Length * 8));

            byte[] hmacKey = Arrays.FirstHalf(cek);
            byte[] aesKey = Arrays.SecondHalf(cek);
            
            IBuffer iv = CryptographicBuffer.GenerateRandom(16);

            SymmetricKeyAlgorithmProvider alg = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);

            CryptographicKey key = alg.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(aesKey));

            byte[] cipherText=Buffer.ToBytes(CryptographicEngine.Encrypt(key, CryptographicBuffer.CreateFromByteArray(plainText), iv));

            byte[] authTag = ComputeAuthTag(aad, Buffer.ToBytes(iv), cipherText, hmacKey);

            return new[] { new Part(Buffer.ToBytes(iv)), new Part(cipherText), new Part(authTag) };
        }

        public byte[] Decrypt([ReadOnlyArray] byte[] aad, [ReadOnlyArray] byte[] cek, [ReadOnlyArray] byte[] iv, [ReadOnlyArray] byte[] cipherText, [ReadOnlyArray] byte[] authTag)
        {
            Ensure.BitSize(cek, keySizeBits, string.Format("AesCbcHmacEncryptor expected key of size {0} bits, but was given {1} bits", keySizeBits, cek.Length * 8));

            byte[] hmacKey = Arrays.FirstHalf(cek);
            byte[] aesKey = Arrays.SecondHalf(cek);

            byte[] expectedAuthTag = ComputeAuthTag(aad, iv, cipherText, hmacKey);

            if (!Arrays.ConstantTimeEquals(expectedAuthTag, authTag))
            {
                throw new Exception("Authentication tag do not match.");
            }

            SymmetricKeyAlgorithmProvider alg = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);

            CryptographicKey key = alg.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(aesKey));

            return Buffer.ToBytes(
                    CryptographicEngine.Decrypt(key, CryptographicBuffer.CreateFromByteArray(cipherText), CryptographicBuffer.CreateFromByteArray(iv)));
        }

        public int KeySize
        {
            get { return keySizeBits; }
        }

        public string Name
        {
            get
            {
                switch (keySizeBits)
                {
                    case 256: return JweAlgorithms.A128CBC_HS256;
                    case 384: return JweAlgorithms.A192CBC_HS384;
                    default: return JweAlgorithms.A256CBC_HS512;
                }
            }
        }

        private byte[] ComputeAuthTag(byte[] aad, byte[] iv, byte[] cipherText, byte[] key)
        {
            byte[] al = Arrays.LongToBytes(aad.Length * 8);
            byte[] hmacInput = Arrays.Concat(aad, iv, cipherText, al);


            CryptographicKey hmacKey = AlgProvider.CreateKey(CryptographicBuffer.CreateFromByteArray(key));

            return Arrays.FirstHalf(
                    Buffer.ToBytes(CryptographicEngine.Sign(hmacKey, CryptographicBuffer.CreateFromByteArray(hmacInput))));
        }

        private MacAlgorithmProvider AlgProvider
        {
            get
            {
                switch (keySizeBits)
                {
                    case 256: return MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);
                    case 384: return MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha384);
                    default: return MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha512);
                }
            }
        }

    }
}