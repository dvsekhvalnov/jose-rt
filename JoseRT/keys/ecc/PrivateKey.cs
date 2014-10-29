using System;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using JoseRT.Keys.pem;
using JoseRT.util;

namespace JoseRT.Ecc
{
    public sealed class PrivateKey
    {
        private static readonly byte[] BCRYPT_ECDSA_PRIVATE_P256_MAGIC = BitConverter.GetBytes(0x32534345);
        private static readonly byte[] BCRYPT_ECDSA_PRIVATE_P384_MAGIC = BitConverter.GetBytes(0x34534345);
        private static readonly byte[] BCRYPT_ECDSA_PRIVATE_P521_MAGIC = BitConverter.GetBytes(0x36534345);

        public static CryptographicKey New([ReadOnlyArray] byte[] x, [ReadOnlyArray] byte[] y, [ReadOnlyArray] byte[] d)
        {
            if (x.Length != y.Length)
                throw new ArgumentException("X, Y and Z must be same size");

            if (x.Length != d.Length)
                throw new ArgumentException("X and Y must be same size");

            int partSize = x.Length;

            byte[] magic;
            string alg;
            if (partSize == 32)
            {
                magic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
                alg = AsymmetricAlgorithmNames.EcdsaP256Sha256;
            }
            else if (partSize == 48)
            {
                magic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
                alg = AsymmetricAlgorithmNames.EcdsaP384Sha384;
            }
            else if (partSize == 66)
            {
                magic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
                alg = AsymmetricAlgorithmNames.EcdsaP521Sha512;
            }
            else
                throw new ArgumentException("Size of X,Y or D must equal to 32, 48 or 66 bytes");

            byte[] partLength = BitConverter.GetBytes(partSize);

            byte[] blob = Arrays.Concat(magic, partLength, x, y, d);

            return AsymmetricKeyAlgorithmProvider.OpenAlgorithm(alg)
                                                 .ImportKeyPair(CryptographicBuffer.CreateFromByteArray(blob), CryptographicPrivateKeyBlobType.BCryptPrivateKey);
        }
    }
}