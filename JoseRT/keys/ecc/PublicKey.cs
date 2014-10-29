using System;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using JoseRT.util;

namespace JoseRT.Ecc
{
    public sealed class PublicKey
    {
        private static readonly byte[] BCRYPT_ECDSA_PUBLIC_P256_MAGIC = BitConverter.GetBytes(0x31534345);
        private static readonly byte[] BCRYPT_ECDSA_PUBLIC_P384_MAGIC = BitConverter.GetBytes(0x33534345);        
        private static readonly byte[] BCRYPT_ECDSA_PUBLIC_P521_MAGIC = BitConverter.GetBytes(0x35534345);

        public static CryptographicKey New([ReadOnlyArray] byte[] x, [ReadOnlyArray] byte[] y)
        {
            if (x.Length != y.Length)
                throw new ArgumentException("X and Y must be same size");

            int partSize = x.Length;

            byte[] magic;
            string alg;
            if (partSize == 32)
            {
                magic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
                alg = AsymmetricAlgorithmNames.EcdsaP256Sha256;
            }
            else if (partSize == 48)
            {
                magic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
                alg = AsymmetricAlgorithmNames.EcdsaP384Sha384;
            }
            else if (partSize == 66)
            {
                magic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
                alg = AsymmetricAlgorithmNames.EcdsaP521Sha512;
            }
            else
                throw new ArgumentException("Size of X,Y or D must equal to 32, 48 or 66 bytes");

            byte[] partLength = BitConverter.GetBytes(partSize);

            byte[] blob = Arrays.Concat(magic, partLength, x, y);

            return AsymmetricKeyAlgorithmProvider.OpenAlgorithm(alg)
                                                 .ImportPublicKey(CryptographicBuffer.CreateFromByteArray(blob), CryptographicPublicKeyBlobType.BCryptPublicKey);
        }
    }
}