using System;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using JoseRT.Util;
using Buffer = JoseRT.Util.Buffer;

namespace JoseRT.crypto
{
    public static class PBKDF2
    {
        /// <summary>
        /// Implements RFC2898 Password Based Key Derivation Function #2
        /// </summary>
        /// <param name="password">password to be used as hash key</param>
        /// <param name="salt">salt</param>
        /// <param name="iterationCount">number of iterations to perform</param>
        /// <param name="keyBitLength">desired key length in bits to detive</param>
        /// <param name="prf">Pseudo Random Function, HMAC will be inited with key equal to given password</param>
        /// <returns></returns>
        public static byte[] DeriveKey([ReadOnlyArray] byte[] password, [ReadOnlyArray] byte[] salt, int iterationCount, int keyBitLength, MacAlgorithmProvider prf)
        {            
            CryptographicKey key = prf.CreateKey(CryptographicBuffer.CreateFromByteArray(password));

            //  1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and stop.   
            Ensure.MaxValue(keyBitLength, 4294967295, "PBKDF2 expect derived key size to be not more that (2^32-1) bits, but was requested {0} bits.", keyBitLength);

            int hLen = (int) prf.MacLength; //size of mac in bytes
            int dkLen = keyBitLength >> 3; //size of derived key in bytes

            int l = (int)Math.Ceiling(dkLen / (double)hLen);  // l = CEIL (dkLen / hLen) ,
            int r = dkLen - (l - 1) * hLen;                   // r = dkLen - (l - 1) * hLen .

            byte[][] T = new byte[l][];

            for (int i = 0; i < l; i++)
            {
                T[i] = F(salt, iterationCount, i + 1, key);   // T_l = F (P, S, c, l)               
            }

            T[l - 1] = Arrays.LeftmostBits(T[l - 1], r * 8);  //truncate last block to r bits

            return Arrays.Concat(T);                          // DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
        }

        private static byte[] F(byte[] salt, int iterationCount, int blockIndex, CryptographicKey key)
        {
            
            byte[] U=Buffer.ToBytes(CryptographicEngine.Sign(key,
                        CryptographicBuffer.CreateFromByteArray(Arrays.Concat(salt, Arrays.IntToBytes(blockIndex))))); // U_1 = PRF (P, S || INT (i))

            //byte[] U = prf.ComputeHash(Arrays.Concat(salt, Arrays.IntToBytes(blockIndex))); // U_1 = PRF (P, S || INT (i))
            byte[] result = U;

            for (int i = 2; i <= iterationCount; i++)
            {
                U = Buffer.ToBytes(
                    CryptographicEngine.Sign(key, CryptographicBuffer.CreateFromByteArray(U))); // U_c = PRF (P, U_{c-1}) .                
                //U = prf.ComputeHash(U);                                                     // U_c = PRF (P, U_{c-1}) .                
                result = Arrays.Xor(result, U);                                             // U_1 \xor U_2 \xor ... \xor U_c
            }

            return result;
        }
    }
}