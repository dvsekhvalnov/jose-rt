using System;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using Windows.Data.Json;
using Windows.Security.Cryptography.Core;
using JoseRT.crypto;
using JoseRT.Serialization;
using JoseRT.Util;

namespace JoseRT.Jwa
{
    public sealed class Pbse2HmacShaWithAesKWKeyManagement : IJwaAlgorithm
    {
        private int keySizeBits;

        public Pbse2HmacShaWithAesKWKeyManagement(int keySizeBits)
        {
            this.keySizeBits = keySizeBits;
        }

        public Part[] WrapNewKey(uint cekSizeBits, object key, JsonObject header)
        {
            throw new System.NotImplementedException();
        }

        public byte[] Unwrap([ReadOnlyArray] byte[] encryptedCek, object key, uint cekSizeBits, JsonObject header)
        {
            var sharedPassphrase = Ensure.Type<string>(key, "Pbse2HmacShaWithAesKWKeyManagement management algorithm expectes key to be string.");

            byte[] sharedKey = Encoding.UTF8.GetBytes(sharedPassphrase);

//            Ensure.Contains(header, new[] { "p2c" }, "Pbse2HmacShaWithAesKWKeyManagement algorithm expects 'p2c' param in JWT header, but was not found");
//            Ensure.Contains(header, new[] { "p2s" }, "Pbse2HmacShaWithAesKWKeyManagement algorithm expects 'p2s' param in JWT header, but was not found");

            byte[] algId = Encoding.UTF8.GetBytes(header["alg"].GetString());
            int iterationCount = (int)header["p2c"].GetNumber();
            byte[] saltInput = Base64Url.Decode(header["p2s"].GetString());

            byte[] salt = Arrays.Concat(algId, Arrays.Zero, saltInput);

            byte[] kek;

            kek = PBKDF2.DeriveKey(sharedKey, salt, iterationCount, keySizeBits, Prf);

            throw new System.NotImplementedException();
          //  return aesKW.Unwrap(encryptedCek, kek, cekSizeBits, header);
            
        }

        private MacAlgorithmProvider Prf 
        {
            get
            {
                switch (keySizeBits)
                {
                    case 128: return MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);
                    case 192: return MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha384);
                    default: return MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha512);
                } 
            }
        }

        public string Name
        {
            get
            {
                throw new NotImplementedException();
//                switch (keySizeBits)
//                {
//                    case 128: return JwaAlgorithms.PBES2_HS256_A128KW;
//                    case 192: return JwaAlgorithms.PBES2_HS384_A192KW;
//                    default: return JwaAlgorithms.PBES2_HS512_A256KW;
//                }
            }

        }
    }
}