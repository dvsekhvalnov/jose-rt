using System;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using Windows.Data.Json;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using JoseRT.crypto;
using JoseRT.Serialization;
using JoseRT.Util;
using Buffer = JoseRT.Util.Buffer;

namespace JoseRT.Jwa
{
    public sealed class Pbse2HmacShaWithAesKWKeyManagement : IJwaAlgorithm
    {
        private int keySizeBits;

        private AesKeyWrapManagement aesKW;

        public Pbse2HmacShaWithAesKWKeyManagement(int keySizeBits, AesKeyWrapManagement aesKw)
        {
            this.keySizeBits = keySizeBits;
            aesKW = aesKw;
        }

        public Part[] WrapNewKey(uint cekSizeBits, object key, JsonObject header)
        {
            var sharedPassphrase = Ensure.Type<string>(key, "Pbse2HmacShaWithAesKWKeyManagement management algorithm expectes key to be string.");

            byte[] sharedKey = Encoding.UTF8.GetBytes(sharedPassphrase);
            byte[] algId = Encoding.UTF8.GetBytes(header["alg"].GetString());

            const int iterationCount = 8192;
            
            var saltInput = Buffer.ToBytes(CryptographicBuffer.GenerateRandom(12));

            header["p2c"] = JsonValue.CreateNumberValue(iterationCount);
            header["p2s"] = JsonValue.CreateStringValue(Base64Url.Encode(saltInput));

            byte[] salt = Arrays.Concat(algId, Arrays.Zero, saltInput);

            byte[] kek=PBKDF2.DeriveKey(sharedKey, salt, iterationCount, keySizeBits, Prf);
            
            return aesKW.WrapNewKey(cekSizeBits, kek, header);
        }

        public byte[] Unwrap([ReadOnlyArray] byte[] encryptedCek, object key, uint cekSizeBits, JsonObject header)
        {
            var sharedPassphrase = Ensure.Type<string>(key, "Pbse2HmacShaWithAesKWKeyManagement management algorithm expectes key to be string.");

            byte[] sharedKey = Encoding.UTF8.GetBytes(sharedPassphrase);

            Ensure.Contains(header, "p2c", "Pbse2HmacShaWithAesKWKeyManagement algorithm expects 'p2c' param in JWT header, but was not found");
            Ensure.Contains(header, "p2s", "Pbse2HmacShaWithAesKWKeyManagement algorithm expects 'p2s' param in JWT header, but was not found");

            byte[] algId = Encoding.UTF8.GetBytes(header["alg"].GetString());
            int iterationCount = (int)header["p2c"].GetNumber();
            byte[] saltInput = Base64Url.Decode(header["p2s"].GetString());

            byte[] salt = Arrays.Concat(algId, Arrays.Zero, saltInput);

            byte[] kek = PBKDF2.DeriveKey(sharedKey, salt, iterationCount, keySizeBits, Prf);
          
            return aesKW.Unwrap(encryptedCek, kek, cekSizeBits, header);            
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
                switch (keySizeBits)
                {
                    case 128: return JwaAlgorithms.PBES2_HS256_A128KW;
                    case 192: return JwaAlgorithms.PBES2_HS384_A192KW;
                    default: return JwaAlgorithms.PBES2_HS512_A256KW;
                }
            }

        }
    }
}