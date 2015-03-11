using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Data.Json;
using Windows.Security.Cryptography;
using JoseRT.crypto;
using JoseRT.Serialization;
using JoseRT.Util;

namespace JoseRT.Jwa
{
    public sealed class AesKeyWrapManagement: IJwaAlgorithm
    {
        private readonly uint kekSizeBits;

        public AesKeyWrapManagement(uint kekSizeBits)
        {
            this.kekSizeBits = kekSizeBits;
        }

        public Part[] WrapNewKey(uint cekSizeBits, object key, JsonObject header)
        {
            var sharedKey = Ensure.Type<byte[]>(key, "AesKeyWrap management algorithm expectes key to be byte[] array.");
            Ensure.BitSize(sharedKey, kekSizeBits, string.Format("AesKeyWrap management algorithm expected key of size {0} bits, but was given {1} bits", kekSizeBits, sharedKey.Length * 8));

            var cek = Buffer.ToBytes(CryptographicBuffer.GenerateRandom(cekSizeBits >> 3));

            var encryptedCek = AesKeyWrap.Wrap(cek, sharedKey);

            return new[] { new Part(cek), new Part(encryptedCek),};
        }

        public byte[] Unwrap([ReadOnlyArray] byte[] encryptedCek, object key, uint cekSizeBits, JsonObject header)
        {
            var sharedKey = Ensure.Type<byte[]>(key, "AesKeyWrap management algorithm expectes key to be byte[] array.");
            Ensure.BitSize(sharedKey, kekSizeBits, string.Format("AesKeyWrap management algorithm expected key of size {0} bits, but was given {1} bits", kekSizeBits, sharedKey.Length * 8));

            return AesKeyWrap.Unwrap(encryptedCek, sharedKey);
        }

        public string Name
        {
            get
            {
                switch (kekSizeBits)
                {
                    case 128: return JwaAlgorithms.A128KW;
                    case 192: return JwaAlgorithms.A192KW;
                    default: return JwaAlgorithms.A256KW;
                }
            }
        }
    }
}