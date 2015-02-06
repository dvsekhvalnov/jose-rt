using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Data.Json;
using JoseRT.Serialization;
using JoseRT.Util;

namespace JoseRT.Jwa
{
    public sealed class DirectKeyManagement : IJwaAlgorithm
    {
        public Part[] WrapNewKey(uint cekSizeBits, object key, JsonObject header)
        {
            return new[] {new Part(Ensure.Type<byte[]>(key, "DirectKeyManagement expectes key to be byte[] array.")), new Part(new byte[0])};
        }

        public byte[] Unwrap([ReadOnlyArray] byte[] encryptedCek, object key, uint cekSizeBits, JsonObject header)
        {
            Ensure.IsEmpty(encryptedCek, "DirectKeyManagement expects empty content encryption key");

            return Ensure.Type<byte[]>(key, "DirectKeyManagement expectes key to be byte[] array.");
        }

        public string Name
        {
            get { return JwaAlgorithms.DIR; }            
        }
    }
}