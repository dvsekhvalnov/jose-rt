using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Data.Json;
using JoseRT.Serialization;

namespace JoseRT.jwa
{
    public interface IJwaAlgorithm
    {
        /// <summary>
        /// Generates a new Content Encryption Key (CEK) and wraps it via provided management key (Key-Encryption-Key)
        /// </summary>
        /// <param name="cekSizeBits">Length of key to generate (CEK) (bits).</param>
        /// <param name="key">management key (KEK)</param>
        /// <param name="header">JWT headers, dictionary can be mutated as part of call (e.g. keys added, e.t.c)</param>
        /// <returns>2 Parts: [0]=plain CEK, [1]=encrypted CEK</returns>
        Part[] WrapNewKey(int cekSizeBits, object key, JsonObject header);

        /// <summary>
        /// Unwraps protected CEK using provided management key
        /// </summary>
        /// <param name="encryptedCek">wrapped (encrypted) CEK</param>
        /// <param name="key">management key (KEK) used to protected CEK</param>
        /// <param name="cekSizeBits">required unwrapped bit CEK size</param>
        /// <param name="header">JWT headers</param>
        /// <returns>unwapped (decrypted) CEK</returns>
        byte[] Unwrap([ReadOnlyArray] byte[] encryptedCek, object key, int cekSizeBits, JsonObject header);


        /// <summary>
        /// Returns algorithm name as defined in spec
        /// </summary>
        string Name { get; } 
 
    }
}