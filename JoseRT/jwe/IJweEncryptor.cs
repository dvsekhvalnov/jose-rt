using System.Runtime.InteropServices.WindowsRuntime;
using JoseRT.Serialization;

namespace JoseRT.Jwe
{
    public interface IJweEncryptor
    {
        /// <summary>
        /// Performs authenticate encryption of plaintext with CEK (content encryption key) using provided AAD (aditional authentication data)
        /// </summary>
        /// <param name="aad">additional authentication data</param>
        /// <param name="plainText">plaintext to encrypt</param>
        /// <param name="cek">content encryption key</param>
        /// <returns>3 parts: [0]=IV, [1]=cipher text, [2]=auth tag</returns>
        Part[] Encrypt([ReadOnlyArray] byte[] aad, [ReadOnlyArray] byte[] plainText, [ReadOnlyArray] byte[] cek);

        byte[] Decrypt([ReadOnlyArray] byte[] aad, [ReadOnlyArray] byte[] cek, [ReadOnlyArray] byte[] iv, [ReadOnlyArray] byte[] cipherText, [ReadOnlyArray] byte[] authTag);

        /// <summary>
        /// Returns expected key size for given encryption algorithm
        /// </summary>
        uint KeySize { get; }

        /// <summary>
        /// Returns encryption name as defined in spec
        /// </summary>
        string Name { get; } 
    }
}