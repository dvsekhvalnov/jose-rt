using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace JoseRT.Jws
{
    public sealed class HmacUsingSha : IJwsSigner
    {
        private int keySizeBits;

        public HmacUsingSha(int keySizeBits)
        {
            this.keySizeBits = keySizeBits;
        }

        public byte[] Sign([ReadOnlyArray] byte[] securedInput, object key)
        {
            byte[] sharedKey = (byte[])key;

            CryptographicKey hmacKey = AlgProvider.CreateKey(CryptographicBuffer.CreateFromByteArray(sharedKey));            

            IBuffer sig = CryptographicEngine.Sign(hmacKey, CryptographicBuffer.CreateFromByteArray(securedInput));

            byte[] signature;

            CryptographicBuffer.CopyToByteArray(sig, out signature);

            return signature;
        }

        public bool Verify([ReadOnlyArray] byte[] signature, [ReadOnlyArray] byte[] securedInput, object key)
        {
            byte[] sharedKey = (byte[]) key;

            IBuffer msg=CryptographicBuffer.CreateFromByteArray(securedInput);
            IBuffer hmac=CryptographicBuffer.CreateFromByteArray(signature);

            CryptographicKey hmacKey=AlgProvider.CreateKey(CryptographicBuffer.CreateFromByteArray(sharedKey));

            return CryptographicEngine.VerifySignature(hmacKey, msg, hmac);
        }

        public string Name
        {
            get
            {
                switch (keySizeBits)
                {
                    case 256: return JwsAlgorithm.HS256;
                    case 384: return JwsAlgorithm.HS384;
                    default: return JwsAlgorithm.HS512;
                }
            }            
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