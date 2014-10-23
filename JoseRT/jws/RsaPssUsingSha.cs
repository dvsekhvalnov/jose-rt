using System;
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using JoseRT.util;
using Buffer = JoseRT.util.Buffer;

namespace JoseRT.Jws
{
    public sealed class RsaPssUsingSha : IJwsSigner
    {
        private int keySizeBits;

        public RsaPssUsingSha(int keySizeBits)
        {
            this.keySizeBits = keySizeBits;
        }

        public byte[] Sign([ReadOnlyArray] byte[] securedInput, object key)
        {
            var publicKey = Ensure.Type<CryptographicKey>(key, "RsaPssUsingSha expects key to be of type 'CryptographicKey'");

            IBuffer msg = CryptographicBuffer.CreateFromByteArray(securedInput);            

            //reattach key to alg provider
            IBuffer keyBlob = publicKey.Export(CryptographicPrivateKeyBlobType.BCryptPrivateKey);

            CryptographicKey cKey = AlgProvider.ImportKeyPair(keyBlob, CryptographicPrivateKeyBlobType.BCryptPrivateKey);

            return Buffer.ToBytes(CryptographicEngine.Sign(cKey, msg));
        }

        public bool Verify([ReadOnlyArray] byte[] signature, [ReadOnlyArray] byte[] securedInput, object key)
        {
            var publicKey = Ensure.Type<CryptographicKey>(key, "RsaPssUsingSha expects key to be of type 'CryptographicKey'");


            IBuffer msg = CryptographicBuffer.CreateFromByteArray(securedInput);
            IBuffer sig = CryptographicBuffer.CreateFromByteArray(signature);

            //reattach key to alg provider
            IBuffer keyBlob = publicKey.ExportPublicKey(CryptographicPublicKeyBlobType.BCryptPublicKey);

            CryptographicKey cKey = AlgProvider.ImportPublicKey(keyBlob, CryptographicPublicKeyBlobType.BCryptPublicKey);

            return CryptographicEngine.VerifySignature(cKey, msg, sig);
        }

        public string Name
        {
            get
            {
                switch (keySizeBits)
                {
                    case 256: return JwsAlgorithm.PS256;
                    case 384: return JwsAlgorithm.PS384;
                    default: return JwsAlgorithm.PS512;
                }
            }
        }

        private AsymmetricKeyAlgorithmProvider AlgProvider
        {
            get
            {
                switch (keySizeBits)
                {
                    case 256: return AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaSignPssSha256);
                    case 384: return AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaSignPssSha384);
                    default: return AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaSignPssSha512);
                }
            }
        }
    }
}