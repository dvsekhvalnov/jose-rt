using System;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using JoseRT.Keys.pem;

namespace JoseRT.Rsa
{
    public sealed class PublicKey
    {
        public static CryptographicKey Load(string pubKeyContent)
        {
            CryptographicPublicKeyBlobType blobType;

            var block=new Pem(pubKeyContent);

            if (block.Type == null) //not pem encoded
            {
                //trying to guess blob type
                blobType = pubKeyContent.StartsWith("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A")
                    ? CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo
                    : CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey;
            }
            else if ("PUBLIC KEY".Equals(block.Type))
            {
                blobType=CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo;   
            }
            else if ("RSA PUBLIC KEY".Equals(block.Type))
            {
                blobType = CryptographicPublicKeyBlobType.Pkcs1RsaPublicKey;
            }
            else
            {
                throw new Exception(string.Format("PublicKey.Load(): Unsupported type in PEM block '{0}'",block.Type));
            }

            return AsymmetricKeyAlgorithmProvider.OpenAlgorithm(AsymmetricAlgorithmNames.RsaPkcs1)
                                                 .ImportPublicKey(CryptographicBuffer.CreateFromByteArray(block.Decoded), blobType);
        }
    }
}