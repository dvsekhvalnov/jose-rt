using System;
using System.Collections.Generic;
using System.Text;
using Windows.Data.Json;
using JoseRT.Jwa;
using JoseRT.Jwe;
using JoseRT.Jws;
using JoseRT.Serialization;
using JoseRT.Util;

namespace JoseRT
{
    public sealed class Jwt
    {
        private static IDictionary<string, IJwsSigner> signers = new Dictionary<string, IJwsSigner>();
        private static IDictionary<string, IJweEncryptor> encryptors = new Dictionary<string, IJweEncryptor>();
        private static IDictionary<string, IJwaAlgorithm> algorithms = new Dictionary<string, IJwaAlgorithm>();

        static Jwt()
        {
            RegisterJws(new Plaintext());
            RegisterJws(new HmacUsingSha(256));
            RegisterJws(new HmacUsingSha(384));
            RegisterJws(new HmacUsingSha(512));
            RegisterJws(new RsaUsingSha(256));
            RegisterJws(new RsaUsingSha(384));
            RegisterJws(new RsaUsingSha(512));
            RegisterJws(new RsaPssUsingSha(256));
            RegisterJws(new RsaPssUsingSha(384));
            RegisterJws(new RsaPssUsingSha(512));
            RegisterJws(new EcdsaUsingSha(256));
            RegisterJws(new EcdsaUsingSha(384));
            RegisterJws(new EcdsaUsingSha(521));

            RegisterJwe(new AesCbcHmacEncryptor(256));
            RegisterJwe(new AesCbcHmacEncryptor(384));
            RegisterJwe(new AesCbcHmacEncryptor(512));

            RegisterJwa(new DirectKeyManagement());
        }

        public static void RegisterJws(IJwsSigner signer)
        {
            signers[signer.Name] = signer;
        }

        public static void RegisterJwe(IJweEncryptor encryptor)
        {
            encryptors[encryptor.Name] = encryptor;
        }

        public static void RegisterJwa(IJwaAlgorithm algorithm)
        {
            algorithms[algorithm.Name] = algorithm;
        }

        public static string Decode(string token, object key)
        {
            Ensure.IsNotEmpty(token, "JoseRT.Jwt.Decode(): token expected to be in compact serialization form, not empty, whitespace or null.");

            Part[] parts = Compact.Parse(token);

            if (parts.Length == 5) //encrypted JWT
            {
                return Decrypt(parts, key);
            }

            if (parts.Length == 3)
            {
                return Verify(parts, key);
            }

            throw new Exception(string.Format("JoseRT.Jwt.Decode(): expected token with 3 or 5 parts, but got:{0}.", parts.Length));
        }

        private static string Decrypt(Part[] parts, object key)
        {
            Part header = parts[0];
            Part encryptedCek = parts[1];
            Part iv = parts[2];
            Part cipherText = parts[3];
            Part authTag = parts[4];

            var jwtHeader = JsonObject.Parse(header.Utf8);
            var alg = jwtHeader["alg"].GetString();
            var enc = jwtHeader["enc"].GetString();

            if (!encryptors.ContainsKey(enc))
                throw new Exception(string.Format("JoseRT.Jwt.Decrypt(): unknown or unsupported encryption:{0}.", enc));

            if (!algorithms.ContainsKey(alg))
                throw new Exception(string.Format("JoseRT.Jwt.Decrypt(): unknown or unsupported algorithm:{0}.", alg));

            IJwaAlgorithm keys = algorithms[alg];
            IJweEncryptor encryption = encryptors[enc];

            byte[] cek = keys.Unwrap(encryptedCek.Bytes, key, encryption.KeySize, jwtHeader); //TODO part?

            byte[] aad = Encoding.UTF8.GetBytes(Compact.Serialize(header)); //TODO: Part.New(Compact...)
            
            byte[] plainText = encryption.Decrypt(aad, cek, iv.Bytes, cipherText.Bytes, authTag.Bytes); //TODO: all parts, return part?

            return Encoding.UTF8.GetString(plainText, 0, plainText.Length); 
        }

        private static string Verify(Part[] parts, object key)
        {
            Part header = parts[0];
            Part payload = parts[1];
            Part signature = parts[2];

            byte[] securedInput = Encoding.UTF8.GetBytes(Compact.Serialize(header, payload));

            var headerData = JsonObject.Parse(header.Utf8);
            var alg = headerData["alg"].GetString();

            if (!signers.ContainsKey(alg))
                throw new Exception(string.Format("JoseRT.Jwt.Verify(): unknown or unsupported algorithm:{0}.", alg));

            if (!signers[alg].Verify(signature.Bytes, securedInput, key))
                throw new Exception("JoseRT.Jwt.Verify(): Invalid signature."); 

            return payload.Utf8;
        }


        public static string Encode(string payload, string signingAlgorithm, object key)
        {
            Ensure.IsNotEmpty(payload, "JoseRT.Jwt.Encode(): payload expected to be not empty, whitespace or null.");

            if (!signers.ContainsKey(signingAlgorithm))
                throw new Exception(string.Format("JoseRT.Jwt.Encode(): unknown or unsupported signing algorithm:{0}.", signingAlgorithm));

            IJwsSigner signer = signers[signingAlgorithm];

            var jwtHeader = new JsonObject
            {
                {"typ",JsonValue.CreateStringValue("JWT") },
                {"alg", JsonValue.CreateStringValue(signingAlgorithm)}
            };

            var header = Part.New(jwtHeader.Stringify());
            var content = Part.New(payload);

            var securedInput = Encoding.UTF8.GetBytes(Compact.Serialize(header, content));

            var signature = new Part(signer.Sign(securedInput, key)); //TODO: subject to change signer.Sign() to return Part

            return Compact.Serialize(header, content, signature);
        }

        public static string Encode(string payload, string signingAlgorithm)
        {
            return Encode(payload, signingAlgorithm, null);
        }

        public static string Encode(string payload, string keyManagementAlg, string encryption, object key)
        {
            Ensure.IsNotEmpty(payload, "JoseRT.Jwt.Encode(): payload expected to be not empty, whitespace or null.");

            if (!encryptors.ContainsKey(encryption))
                throw new Exception(string.Format("JoseRT.Jwt.Encode(): unknown or unsupported encryption algorithm:{0}.", encryption));

            if (!algorithms.ContainsKey(keyManagementAlg))
                throw new Exception(string.Format("JoseRT.Jwt.Encode(): unknown or unsupported key management algorithm:{0}.", keyManagementAlg));

            IJweEncryptor encryptor = encryptors[encryption];
            IJwaAlgorithm algorithm = algorithms[keyManagementAlg];

            var jwtHeader = new JsonObject
            {
                {"enc",JsonValue.CreateStringValue(encryption) },
                {"alg", JsonValue.CreateStringValue(keyManagementAlg)}
            };

            Part[] keys = algorithm.WrapNewKey(encryptor.KeySize, key, jwtHeader);
            Part cek = keys[0];
            Part encryptedCek = keys[1];
            Part header = Part.New(jwtHeader.Stringify());

            byte[] plainText = Encoding.UTF8.GetBytes(payload);
            
            byte[] aad = Encoding.UTF8.GetBytes(Compact.Serialize(header));
            Part[] encParts = encryptor.Encrypt(aad, plainText, cek.Bytes);

            return Compact.Serialize(header, encryptedCek, encParts[0], encParts[1], encParts[2]);
        }
    }
}

