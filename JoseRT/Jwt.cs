using System;
using System.Collections.Generic;
using System.Text;
using Windows.Data.Json;
using JoseRT.Jws;
using JoseRT.Serialization;
using JoseRT.util;

namespace JoseRT
{
    public sealed class Jwt
    {
        private static IDictionary<string, IJwsSigner> signers = new Dictionary<string, IJwsSigner>();

        static Jwt()
        {
            Register(new Plaintext());
            Register(new HmacUsingSha(256));
            Register(new HmacUsingSha(384));
            Register(new HmacUsingSha(512));
        }

        public static void Register(IJwsSigner signer)
        {
            signers[signer.Name] = signer;
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
            throw new NotImplementedException("not yet");
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
                throw new Exception("JoseRT.Jwt.Verify(): Invalid signature."); //TODO: find better exception class

            return payload.Utf8;
        }


        public static string Encode(string payload, string signingAlgorithm, object key)
        {
            Ensure.IsNotEmpty(payload, "JoseRT.Jwt.Encode(): payload expected to be not empty, whitespace or null.");

            if (!signers.ContainsKey(signingAlgorithm))
                throw new Exception(string.Format("JoseRT.Jwt.Encode(): unknown or unsupported algorithm:{0}.", signingAlgorithm));

            IJwsSigner signer = signers[signingAlgorithm];

            var jwtHeader = new JsonObject
            {
                {"typ",JsonValue.CreateStringValue("JWT") },
                {"alg", JsonValue.CreateStringValue(signingAlgorithm)}
            };

            var header = Part.New(jwtHeader.Stringify());
            var content = Part.New(payload);

            var securedInput = Encoding.UTF8.GetBytes(Compact.Serialize(header, content));

            var signature = new Part(signer.Sign(securedInput, key));

            return Compact.Serialize(header, content, signature);
        }

        public static string Encode(string payload, string signingAlgorithm)
        {
            return Encode(payload, signingAlgorithm, null);
        }
    }
}

