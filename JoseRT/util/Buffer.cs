﻿using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace JoseRT.Util
{
    public sealed class Buffer
    {
        public static byte[] ToBytes(IBuffer data)
        {
            byte[] result;

            CryptographicBuffer.CopyToByteArray(data, out result);

            return result;
        }
    }
}