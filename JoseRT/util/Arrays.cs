using System;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using JoseRT.Serialization;

namespace JoseRT.util
{
    public sealed class Arrays
    {
        public static string Dump([ReadOnlyArray] byte[] arr)
        {
            var builder = new StringBuilder();

            builder.Append(string.Format("({0} bytes): [", arr.Length).Trim());

            foreach (byte b in arr)
            {
                builder.Append(b);
                builder.Append(",");
            }

            builder.Remove(builder.Length - 1, 1);
            builder.Append("] Hex:[").Append(BitConverter.ToString(arr).Replace("-", " "));
            builder.Append("] Base64Url:").Append(Base64Url.Encode(arr)).Append("\n");

            return builder.ToString();
        }
    }
}