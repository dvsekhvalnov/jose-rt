using System;
using System.Linq;
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

        internal static byte[] Concat(params byte[][] arrays)
        {
            byte[] result = new byte[arrays.Sum(a => (a == null) ? 0 : a.Length)];
            int offset = 0;

            foreach (byte[] array in arrays)
            {
                if (array == null) continue;

                System.Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }

            return result;
        }


    }
}