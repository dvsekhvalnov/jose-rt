using System;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using JoseRT.Serialization;


namespace JoseRT.Util
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

        public static byte[] FirstHalf([ReadOnlyArray] byte[] arr)
        {
            Ensure.Divisible(arr.Length, 2, "Arrays.FirstHalf(): expects even number of element in array.");

            int halfIndex = arr.Length / 2;

            var result = new byte[halfIndex];

            System.Buffer.BlockCopy(arr, 0, result, 0, halfIndex);

            return result;
        }

        public static byte[] SecondHalf([ReadOnlyArray] byte[] arr)
        {
            Ensure.Divisible(arr.Length, 2, "Arrays.SecondHalf(): expects even number of element in array.");

            int halfIndex = arr.Length / 2;

            var result = new byte[halfIndex];

            System.Buffer.BlockCopy(arr, halfIndex, result, 0, halfIndex);

            return result;
        }

        public static byte[] LongToBytes(long lValue)
        {
            ulong _value = (ulong)lValue;

            return BitConverter.IsLittleEndian
                ? new[] { (byte)((_value >> 56) & 0xFF), (byte)((_value >> 48) & 0xFF), (byte)((_value >> 40) & 0xFF), (byte)((_value >> 32) & 0xFF), (byte)((_value >> 24) & 0xFF), (byte)((_value >> 16) & 0xFF), (byte)((_value >> 8) & 0xFF), (byte)(_value & 0xFF) }
                : new[] { (byte)(_value & 0xFF), (byte)((_value >> 8) & 0xFF), (byte)((_value >> 16) & 0xFF), (byte)((_value >> 24) & 0xFF), (byte)((_value >> 32) & 0xFF), (byte)((_value >> 40) & 0xFF), (byte)((_value >> 48) & 0xFF), (byte)((_value >> 56) & 0xFF) };
        }

        public static bool ConstantTimeEquals([ReadOnlyArray] byte[] expected, [ReadOnlyArray] byte[] actual)
        {
            if (expected == actual)
                return true;

            if (expected == null || actual == null)
                return false;

            if (expected.Length != actual.Length)
                return false;

            bool equals = true;

            for (int i = 0; i < expected.Length; i++)
                if (expected[i] != actual[i])
                    equals = false;

            return equals;
        }
    }
}