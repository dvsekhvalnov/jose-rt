using System;

namespace JoseRT.Util
{
    internal class Ensure
    {
        public static void Divisible(int arg, int divisor, string msg, params object[] args)
        {
            if (arg % divisor != 0)
                throw new ArgumentException(string.Format(msg, args));
        }

        public static void BitSize(byte[] array, int expectedSize, string msg, params object[] args)
        {
            if (expectedSize != array.Length * 8)
                throw new ArgumentException(string.Format(msg, args));
        }

        public static void IsEmpty(byte[] arr, string msg, params object[] args)
        {
            if (arr.Length != 0)
                throw new ArgumentException(msg);
        }

        public static T Type<T>(object obj, string msg, params object[] args)
        {
            if (!(obj is T))
                throw new ArgumentException(string.Format(msg, args));

            return (T) obj;
        }

        public static void IsNotEmpty(string arg, string msg, params object[] args)
        {
            if (string.IsNullOrWhiteSpace(arg))
                throw new ArgumentException(string.Format(msg, args));
        }
    }
}