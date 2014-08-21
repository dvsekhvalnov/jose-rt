using System;

namespace JoseRT.util
{
    internal class Ensure
    {
        public static T Type<T>(object obj, string msg, params object[] args)
        {
            if (!(obj is T))
                throw new ArgumentException(string.Format(msg, args));

            return (T)obj;
        }

        public static void IsNotEmpty(string arg, string msg, params object[] args)
        {
            if (string.IsNullOrWhiteSpace(arg))
                throw new ArgumentException(string.Format(msg,args));
        }
    }
}