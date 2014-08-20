namespace JoseRT
{
    public sealed class JwsAlgorithm
    {
        public static string None
        {
            get { return "none"; }
        }

        public static string HS256
        {
            get { return "HS256"; }
        }

        public static string HS384
        {
            get { return "HS384"; }
        }

        public static string HS512
        {
            get { return "HS512"; }
        }
    }
}