namespace JoseRT
{
    public sealed class JwaAlgorithms
    {
        public static string DIR
        {
            get { return "dir"; }
        }

        public static string RSA1_5
        {
            get { return "RSA1_5"; }
        }

        public static string RSA_OAEP
        {
            get { return "RSA-OAEP"; }
        }

        public static string RSA_OAEP_256
        {
            get { return "RSA-OAEP-256"; }
        }     

        public static string A128KW
        {
            get { return "A128KW"; }
        }

        public static string A192KW
        {
            get { return "A192KW"; }
        }

        public static string A256KW
        {
            get { return "A256KW"; }
        }


//        public static string PBES2_HS256_A128KW
//        {
//            get { return "PBES2-HS256+A128KW"; }
//        }
//
//        public static string PBES2_HS384_A192KW
//        {
//            get { return "PBES2-HS384+A192KW"; }
//        }
//
//        public static string PBES2_HS512_A256KW
//        {
//            get { return "PBES2-HS512+A256KW"; }
//        }
    }
}