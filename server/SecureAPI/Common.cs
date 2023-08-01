namespace SecureAPI
{
    public static class Common
    {
        public static string SecretKey { get { return "H! MaI SeCTeri Key opfg This is the Key. Abo new test Key new this"; }  }
        public static string Issuer { get { return "www.mywebsite.com"; } }
        public static string Audience { get { return "MySecureAPI"; } }
        public static string TokenType { get { return "JWT"; } }
    }
}
