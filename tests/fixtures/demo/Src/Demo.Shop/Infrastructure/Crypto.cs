using System.Security.Cryptography;

namespace Demo.Shop.Infrastructure
{
    public static class Crypto
    {
        public static ICryptoTransform CreateEncryptor(byte[] key, byte[] iv)
        {
            var algorithm = new DESCryptoServiceProvider();
            return algorithm.CreateEncryptor(key, iv);
        }
    }
}
