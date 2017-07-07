using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HALOSDecoder
{
    public class Util
    {

        public static Dictionary<string, int[]> KeySizes { get; } = new Dictionary<string, int[]>
        {
            {"AES", new int[] { 16, 24, 32 } },
            {"Rijndael", new int[] { 16, 20, 24, 28, 32 } },
            {"Twofish", new int[] { 16, 24, 32 } },
            {"Serpent", new int[] {16, 24, 32} }
        };

        public static bool IsKeyValid(IBlockCipher engine, byte[] key)
        {
            int[] sizes = KeySizes[engine.AlgorithmName];
            return sizes.Contains(key.Length);
        }

        public static bool IsIvValid(IBlockCipher engine, byte[] iv)
        {
            return iv.Length == engine.GetBlockSize();
        }


        public static byte[] StringToByteArray(string strData)
        {
            return Enumerable.Range(0, strData.Length)
                     .Where(x => x % 2 == 0)
                     .Select(x => Convert.ToByte(strData.Substring(x, 2), 16))
                     .ToArray();
        }

        public static string ByteArrayToString(byte[] byteData)
        {
            return BitConverter.ToString(byteData).Replace("-", "");
        }

    }
}
