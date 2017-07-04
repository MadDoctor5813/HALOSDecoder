using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HALOSDecoder
{
    public class Util
    {

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
