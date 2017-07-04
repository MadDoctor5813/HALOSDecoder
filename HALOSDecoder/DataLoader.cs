using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HALOSDecoder
{
    class DataLoader
    {

        public static byte[] halosData { get; set; }
        public static List<byte[]> keys { get; set; }
        public static List<byte[]> ivs { get; set; }
        public static List<byte[]> pads { get; set; }

        public static IBlockCipher[] algos = { new AesEngine(), new RijndaelEngine(), new TwofishEngine(), new SerpentEngine() };

        static DataLoader()
        {
            LoadHalosData();
            LoadKeys();
            LoadIvs();
            LoadPads();
        }

        private static void LoadHalosData()
        {
            using (StreamReader reader = new StreamReader(new FileStream("HALOS.txt", FileMode.Open, FileAccess.Read)))
            {
                string data = reader.ReadToEnd();
                halosData = Util.StringToByteArray(data);
            }
        }

        private static void LoadKeys()
        {
            keys = new List<byte[]>();
            using (StreamReader reader = new StreamReader(new FileStream("KEYS.txt", FileMode.Open, FileAccess.Read)))
            {
                while (!reader.EndOfStream)
                {
                    string key = reader.ReadLine();
                    keys.Add(Encoding.ASCII.GetBytes(key));
                }
            }
        }

        private static void LoadIvs()
        {
            ivs = new List<byte[]>();
            using (StreamReader reader = new StreamReader(new FileStream("IVS.txt", FileMode.Open, FileAccess.Read)))
            {
                while (!reader.EndOfStream)
                {
                    string iv = reader.ReadLine();
                    ivs.Add(Encoding.ASCII.GetBytes(iv));
                }
            }
        }

        private static void LoadPads()
        {
            pads = new List<byte[]>();
            using (StreamReader reader = new StreamReader(new FileStream("PADS.txt", FileMode.Open, FileAccess.Read)))
            {
                int idx = 0;
                while (!reader.EndOfStream)
                {
                    byte[] padBytes = Encoding.ASCII.GetBytes(reader.ReadLine());
                    if (padBytes.Length != 376)
                    {
                        Console.WriteLine($"Pad {idx + 1} is of invalid length. Skipping...");
                    }
                    else
                    {
                        pads.Add(padBytes);
                    }
                    idx++;
                }
            }
        }

    }
}
