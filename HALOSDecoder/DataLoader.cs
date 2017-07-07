using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using System;
using System.Collections;
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
        private static List<byte[]> keys { get; set; }
        private static List<byte[]> ivs { get; set; }
        public static List<byte[]> pads { get; set; }

        public static IBlockCipher[] algos = { new AesEngine(), new RijndaelEngine(), new TwofishEngine(), new SerpentEngine(), new DesEdeEngine() };

        static DataLoader()
        {
            LoadHalosData();
            LoadKeys();
            LoadIvs();
            LoadPads();
        }

        public static IEnumerable<byte[]> GetValidKeys(IBlockCipher algo)
        {
            foreach (byte[] key in keys)
            {
                if (Util.IsKeyValid(algo, key))
                {
                    //DES keys need to have parity bits added to them
                    if (algo.AlgorithmName == "DESede")
                    {
                        yield return AddDesParity(key);
                    }
                    else
                    {
                        yield return key;
                    }
                }
            }
        }

        public static IEnumerable<byte[]> GetValidIvs(IBlockCipher algo)
        {
            foreach (byte[] iv in ivs)
            {
                if (Util.IsIvValid(algo, iv))
                {
                    yield return iv;
                }
            }
        }

        private static byte[] AddDesParity(byte[] key)
        {
            //split into 7 bit chunks
            BitArray keyBits = new BitArray(key);
            BitArray[] chunks = new BitArray[keyBits.Length / 7];
            for (int i = 0; i < chunks.Length; i++)
            {
                chunks[i] = new BitArray(7);
                for (int j = 0; j < 7; j++)
                {
                    chunks[i][j] = keyBits[(i * 7) + j];
                }
            }
            int convertedLen = 0;
            if (key.Length == 14)
            {
                convertedLen = 16;
            }
            else
            {
                convertedLen = 24;
            }
            byte[] converted = new byte[convertedLen];
            for (int i = 0; i < chunks.Length; i++)
            {
                BitArray chunkWithParity = new BitArray(8);
                int paritySum = 0;
                for (int j = 0; j < 7; j++)
                {
                    if (chunks[i][j] == true)
                    {
                        paritySum++;
                    }
                    chunkWithParity[j] = chunks[i][j];
                }
                chunkWithParity[7] = (paritySum % 2 == 0);
                chunkWithParity.CopyTo(converted, i);
            }
            return converted;
            
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
