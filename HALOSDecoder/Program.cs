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
    class Program
    {

        byte[] halosData;
        List<byte[]> keys;
        List<byte[]> ivs;

        private IBlockCipher[] algos = { new AesEngine(), new RijndaelEngine(), new TwofishEngine(), new SerpentEngine() };

        static void Main(string[] args)
        {
            new Program();
        }

        public Program()
        {
            LoadHalosData();
            LoadKeys();
            LoadIvs();
            BeginSearch();
        }

        private void BeginSearch()
        {
            using (StreamWriter fullLogWriter = new StreamWriter(new FileStream("log_full.txt", FileMode.Create, FileAccess.Write)))
            using (StreamWriter logWriter = new StreamWriter(new FileStream("log.txt", FileMode.Create, FileAccess.Write)))
            {
                fullLogWriter.WriteLine("Starting ECB search");
                foreach (IBlockCipher algo in algos)
                {
                    CastleCipher cipher = new CastleCipher(algo);
                    foreach (byte[] key in keys)
                    {
                        cipher.InitEcb(key);
                        DecryptResult result = cipher.Decrypt(halosData);
                        result.WriteToFile(fullLogWriter);
                        if (result.DistinctBytes < 180)
                        {
                            result.WriteToFile(logWriter);
                        }
                    }
                }
                fullLogWriter.WriteLine("Starting CBC search");
                foreach (IBlockCipher algo in algos)
                {
                    CastleCipher cipher = new CastleCipher(algo);
                    foreach (byte[] key in keys)
                    {
                        foreach (byte[] iv in ivs)
                        {
                            cipher.InitCbc(key, iv);
                            DecryptResult result = cipher.Decrypt(halosData);
                            result.WriteToFile(fullLogWriter);
                            if (result.DistinctBytes < 180)
                            {
                                result.WriteToFile(logWriter);
                            }
                        }
                    }
                }
            }
        }

        private void LoadHalosData()
        {
            using (StreamReader reader = new StreamReader(new FileStream("HALOS.txt", FileMode.Open, FileAccess.Read)))
            {
                string data = reader.ReadToEnd();
                halosData = Util.StringToByteArray(data);
            }
        }

        private void LoadKeys()
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

        private void LoadIvs()
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


    }
}
