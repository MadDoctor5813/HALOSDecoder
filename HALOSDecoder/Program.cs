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
        List<byte[]> pads;

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
            LoadPads();
            using (StreamWriter fullLogWriter = new StreamWriter(new FileStream("log_full.txt", FileMode.Create, FileAccess.Write)))
            using (StreamWriter logWriter = new StreamWriter(new FileStream("log.txt", FileMode.Create, FileAccess.Write)))
            {
                fullLogWriter.WriteLine("Beginning decryption for raw data");
                logWriter.WriteLine("Beginning decryption for raw data");
                BeginDecryption(halosData, fullLogWriter, logWriter);
                fullLogWriter.WriteLine("Beginning decryption for xor pads");
                logWriter.WriteLine("Beginning decryption for xor pads");
                for (int i = 0; i < pads.Count; i++)
                {
                    fullLogWriter.WriteLine($"Using pad {i + 1}");
                    logWriter.WriteLine($"Using pad {i + 1}");
                    byte[] pad = pads[i];
                    byte[] xorPad = new byte[halosData.Length];
                    for (int j = 0; j < xorPad.Length; j++)
                    {
                        xorPad[j] = (byte)(pad[j] ^ halosData[j]);
                    }
                    BeginDecryption(xorPad, fullLogWriter, logWriter);
                }
                fullLogWriter.WriteLine("Beginning decryption for modular add pads");
                logWriter.WriteLine("Beginning decryption for modular add pads");
                for (int i = 0; i < pads.Count; i++)
                {
                    fullLogWriter.WriteLine($"Using pad {i + 1}");
                    logWriter.WriteLine($"Using pad {i + 1}");
                    byte[] pad = pads[i];
                    byte[] xorPad = new byte[halosData.Length];
                    for (int j = 0; j < xorPad.Length; j++)
                    {
                        xorPad[j] = (byte)((pad[j] + halosData[j]) % 256);
                    }
                    BeginDecryption(xorPad, fullLogWriter, logWriter);
                }
            }
        }

        private void LoadPads()
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

        private void BeginDecryption(byte[] data, StreamWriter fullLogWriter, StreamWriter logWriter)
        {

            fullLogWriter.WriteLine("Starting ECB search");
            logWriter.WriteLine("Starting ECB search");
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
            logWriter.WriteLine("Starting CBC search");
            foreach (IBlockCipher algo in algos)
            {
                CastleCipher cipher = new CastleCipher(algo);
                foreach (byte[] key in keys)
                {
                    foreach (byte[] iv in ivs)
                    {
                        cipher.InitCbc(key, iv);
                        DecryptResult result = cipher.Decrypt(data);
                        result.WriteToFile(fullLogWriter);
                        if (result.DistinctBytes < 180)
                        {
                            result.WriteToFile(logWriter);
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
