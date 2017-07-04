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
    class MassDecrypter
    {

        public MassDecrypter()
        {
        }

        public void MassDecrypt(string fullLogPath, string logPath)
        {
            using (StreamWriter fullLogWriter = new StreamWriter(new FileStream(fullLogPath, FileMode.Create, FileAccess.Write)))
            using (StreamWriter logWriter = new StreamWriter(new FileStream(logPath, FileMode.Create, FileAccess.Write)))
            {
                fullLogWriter.WriteLine("Beginning decryption for raw data");
                logWriter.WriteLine("Beginning decryption for raw data");
                BeginDecryption(DataLoader.halosData, fullLogWriter, logWriter);
                fullLogWriter.WriteLine("Beginning decryption for xor pads");
                logWriter.WriteLine("Beginning decryption for xor pads");
                for (int i = 0; i < DataLoader.pads.Count; i++)
                {
                    fullLogWriter.WriteLine($"Using pad {i + 1}");
                    logWriter.WriteLine($"Using pad {i + 1}");
                    byte[] pad = DataLoader.pads[i];
                    byte[] xorPad = new byte[DataLoader.halosData.Length];
                    for (int j = 0; j < xorPad.Length; j++)
                    {
                        xorPad[j] = (byte)(pad[j] ^ DataLoader.halosData[j]);
                    }
                    BeginDecryption(xorPad, fullLogWriter, logWriter);
                }
                fullLogWriter.WriteLine("Beginning decryption for modular add pads");
                logWriter.WriteLine("Beginning decryption for modular add pads");
                for (int i = 0; i < DataLoader.pads.Count; i++)
                {
                    fullLogWriter.WriteLine($"Using pad {i + 1}");
                    logWriter.WriteLine($"Using pad {i + 1}");
                    byte[] pad = DataLoader.pads[i];
                    byte[] xorPad = new byte[DataLoader.halosData.Length];
                    for (int j = 0; j < xorPad.Length; j++)
                    {
                        xorPad[j] = (byte)((pad[j] + DataLoader.halosData[j]) % 256);
                    }
                    BeginDecryption(xorPad, fullLogWriter, logWriter);
                }
            }
        }

        private void BeginDecryption(byte[] data, StreamWriter fullLogWriter, StreamWriter logWriter)
        {

            fullLogWriter.WriteLine("Starting ECB search");
            logWriter.WriteLine("Starting ECB search");
            foreach (IBlockCipher algo in DataLoader.algos)
            {
                CastleCipher cipher = new CastleCipher(algo);
                foreach (byte[] key in DataLoader.keys)
                {
                    cipher.InitEcb(key);
                    DecryptResult result = cipher.Decrypt(DataLoader.halosData);
                    result.WriteToFile(fullLogWriter);
                    if (result.DistinctBytes < 180)
                    {
                        result.WriteToFile(logWriter);
                    }
                }
            }
            fullLogWriter.WriteLine("Starting CBC search");
            logWriter.WriteLine("Starting CBC search");
            foreach (IBlockCipher algo in DataLoader.algos)
            {
                CastleCipher cipher = new CastleCipher(algo);
                foreach (byte[] key in DataLoader.keys)
                {
                    foreach (byte[] iv in DataLoader.ivs)
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
    }
}
