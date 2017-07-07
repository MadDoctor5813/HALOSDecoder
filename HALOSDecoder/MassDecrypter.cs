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

        public Logger Logger { get; }

        public MassDecrypter()
        {
            Logger = new Logger("decrypt");
        }

        public void MassDecrypt()
        {
            Logger.Log("Beginning decryption for raw data...", LogLevel.Important);
            BeginDecryption(DataLoader.halosData);
            Logger.Log("Beginning decryption for xor pads...", LogLevel.Important);
            for (int i = 0; i < DataLoader.pads.Count; i++)
            {
                Logger.Log($"Using pad {i + 1}...", LogLevel.Important);
                byte[] pad = DataLoader.pads[i];
                byte[] xorPad = new byte[DataLoader.halosData.Length];
                for (int j = 0; j < xorPad.Length; j++)
                {
                    xorPad[j] = (byte)(pad[j] ^ DataLoader.halosData[j]);
                }
                BeginDecryption(xorPad);
            }
            Logger.Log("Beginning decryption for modular add pads...", LogLevel.Important);
            for (int i = 0; i < DataLoader.pads.Count; i++)
            {
                Logger.Log($"Using pad {i + 1}...", LogLevel.Important);
                byte[] pad = DataLoader.pads[i];
                byte[] addPad = new byte[DataLoader.halosData.Length];
                for (int j = 0; j < addPad.Length; j++)
                {
                    addPad[j] = (byte)((pad[j] + DataLoader.halosData[j]) % 256);
                }
                BeginDecryption(addPad);
            }
        }

        private void BeginDecryption(byte[] data)
        {

            Logger.Log("Starting ECB search...", LogLevel.Important);
            foreach (IBlockCipher algo in DataLoader.algos)
            {
                CastleCipher cipher = new CastleCipher(algo);
                foreach (byte[] key in DataLoader.GetValidKeys(algo))
                {
                    cipher.InitEcb(key);
                    DecryptResult result = cipher.Decrypt(DataLoader.halosData);
                    Logger.Log(result);
                }
            }
            Logger.Log("Starting CBC search...", LogLevel.Important);
            foreach (IBlockCipher algo in DataLoader.algos)
            {
                CastleCipher cipher = new CastleCipher(algo);
                foreach (byte[] key in DataLoader.GetValidKeys(algo))
                {
                    foreach (byte[] iv in DataLoader.GetValidIvs(algo))
                    {
                        cipher.InitCbc(key, iv);
                        DecryptResult result = cipher.Decrypt(data);
                        Logger.Log(result);
                    }
                }
            }
            Logger.Log("Starting CTR search...", LogLevel.Important);
            foreach (IBlockCipher algo in DataLoader.algos)
            {
                CastleCipher cipher = new CastleCipher(algo);
                foreach (byte[] key in DataLoader.GetValidKeys(algo))
                {
                    foreach (byte[] iv in DataLoader.GetValidIvs(algo))
                    {
                        cipher.InitCtr(key, iv);
                        DecryptResult result = cipher.Decrypt(data);
                        Logger.Log(result);
                    }
                }
            }
        }
    }
}
