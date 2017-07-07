using Org.BouncyCastle.Crypto.Engines;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HALOSDecoder
{
    class CascadeDecrypter
    {

        public Logger Logger { get; }

        public CascadeDecrypter()
        {
            Logger = new Logger("cascade");
        }

        public void CascadeDecrypt()
        {
            Logger.Log("Beginning ECB cascade...", LogLevel.Important);
            CastleCipher serpent = new CastleCipher(new SerpentEngine());
            CastleCipher twofish = new CastleCipher(new TwofishEngine());
            CastleCipher aes = new CastleCipher(new AesEngine());
            foreach (byte[] key in DataLoader.keys)
            {
                serpent.InitEcb(key);
                twofish.InitEcb(key);
                aes.InitEcb(key);
                DecryptResult serpentResult = serpent.Decrypt(DataLoader.halosData);
                DecryptResult twofishResult = twofish.Decrypt(serpentResult.Plaintext);
                DecryptResult final = aes.Decrypt(twofishResult.Plaintext);
                Logger.Log(final);
            }
            Logger.Log("Beginning CBC cascade...", LogLevel.Important);
            foreach (byte[] key in DataLoader.keys)
            {
                foreach (byte[] iv in DataLoader.ivs)
                {
                    serpent.InitCbc(key, iv);
                    twofish.InitCbc(key, iv);
                    aes.InitCbc(key, iv);
                    DecryptResult serpentResult = serpent.Decrypt(DataLoader.halosData);
                    DecryptResult twofishResult = twofish.Decrypt(serpentResult.Plaintext);
                    DecryptResult final = aes.Decrypt(twofishResult.Plaintext);
                    Logger.Log(final);
                }
            }
            Logger.Log("Beginning CTR cascade...", LogLevel.Important);
            foreach (byte[] key in DataLoader.keys)
            {
                foreach (byte[] iv in DataLoader.ivs)
                {
                    serpent.InitCtr(key, iv);
                    twofish.InitCtr(key, iv);
                    aes.InitCtr(key, iv);
                    DecryptResult serpentResult = serpent.Decrypt(DataLoader.halosData);
                    DecryptResult twofishResult = twofish.Decrypt(serpentResult.Plaintext);
                    DecryptResult final = aes.Decrypt(twofishResult.Plaintext);
                    Logger.Log(final);
                }
            }
        }
    }
}
