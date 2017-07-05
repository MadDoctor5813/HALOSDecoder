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

        public CascadeDecrypter()
        {
        }

        public void CascadeDecrypt(string fullLogPath, string logPath)
        {
            using (StreamWriter fullLogWriter = new StreamWriter(new FileStream(fullLogPath, FileMode.Create, FileAccess.Write)))
            using (StreamWriter logWriter = new StreamWriter(new FileStream(logPath, FileMode.Create, FileAccess.Write)))
            {
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
                    final.WriteToFile(fullLogWriter);
                    if (final.DistinctBytes < 180)
                    {
                        final.WriteToFile(logWriter);
                    }
                }
            }
        }

    }
}
