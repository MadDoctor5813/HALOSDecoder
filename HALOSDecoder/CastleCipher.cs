using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HALOSDecoder
{

    public class CastleCipher
    {

        public IBlockCipher Engine { get; set; }
        public BufferedBlockCipher Cipher { get; set; }

        public CastleCipher(IBlockCipher engine)
        {
            this.Engine = engine;
        }

        public void InitEcb(byte[] key)
        {
            Cipher = new BufferedBlockCipher(Engine);
            Cipher.Init(false, new KeyParameter(key));
        }

        public void InitCbc(byte[] key, byte[] iv)
        {
            Cipher = new BufferedBlockCipher(new CbcBlockCipher(Engine));
            Cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
        }

        public byte[] Decrypt(byte[] data)
        {
            return Cipher.DoFinal(data);
        }
    }
}
