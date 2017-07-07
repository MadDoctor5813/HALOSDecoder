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

        private byte[] key;
        private byte[] iv;

        public CastleCipher(IBlockCipher engine)
        {
            this.Engine = engine;
        }

        public void InitEcb(byte[] key)
        {
            this.key = key;
            this.iv = null;
            Cipher = new BufferedBlockCipher(Engine);
            Cipher.Init(false, new KeyParameter(key));
        }

        public void InitCbc(byte[] key, byte[] iv)
        {
            this.key = key;
            this.iv = iv;
            Cipher = new BufferedBlockCipher(new CbcBlockCipher(Engine));
            Cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
        }

        public void InitCtr(byte[] key, byte[] iv)
        {
            this.key = key;
            this.iv = iv;
            Cipher = new BufferedBlockCipher(new SicBlockCipher(Engine));
            Cipher.Init(false, new ParametersWithIV(new KeyParameter(key), iv));
        }

        public DecryptResult Decrypt(byte[] data)
        {
            //pad data to block size boundary
            if (data.Length % Engine.GetBlockSize() != 0)
            {
                int newLength = data.Length + (Engine.GetBlockSize() - (data.Length % Engine.GetBlockSize()));
                Array.Resize(ref data, newLength);
            }
            byte[] pText = Cipher.DoFinal(data);
            Cipher.Reset();
            if (iv == null)
            {
                return new DecryptResult(Engine.AlgorithmName, Encoding.ASCII.GetString(key), null, pText);
            }
            else
            {
                return new DecryptResult(Engine.AlgorithmName, Encoding.ASCII.GetString(key), Encoding.ASCII.GetString(iv), pText);
            }
        }
    }
}
