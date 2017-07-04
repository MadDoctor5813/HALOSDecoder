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

        static void Main(string[] args)
        {
            new Program();
        }

        public Program()
        {
            LoadHalosData();
            LoadKeys();
            LoadIvs();
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
