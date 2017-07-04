using System.Collections.Generic;
using System.IO;

namespace HALOSDecoder
{
    public struct DecryptResult
    {
        public string AlgoName { get; set; }
        public string Key { get; set; }
        public string IV { get; set; }
        public byte[] Plaintext { get; set; }
        public int DistinctBytes { get; set; }
        public Dictionary<byte, int> ByteFrequencies { get; set; }

        public DecryptResult(string algoName, string key, string iv, byte[] plaintext)
        {
            this.AlgoName = algoName;
            this.Key = key;
            this.IV = iv;
            this.Plaintext = plaintext;
            ByteFrequencies = new Dictionary<byte, int>();
            foreach (byte pByte in plaintext)
            {
                if (ByteFrequencies.ContainsKey(pByte))
                {
                    ByteFrequencies[pByte] = ByteFrequencies[pByte] + 1;
                }
                else
                {
                    ByteFrequencies[pByte] = 1;
                }
            }
            DistinctBytes = ByteFrequencies.Keys.Count;
        }

        public void WriteToFile(StreamWriter stream)
        {
            stream.WriteLine($"Using algorithm {AlgoName} with key {Key}");
            if (IV != null)
            {
                stream.WriteLine($"Using IV {IV}");
            }
            stream.WriteLine(Util.ByteArrayToString(Plaintext));
            stream.WriteLine($"Distinct bytes: {DistinctBytes}");
            stream.WriteLine(string.Join(",", ByteFrequencies));
            stream.WriteLine("=====================================================");
        }

    }
}