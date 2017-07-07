using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HALOSDecoder
{
    class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Starting mass decryption...");
            MassDecrypter decrypter = new MassDecrypter();
            decrypter.MassDecrypt();
            Console.WriteLine($"Mass decrypt logs written to {decrypter.Logger.FullLogPath} and {decrypter.Logger.LogPath}.");
            Console.WriteLine("Starting cascade decryption...");
            CascadeDecrypter cascade = new CascadeDecrypter();
            cascade.CascadeDecrypt();
            Console.WriteLine($"Cascade decrypt logs written to {cascade.Logger.FullLogPath} and {cascade.Logger.LogPath}.");
        }

    }
}
