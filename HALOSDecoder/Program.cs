using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HALOSDecoder
{
    class Program
    {

        const string fullLogPath = "decrypt_log_full.txt";
        const string logPath = "decrypt_log.txt";

        public static void Main(string[] args)
        {
            Console.WriteLine("Starting mass decryption...");
            MassDecrypter decrypter = new MassDecrypter();
            decrypter.MassDecrypt(fullLogPath, logPath);
            Console.WriteLine($"Mass decrypt logs written to {fullLogPath} and {logPath}.");
        }

    }
}
