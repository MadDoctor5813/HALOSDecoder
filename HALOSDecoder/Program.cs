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

        const string fullCascadeLogPath = "cascade_log_full.txt";
        const string cascadeLogPath = "cascade_log.txt";

        public static void Main(string[] args)
        {
            Console.WriteLine("Starting mass decryption...");
            MassDecrypter decrypter = new MassDecrypter();
            decrypter.MassDecrypt(fullLogPath, logPath);
            Console.WriteLine($"Mass decrypt logs written to {fullLogPath} and {logPath}.");
            Console.WriteLine("Starting cascade decryption...");
            CascadeDecrypter cascade = new CascadeDecrypter();
            cascade.CascadeDecrypt(fullCascadeLogPath, cascadeLogPath);
            Console.WriteLine($"Cascade decrypt logs written to {fullCascadeLogPath} and {cascadeLogPath}.");
        }

    }
}
