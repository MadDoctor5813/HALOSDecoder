using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HALOSDecoder
{

    public enum LogLevel
    {
        Default,
        Important
    }


    public class Logger
    {

        public string Name { get; }
        public string LogPath { get; }
        public string FullLogPath { get; }
        
        public StreamWriter LogStream { get; }
        public StreamWriter FullLogStream { get; }

        public Logger(string name)
        {
            this.Name = name;
            LogPath = $"{name}_log.txt";
            FullLogPath = $"{name}_log_full.txt";
            LogStream = new StreamWriter(new FileStream(LogPath, FileMode.Create, FileAccess.Write));
            LogStream.AutoFlush = true;
            FullLogStream = new StreamWriter(new FileStream(FullLogPath, FileMode.Create, FileAccess.Write));
            FullLogStream.AutoFlush = true;
        }

        public void Log(string log, LogLevel level = LogLevel.Default)
        {
            if (level == LogLevel.Default)
            {
                FullLogStream.WriteLine(log);
            }
            else if (level == LogLevel.Important)
            {
                FullLogStream.WriteLine(log);
                LogStream.WriteLine(log);
            }
        }

        public void Log(DecryptResult decryptResult)
        {
            if (decryptResult.DistinctBytes > 180)
            {
                decryptResult.WriteToFile(FullLogStream);
            }
            else
            {
                decryptResult.WriteToFile(FullLogStream);
                decryptResult.WriteToFile(LogStream);
            }
        }
    }
}
