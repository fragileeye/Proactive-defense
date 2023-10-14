using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SimSharp;
using System.IO;
using Gnu.Getopt;
using System.Threading;

namespace SimProcess
{
    class Program
    {
        private static readonly int M = 1; //1500 for seq attack
        private static readonly int s = 0;
        private static readonly double t0 = 1; //1 packet per unit
        private static double t1 = 1;//148809; //how many packets per unit
        private static int units = 0;
        private static List<int> listN = new List<int>();
        private static List<int> liste = new List<int>();
        private static readonly int length = 11;
        private static string filename;

        static void Main(string[] args)
        {
            int ch;
            LongOpt[] opt = new LongOpt[3];

            opt[0] = new LongOpt("hopping interval", Argument.Required, null, 't');
            opt[1] = new LongOpt("filename", Argument.Required, null, 'f');
            opt[2] = new LongOpt("help", Argument.Optional, null, 'h');

            Getopt getopt = new Getopt("SimSeqAttack", args, "-:t:f:h", opt);
            while((ch = getopt.getopt()) != -1)
            {
                switch(ch)
                {
                    case 't':
                        int.TryParse(getopt.Optarg, out units);
                        t1 = t1 * units;
                        break;

                    case 'f':
                        filename = getopt.Optarg;
                        break;

                    case 'h':
                        break;

                    default:
                        Console.WriteLine("invalid parameters!");
                        break;
                }
            }

            for(int i = 1; i < length; ++i)
            {
                //listN.Add(50 * i);
                //liste.Add(50000 * i);
                listN.Add(50 * i);
                liste.Add(100 * i);
            }

            foreach (var N in listN)
            {
                foreach (var e in liste)
                {
                    DateTime start_time = DateTime.Now;
                    var sim = new SeqAttack(N, M, s, e, t1, t0);
                    var rate = sim.simulate();

                    string result = string.Format("N: {0}, e: {1}, t1: {2}, rate: {3}", N, e, t1, rate);

                    using (StreamWriter fs = new StreamWriter(filename, true))
                    {
                        fs.WriteLine(result + "\r\n");
                    }
                    
                    var delta_time = (DateTime.Now - start_time).ToString();
                    Console.WriteLine(result);
                    Console.WriteLine("colapse time: {0}\n", delta_time);
                    Thread.Sleep(5000); //sleep to collect garbage
                }
            }
            
        }
    }
}
