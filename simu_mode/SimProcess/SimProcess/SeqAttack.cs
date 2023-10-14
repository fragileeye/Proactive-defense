using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SimSharp;

namespace SimProcess
{
    class SeqAttack
    {
        private int N;
        private int M;
        private double t1;
        private double t0;
        private List<int> segs = new List<int>();
        private List<uint> seqs = new List<uint>();
        private long seg_sum = 0;
        
        public SeqAttack(int N, int M, int s, int e, double t1, double t0)
        {
            this.N = N;
            this.M = M;
            this.t1 = t1;
            this.t0 = t0;

            Random rand = new Random();

            for(int i = 0; i < this.N; ++i)
            {
                this.segs.Add(rand.Next(s, e));
                // for seq attack, here is the int range, while for id attack, here is the short range
                // this.seqs.Add((uint)rand.Next(int.MinValue, int.MaxValue));
                this.seqs.Add((uint)rand.Next(short.MinValue, short.MaxValue));
                this.seg_sum += this.segs[i];
            }
        }

        private IEnumerable<int> gen_packets()
        {
            List<int> record_segs = new List<int>(this.segs);
            long record_sum = this.seg_sum;

            Console.WriteLine("sum of packets: {0}", record_sum);
            Random rand = new Random();

            while(record_sum > 0)
            {
                long seg_idx = (long)(1 + rand.NextDouble() * (record_sum - 1));

                for(int i = 0; i < this.N; ++i)
                {
                    if(seg_idx > record_segs[i])
                    {
                        seg_idx -= record_segs[i];
                    }
                    else
                    {
                        seg_idx = i;
                        break;
                    }
                }

                int session_idx = (int)seg_idx;
                yield return session_idx;

                record_segs[session_idx]--;
                record_sum--;
            }
        }
        

        public double simulate()
        { 
            var env = new Simulation();
            var res = new Resource(env, capacity: 1);
            var packets = gen_packets();
            var sim_switch = new SimSwitch(env, res, this.t1, this.t0, this.seqs, this.segs, this.N, this.M);

            env.Process(sim_switch.forwarding(packets));
            env.Process(sim_switch.hopping());
            env.Run();
    
            return sim_switch.statistic();
        }
    }
}
