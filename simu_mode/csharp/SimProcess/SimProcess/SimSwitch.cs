using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SimSharp;

namespace SimProcess
{
    class SimSwitch
    {
        private readonly uint L = uint.MaxValue;
        private Simulation env;
        private Resource res;
        private int N;
        private int M;
        private double t1;
        private double t0;
        private List<uint> seqs = new List<uint>();
        private List<int> segs = new List<int>();
        private List<HashSet<uint>> seq_set = new List<HashSet<uint>>();
        private Dictionary<int, long> seq_dict = new Dictionary<int, long>();

        public SimSwitch(Simulation env, Resource res, double t1, double t0,
            List<uint> seqs, List<int> segs, int N, int M)
        {
            this.env = env;
            this.res = res;
            this.N = N;
            this.M = M;
            this.t1 = t1;
            this.t0 = t0;
            this.seqs = seqs;
            this.segs = segs;

            for (int i = 0; i < N; ++i)
            {
                this.seq_set.Add(new HashSet<uint>());
                this.seq_set[i].Add(seqs[i]);
                this.seq_dict.Add(i, seqs[i]);
            }
        }

        public IEnumerable<Event> forwarding(IEnumerable<int> session_idx)
        {
            foreach (int idx in session_idx)
            {
                using (var req = this.res.Request())
                {
                    yield return req;
                    this.seq_dict[idx] = (uint)(this.seq_dict[idx] + this.M) % L;
                    yield return this.env.TimeoutD(this.t0);
                }
            }
        }

        public IEnumerable<Event> hopping()
        {
            long seg_sum = 0;

            foreach(var n in this.segs)
            {
                seg_sum += n;
            }

            int hopping_times = (int)(seg_sum / this.t1);

            while (hopping_times > 0)
            {
                yield return this.env.TimeoutD(this.t1);
                using (var req = this.res.Request())
                {
                    yield return req;
                    foreach (var kv in this.seq_dict)
                    {
                        this.seq_set[kv.Key].Add((uint)kv.Value);
                    }
                }
                hopping_times--;
            }
        }

        public bool if_collision(int si, int sj)
        {
            if (Math.Abs(this.seqs[si] - this.seqs[sj]) % this.M == 0 &&
                this.seq_set[si].Overlaps(this.seq_set[sj]))
            {
                return true;
            }

            return false;
        }

        public double statistic()
        {
            int collision = 0;
            HashSet<int> collision_set = new HashSet<int>();

            for (int i = 0; i < this.N; ++i)
            {
                if (collision_set.Contains(i))
                {
                    continue;
                }

                int collision_size = collision;
                for (int k = i + 1; k < this.N; ++k)
                {
                    if (if_collision(i, k))
                    {
                        collision++;
                        collision_set.Add(k);
                    }
                }

                if (collision > collision_size)
                {
                    collision++;
                }
            }

            return (double)collision / this.N;
        }
    }
}
