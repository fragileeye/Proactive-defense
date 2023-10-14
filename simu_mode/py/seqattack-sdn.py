import random
import getopt
import sys
import simpy
import random
import copy
import datetime

'''
L: sequence space
N: session count
M: segment size
s: low limit of segments count
e: high limit of segments count
T: time to finish all sessions
t0: minimal time slice to transmit a segment
t1: time slice for hopping
'''
class Sim_Switch:
    def __init__(self, env, res, t1, t0, seqs, segs, L, N, M):
        self.env = env 
        self.res = res
        self.t1 = t1
        self.t0 = t0
        self.L = L
        self.N = N
        self.M = M
        self.seqs = seqs
        self.seq_set = [{seq} for seq in seqs]
        self.seq_dict = {i: seqs[i] for i in range(N)}

    #ignore the process of packeted_in, cause we don't care about this
    #we just attend to the packets forwarding in links and the sequence number of them. 
    def forwarding(self, packets):
        #idx indicates each shuffled segments
        for idx in packets:
            with self.res.request() as req:
                yield req
                #increase the seq num of this session which is identified by idx
                self.seq_dict[idx] = (self.seq_dict[idx] + self.M) % self.L 
                #forwarding segment of this session
                yield self.env.timeout(self.t0)
                #print('forwarding id: {0}'.format(idx))

    def hopping(self, times):
        while times > 0:
            yield self.env.timeout(self.t1)
            with self.res.request() as req:
                yield req
                #record current seq num during hopping
                for k, v in self.seq_dict.items():
                    self.seq_set[k].add(v) 
                times -= 1       
                #print('hopping times left: {0}'.format(times))   

    def if_collision(self, si, sj):
        if abs(self.seqs[si] - self.seqs[sj]) % self.M == 0 and  \
            len(self.seq_set[si] & self.seq_set[sj]) > 0:
            return True
        return False

    def statistic(self):
        collision = 0
        collision_set = set()
        for i in range(self.N):
            if i in collision_set: 
                continue
            collision_size = collision
            for j in range(i+1, self.N):
                if self.if_collision(i, j):
                    collision += 1
                    collision_set.add(j)
            # index i collsion
            if collision > collision_size: 
                collision += 1
        return float(collision) / self.N


class SeqAttack_SDN:
    def __init__(self, N, M, s, e, t1, t0):
        self.L = 2**32
        self.N = N
        self.M = M
        self.t1 = t1
        self.t0 = t0
        self.segs = [random.randint(s, e) for i in range(self.N)]
        self.seqs = [random.randint(0, self.L) for i in range(self.N)]       
        self.seg_sum = sum(self.segs)

    #normal ordered
    #packets = (i for i in self.range(self.N) for k in range(self.segs))
    #random handle a packet
    # def gen_packets(self):
    #     record_segs = copy.deepcopy(self.segs)
    #     record_sum = self.seg_sum
    #     print('sum of packets: {0}'.format(record_sum))
    #     while record_sum > 0:
    #         seg_idx = random.randint(1, record_sum)
    #         for i in range(self.N):
    #             if seg_idx > record_segs[i]:
    #                 seg_idx -= record_segs[i]
    #             else:
    #                 seg_idx = i
    #                 break
    #         yield seg_idx
    #         record_segs[seg_idx] -= 1
    #         record_sum -= 1

    def gen_packets(self):
        record_segs = copy.deepcopy(self.segs)
        record_sum = self.seg_sum
        print('sum of packets: {0}'.format(record_sum))
        while record_sum > 0:
            seg_idx = random.randint(1, record_sum)
            for i in range(self.N):
                if seg_idx > record_segs[i]:
                    seg_idx -= record_segs[i]
                else:
                    seg_idx = i
                    break
            yield seg_idx
            record_segs[seg_idx] -= 1
            record_sum -= 1

    def simulate(self):
        env = simpy.Environment()
        res = simpy.Resource(env, capacity=1)   
        packets = self.gen_packets()
        hopping_times = int(self.seg_sum * self.t0) // self.t1 + 1
        self.switch = Sim_Switch(env, res, self.t1, self.t0, self.seqs, 
                                    self.segs, self.L, self.N, self.M)
        env.process(self.switch.forwarding(packets))
        env.process(self.switch.hopping(hopping_times))
        env.run()
        collison_rate = self.switch.statistic()
        return collison_rate

def print_useage():
    usage = '''
        Usage: SeqAttack_SDN.py\n
        \t -N <sessions> \n
        \t -M <segment_size> \n
        \t -s <low_segments> \n
        \t -e <high_segments> \n
        \t -t1 <hopping interval> \n
        \t -t0 <transmit interval> \n
    '''
    print(usage)

def main():
    N, M, s, e, t1, t0 = [0] * 6
    try:
        opts, args = getopt.getopt(sys.argv[1:], "N:M:s:e:t1:t0")
        for opt_name, opt_value in opts:
            if opt_name == '-N':
                N = int(opt_value)
            elif opt_name == '-M':
                M = int(opt_value)
            elif opt_name == '-s':
                s = int(opt_value)
            elif opt_name == '-e':
                e = int(opt_value)
            elif opt_name == '-t1':
                t1 = float(opt_value)
            elif opt_name == '-t0':
                t0 = float(opt_value)
    except:
        print_useage()
        sys.exit()

    sim = SeqAttack_SDN(N, M, s, e, t1, t0)
    printf("collision rate: {0}".format(sim.simulate()))

def auto_test():
    M = 1500
    s = 100

    #assume we need 0.01 timeslice to handle a packet
    t0 = 0.01

    #60s (SDN)
    #measure under 80Mbps 
    #0.01s->1packet, 10s->1000packets->80Mbps
    t1 = 6000

    N_list = [500*i for i in range(1, 11)]
    e_list = [100000*i for i in range(1,11)]

    with open('seqattack-sdn.txt', 'wb+') as fp:
        for N in N_list:
            for e in e_list:
                #for t1 in t1_list:
                sim = SeqAttack_SDN(N, M, s, e, t1, t0)
                result = "N: {0}, e: {1}, t1: {2}, rate: {3}\r\n".format(N, e, t1, sim.simulate())
                print(result)
                fp.write(result.encode())

if __name__ == '__main__':
    # main()
    auto_test()





            