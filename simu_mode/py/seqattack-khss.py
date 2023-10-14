import random
import getopt
import sys

'''
L: sequence space
N: session count
M: segment size
s: low limit of segments count
e: high limit of segments count
T: time to finish all sessions
'''

class Sim_SeqAttack:
    def __init__(self, N, M, s, e):
        self.L = 2**32
        self.N = N
        self.M = M
        self.s = s
        self.e = e
        self.size = [random.randint(s, e) for i in range(N)]
        self.seqs = [random.randint(0, self.L) for i in range(N)]
        self.collision = 0

    def if_divided(self, s, e):
        if s <= e:
            return (e - s) % self.M == 0
        else:
            return (self.L - s + e) % self.M == 0

    def if_overlap(self, dist, size):
        return (self.M * size)  >= dist

    def if_collison(self, seq_s, seq_e, size_s, size_e):
        if seq_s <= seq_e:
            dist1 = seq_e - seq_s
            dist2 = self.L - seq_e + seq_s
            if self.if_divided(seq_s, seq_e) and self.if_overlap(dist1, size_s): 
                return True
            if self.if_divided(seq_e, seq_s) and self.if_overlap(dist2, size_e):
                return True
            return False 
        else:
            dist1 = seq_s - seq_e
            dist2 = self.L - seq_s + seq_e
            if self.if_divided(seq_e, seq_s) and self.if_overlap(dist1, size_e):
                return True
            if self.if_divided(seq_s, seq_e) and self.if_overlap(dist2, size_s):
                return True
            return False

    def start_sim(self):
        collision_set = set()
        for i in range(self.N):
            if i in collision_set: 
                continue
            collision_size = self.collision
            for j in range(i+1, self.N):
                if self.if_collison(self.seqs[i], self.seqs[j],
                                    self.size[i], self.size[j]):
                    self.collision += 1
                    collision_set.add(j)
            # index i collsion
            if self.collision > collision_size: 
                self.collision += 1

    def stop_sim(self):
        self.rate = self.collision / self.N
        # print('================================')
        # print('N: {0}, M: {1}, s: {2}, e: {3}'.format(self.N, self.M, self.s, self.e))
        # print('collision rate: {0}'.format(self.rate))
        # print('================================')
        

    def auto_sim(self):
        self.start_sim()
        self.stop_sim()
        return self.rate

def print_useage():
    print('Usage: Sim_SeqAttack.py\n\t -N <sessions>\n\t -M <segment_size>\n\t -s <low_segments>\n\t -e <high_segments>')

def main():
    N, M, s, e = [0] * 4
    try:
        opts, args = getopt.getopt(sys.argv[1:], "N:M:s:e:")
        for opt_name, opt_value in opts:
            if opt_name == '-N':
                N = int(opt_value)
            elif opt_name == '-M':
                M = int(opt_value)
            elif opt_name == '-s':
                s = int(opt_value)
            elif opt_name == '-e':
                e = int(opt_value)
    except:
        print_useage()
        sys.exit()

    sim = Sim_SeqAttack(N, M, s, e)
    sim.auto_sim()

def auto_test():
    M = 1500
    s = 100
    repeat = 10

    e_list = [100000*i for i in range(1, 11)]
    N_list = [500*i  for i in range(1, 11)]
    
    with open('seqattack-khss.txt', 'wb+') as fp:
        for N in N_list:
            for e in e_list:
                rates = []
                for k in range(repeat):
                    sim = Sim_SeqAttack(N, M, s, e)
                    rates.append(sim.auto_sim())
                average_rate = sum(rates) / repeat
                result = "N: {0}, e: {1}, rate: {2}\r\n".format(N, e, average_rate)
                print(result)
                fp.write(result.encode())

    
if __name__ == '__main__':
    # main()
    auto_test()





            