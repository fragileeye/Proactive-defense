from multiprocessing import Process 
from scapy.all import *
import os 
import sys 

PREV_SEQ = 0
NEXT_SEQ = 1

class AutoReassemble(Process):
    def __init__(self, rpath):
        super().__init__()
        self.rpath = rpath
        self.max_gap = 4 * 1460
        # total tcp segments 
        self.total_segments = 0
        # total valid sessions
        self.total_sessions = 0
        # tcp session pools 
        self.session_pool = {}
        '''
            session_pool = {
                'first_seq': [(prev_seq, next_seq), ...]
            }
        '''

    def reassemble_once(self, session_done, seq_list, new_pair):
        if len(seq_list) == 1:
            cur_pair = seq_list[0]
            if new_pair[PREV_SEQ] == cur_pair[NEXT_SEQ]:
                cur_pair[NEXT_SEQ] = new_pair[NEXT_SEQ]
                return True
            elif new_pair[NEXT_SEQ] == cur_pair[NEXT_SEQ]:
                return True
            else:
                return False 
        else:
            next_pair = None
            for i, cur_pair in enumerate(reversed(seq_list)):
                if new_pair[PREV_SEQ] > cur_pair[NEXT_SEQ]:
                    # last segment
                    if not session_done and not next_pair:
                        seq_list.append(new_pair)
                        return True
                    elif new_pair[NEXT_SEQ] == next_pair[PREV_SEQ]:
                        next_pair[PREV_SEQ] = new_pair[PREV_SEQ]
                        return True
                    elif new_pair[NEXT_SEQ] < next_pair[PREV_SEQ]:
                        seq_list.insert(-i, new_pair)
                        return True
                    else:
                        return False 
                elif new_pair[PREV_SEQ] == cur_pair[NEXT_SEQ]:
                    if not session_done and not next_pair:
                        cur_pair[NEXT_SEQ] = new_pair[NEXT_SEQ]
                        return True
                    elif new_pair[NEXT_SEQ] < next_pair[PREV_SEQ]:
                        cur_pair[NEXT_SEQ] = new_pair[NEXT_SEQ]
                        return True
                    elif new_pair[NEXT_SEQ] == next_pair[PREV_SEQ]:
                        cur_pair[NEXT_SEQ] = next_pair[NEXT_SEQ]
                        seq_list.pop(-(i+1))
                        return True
                    else:
                        return False
                elif new_pair[NEXT_SEQ] == cur_pair[NEXT_SEQ]:
                    return True 
                next_pair = cur_pair
            return False 

    def reassemble(self, new_pair, session_done=False):
        for k, v in self.session_pool.items():
            seq_edge = v['seq_edge']
            seq_list = v['seq_list']
            up_lim, dw_lim = k, seq_edge 
            cond = (
                not v['session_done'],
                new_pair[PREV_SEQ] >= up_lim,
                new_pair[NEXT_SEQ] < dw_lim
                )
            if not all(cond):
                continue
            
            if self.reassemble_once(
                session_done, seq_list, new_pair):
                v['segments'] += 1
                v['session_done'] = session_done
                v['seq_edge'] = seq_list[-1][NEXT_SEQ] + self.max_gap
            break
            
    def analyze(self, pkt):
        _ip, _tcp = pkt[IP], pkt[TCP]
        seq = _tcp.seq 
        payload_size = _ip.len - 4 * (_ip.ihl + _tcp.dataofs)
        next_seq = seq + payload_size
        if _tcp.flags.S and not _tcp.flags.SA:
            if seq not in self.session_pool:
                self.session_pool[seq] = {
                    'session_done': False,
                    # SEQ takes 1 offset, thus next_seq+1
                    'seq_list': [[seq, next_seq + 1]],
                    'seq_edge': next_seq + self.max_gap,
                    'segments': 1,
                }
                self.total_sessions += 1
            else:
                self.session_pool[seq]['segments'] += 1
        else: 
            session_done = _tcp.flags.F or _tcp.flags.R
            self.reassemble([seq, next_seq], session_done)
        self.total_segments += 1

    def statistic(self):
        reassembled_sessions = 0
        reassembled_segments = 0
        dir_path, fname = os.path.split(self.rpath)
        stat_path = os.path.join(dir_path, fname+'_stat.txt')
        sess_path = os.path.join(dir_path, fname+'_sses.txt')
        for _, v in self.session_pool.items():
            if len(v['seq_list']) == 1 and v['session_done']:
                reassembled_sessions += 1
                reassembled_segments += v['segments']
        stat = '''
            ===========================
            total tcp sessions: {0},
            reassembled sessions: {1},
            total tcp segments: {2},
            reassembled segments: {3},
            ===========================    
            '''.format(self.total_sessions,
                reassembled_sessions,
                self.total_segments,
                reassembled_segments)

        with open(stat_path, 'w+') as fp:
            fp.write(stat)

        with open(sess_path, 'w+') as fp:
            for k, v in self.session_pool.items():
                fp.write('{0}: {1}\n'.format(k,v))

    def run(self):
        try:
            reader = PcapReader(self.rpath)
            for pkt in reader:
                if TCP in pkt:
                    self.analyze(pkt)
            self.statistic()
        except Exception as e:
            print(e)

def main():
    for i, opt in enumerate(sys.argv):
        if opt == '-r':
            dir_path = sys.argv[i+1]
    if not os.path.exists(dir_path):
        print('{0} does not exist.'.format(dir_path))
        return 
    ps_list = []
    for fname in os.listdir(dir_path):
        if not fname.startswith('univ1_pt'):
            continue
        rpath = os.path.join(dir_path, fname)
        ps = AutoReassemble(rpath)
        ps_list.append(ps)
        ps.start()
    for ps in ps_list:
        ps.join()

if __name__ == '__main__':
    main()