from scapy.all import *
import sys

PREV_SEQ = 0
NEXT_SEQ = 1

class SessionReassembly:
    def __init__(self, fpath):
        self.fpath = fpath
        self.max_gap = 4 * 1460
        # identified segments
        self.known_segments = 0
        # broken segments, not start flags
        self.broken_segments = 0
        # total tcp segments 
        self.total_segments = 0
        # total reassembled sessions
        self.known_sessions = 0
        # total valid sessions
        self.total_sessions = 0
        # tcp session pools 
        self.session_pool = {}
        '''
            session_pool = {
                'first_seq': [(prev_seq, next_seq), ...]
            }
        '''

    def reassemble_once(self, seq_done, seq_list, new_pair):
        if len(seq_list) == 1:
            cur_pair = seq_list[0]
            if new_pair[PREV_SEQ] == cur_pair[NEXT_SEQ]:
                cur_pair[NEXT_SEQ] = new_pair[NEXT_SEQ]
                return True
            elif new_pair[PREV_SEQ] == cur_pair[PREV_SEQ]:
                return True
            else:
                return False 
        else:
            next_pair = None
            for i, cur_pair in enumerate(reversed(seq_list)):
                if new_pair[PREV_SEQ] > cur_pair[NEXT_SEQ]:
                    # last segment
                    if not seq_done and not next_pair:
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
                    if not seq_done and not next_pair:
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
                elif new_pair[PREV_SEQ] == cur_pair[PREV_SEQ]:
                    return True 
                next_pair = cur_pair
            return False 

    def reassemble(self, new_pair, seq_done=False):
        for k, v in self.session_pool.items():
            seq_edge = v['seq_edge']
            seq_list = v['seq_list']
            up_lim, dw_lim = k, seq_edge 
            cond = (
                not v['seq_done'],
                new_pair[PREV_SEQ] >= up_lim,
                new_pair[NEXT_SEQ] < dw_lim
                )
            if not all(cond):
                continue
            
            status = self.reassemble_once(
                seq_done, seq_list, new_pair)
            if status:
                v['seq_done'] = seq_done
                v['seq_edge'] = seq_list[-1][NEXT_SEQ] + self.max_gap
                self.known_segments += 1    
            else:    
                self.broken_segments += 1
            break
            
    def analyze(self, pkt):
        _ip, _tcp = pkt[IP], pkt[TCP]
        seq = _tcp.seq 
        payload_size = _ip.len - 4 * (_ip.ihl + _tcp.dataofs)
        next_seq = seq + payload_size
        if _tcp.flags.S:
            if seq not in self.session_pool:
                self.session_pool[seq] = {
                    'seq_done': False,
                    # SEQ takes 1 offset, thus next_seq+1
                    'seq_list': [[seq, next_seq + 1]],
                    'seq_edge': next_seq + self.max_gap,
                }
            self.known_segments += 1
            self.total_sessions += 1    
        else: 
            seq_done = _tcp.flags.F or _tcp.flags.R
            self.reassemble([seq, next_seq], seq_done)

    def statistic(self):
        reassembled_sessions = 0
        for _, v in self.session_pool.items():
            if len(v['seq_list']) == 1:
                reassembled_sessions += 1
        stat = '''
            ===========================
            total tcp sessions: {0},
            reassembled sessions: {1},
            total tcp segments: {2},
            known tcp segments: {3},
            broken tcp segments: {4},
             ===========================    
            '''.format(self.total_sessions,
                reassembled_sessions,
                self.total_segments,
                self.known_segments,
                self.broken_segments)
        with open('stat.txt', 'w+') as fp:
            fp.write(stat)

        with open('session.txt', 'w+') as fp:
            for k, v in self.session_pool.items():
                fp.write('{0}: {1}\n'.format(k,v))
        print(stat) 

    def run(self):
        try:
            reader = PcapReader(self.fpath)
            for pkt in reader:
                if TCP in pkt:
                    self.total_segments += 1
                    self.analyze(pkt)
                if self.total_segments % 1000 == 0:
                    stat = '''
                ===========================
                total tcp sessions: {0},
                total tcp segments: {1},
                known tcp segments: {2},
                broken tcp segments: {3},
                ===========================    
                '''.format(self.total_sessions,
                    self.total_segments,
                    self.known_segments,
                    self.broken_segments)
                    print(stat)
            self.statistic()
        except Exception as e:
            print(e)

if __name__ == '__main__':
    for i, opt in enumerate(sys.argv):
        if opt == '-r':
            fpath = sys.argv[i+1]
    r = SessionReassembly(fpath)
    r.run()