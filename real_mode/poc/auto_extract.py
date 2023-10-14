from multiprocessing import Process 
from scapy.all import *
import os 
import sys 

class AutoExtract(Process):
    def __init__(self, rpath, wpath, is_full):
        super().__init__()
        self.rpath = rpath 
        self.wpath = wpath
        self.is_full = is_full
        self.session_map = dict()

    def extract_full_sessions(self):
        try:
            reader = PcapReader(self.rpath)
            for pkt in reader:
                if TCP in pkt:
                    _ip, _tcp = pkt[IP], pkt[TCP]
                    key = (_ip.src, _tcp.sport)
                    if _tcp.flags.S and not _tcp.flags.SA:
                        self.session_map[key] = 1 
                    elif key in self.session_map:
                        self.session_map[key] += 1
            reader = PcapReader(self.rpath)
            writer = PcapWriter(self.wpath, append=True)
            for pkt in reader:
                if TCP in pkt:
                    _ip, _tcp = pkt[IP], pkt[TCP]
                    key = (_ip.src, _tcp.sport)
                    if self.session_map.get(key, 0) > 1:
                        writer.write(pkt)
            writer.close()
        except Exception as e:
            print(e)

    def extract_all_sessions(self):
        try:
            reader = PcapReader(self.rpath)
            writer = PcapWriter(self.wpath, append=True)
            for pkt in reader:
                if TCP in pkt:
                    _ip, _tcp = pkt[IP], pkt[TCP]
                    key = (_ip.src, _tcp.sport)
                    if _tcp.flags.S and not _tcp.flags.SA:
                        self.session_map[key] = 0 
                        writer.write(pkt)
                    elif key in self.session_map:
                        self.session_map[key] += 1
                        writer.write(pkt)
            writer.close()
        except Exception as e:
            print(e)
    
    def run(self):
        if self.is_full:
            self.extract_full_sessions()
        else:
            self.extract_all_sessions()

def main():
    for i, opt in enumerate(sys.argv):
        if opt == '-r':
            dir_path = sys.argv[i+1]
    if not os.path.exists(dir_path):
        print('{0} does not exist.'.format(dir_path))
        return 
    out_path = os.path.join(dir_path, 'full_session')
    if not os.path.exists(out_path):
        print('{0} does not exist.'.format(out_path))
        os.mkdir(out_path)
    ps_list = []
    for fname in os.listdir(dir_path):
        if not fname.startswith('univ1_pt'):
            continue
        rpath = os.path.join(dir_path, fname)
        wpath = os.path.join(out_path, fname+'_ss')
        # print('read path: {0}, write path: {1}'.format(rpath, wpath))
        extractor = AutoExtract(rpath, wpath, True)
        ps_list.append(extractor)
        extractor.start()
    for extractor in ps_list:
        extractor.join()

if __name__ == '__main__':
    main()

