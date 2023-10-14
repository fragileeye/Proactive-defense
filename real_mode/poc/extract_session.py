from scapy.all import *
import sys 

class ExtractSession:
    def __init__(self, rpath, wpath, is_full=True):
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

    def stat(self):
        for k, v in self.session_map.items():
            print(k, v)

if __name__ == '__main__':
    for i, opt in enumerate(sys.argv):
        if opt == '-r':
            rpath = sys.argv[i+1]
        elif opt == '-w':
            wpath = sys.argv[i+1]
        elif opt == '-f':
            is_full = int(sys.argv[i+1])
    extract = ExtractSession(rpath, wpath, is_full)
    extract.run()
    extract.stat()
    