from scapy.all import *
from ipaddress import IPv4Network, IPv4Address
import os 
import sys 

class StatDomain:
    def __init__(self, rpath, wpath):
        self.rpath = rpath
        self.wpath = wpath 
        self.domain_map = {}

    def run(self):
        try:
            reader = PcapReader(self.rpath)
            for pkt in reader:
                if TCP in pkt:
                    _ip, _tcp = pkt[IP], pkt[TCP]
                    addr_list = _ip.dst.split('.') 
                    addr_list[-1] = '0'
                    key = IPv4Network('{0}/24'.format('.'.join(addr_list)))
                    if _tcp.flags.S and not _tcp.flags.A:
                        if key not in self.domain_map:
                            self.domain_map[key] = {
                                'sessions': 1,
                                'segments': 1,
                            } 
                        else:
                            value = self.domain_map[key]
                            value['sessions'] += 1
                            value['segments'] += 1
                    elif key in self.domain_map:
                        value = self.domain_map[key]
                        value['segments'] += 1
            
            with open(self.wpath, 'w+') as fp:
                stat_num = 0
                for k, v in self.domain_map.items():
                    sessions = v['sessions']
                    segments = v['segments']
                    fp.write('{0} sessions: {1}, segments: {2}\n'.format(k, sessions, segments))
                    stat_num += v['segments'] 
                print('total segments: {0}'.format(stat_num))
        except Exception as e:
            print(e)

def main():
    for i, opt in enumerate(sys.argv):
        if opt == '-r':
            rpath = sys.argv[i+1]
        elif opt == '-w':
            wpath = sys.argv[i+1]
    stat = StatDomain(rpath, wpath)
    stat.run() 

if __name__ == '__main__':
    main() 