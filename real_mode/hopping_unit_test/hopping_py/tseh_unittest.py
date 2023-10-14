from scapy.all import *
import hmac
import sys

hopping_key = bytes([
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff 
 ])


class RCEH:
    def __init__(self, rpath, wpath, ival, choice):
        self.rpath = rpath	
        self.wpath = wpath
        self.ival = ival #ms
        self.choice = choice
        self.opera_units = {'hopping': self.hopping, 'dehopping': self.dehopping}
    
    def hopping(self, pkt, start_time):
        timestamp = int((pkt.time - start_time) * 1000) // self.ival
        _ip, _tcp = pkt[IP], pkt[TCP]
        ip_src = int.from_bytes(inet_pton(socket.AF_INET, _ip.src), 'big')
        ip_dst = int.from_bytes(inet_pton(socket.AF_INET, _ip.dst), 'big')
        # generate digest
        hobj = hmac.new(hopping_key, timestamp.to_bytes(4, 'big'), digestmod='md5')
        digest = hobj.digest()
        
        ip_src = ip_src ^ int.from_bytes(digest[0:1], 'big')
        ip_dst = ip_dst ^ int.from_bytes(digest[1:2], 'big')
        _ip.src = inet_ntop(socket.AF_INET, ip_src.to_bytes(4, 'big'))
        _ip.dst = inet_ntop(socket.AF_INET, ip_dst.to_bytes(4, 'big'))
        _tcp.sport = _tcp.sport ^ int.from_bytes(digest[2:4], 'big')
        _tcp.dport = _tcp.dport ^ int.from_bytes(digest[4:6], 'big')
        if 'SEQ' in self.choice:
           _tcp.seq = _tcp.seq ^ int.from_bytes(digest[6:10], 'big')
           _tcp.ack = _tcp.ack ^ int.from_bytes(digest[10:14], 'big')
        if 'ID' in self.choice:
            _ip.id = _ip.id ^ int.from_bytes(digest[14:16], 'big')
        return pkt
    
    def dehopping(self, pkt, start_time):
        return self.hopping(pkt, start_time)
    
    def run(self, opera):
        opera_func = self.opera_units[opera]
        try:
            reader = PcapReader(self.rpath)
            writer = PcapWriter(self.wpath, append=True)
            start_time = 0
            for pkt in reader:
                if IP not in pkt or TCP not in pkt:
                    continue
                if start_time == 0:
                    start_time = pkt.time
                new_pkt = opera_func(pkt, start_time)
                writer.write(new_pkt) 
            writer.close()
        except Scapy_Exception as e:
            print(e)

if __name__ == '__main__':
    choice = []
    for i, opt in enumerate(sys.argv):
        if opt == '-r':
            rpath = sys.argv[i+1]
        elif opt == '-w':
            wpath = sys.argv[i+1]
        elif opt == '-t':
            ival = int(sys.argv[i+1])
        elif opt == '-id':
            choice.append('ID')
        elif opt == '-seq':
            choice.append('SEQ')
        elif opt == '-h':
            opera = 'hopping'
        elif opt == '-d':
            opera = 'dehopping'
    sobj = RCEH(rpath, wpath, ival, choice)
    sobj.run(opera)
