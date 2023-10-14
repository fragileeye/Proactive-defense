from scapy.all import *
from Crypto.Cipher import AES 
import sys

encrypt_key = bytes([
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
])

i_vector = bytes([
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
    0x12, 0x34, 0x56, 0x78, 
    0xab, 0xcd, 0xef, 0xff,
])


class P4NIS:
    def __init__(self, rpath, wpath, choice):
        self.rpath = rpath
        self.wpath = wpath
        self.choice = choice
        self.opera_units = {'hopping': self.hopping, 'dehopping': self.dehopping}
        self.aes = AES.new(encrypt_key, AES.MODE_CBC, i_vector)
        
    def hopping(self, pkt):
        text = raw(pkt)
        # generate digest
        while len(text) % 16 != 0:
            text += b'\x00'
        digest = self.aes.encrypt(text)

        _ip, _tcp = pkt[IP], pkt[TCP]
        ip_src = int.from_bytes(inet_pton(socket.AF_INET, _ip.src), 'big')
        ip_dst = int.from_bytes(inet_pton(socket.AF_INET, _ip.dst), 'big')

        # hopping 
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

    def dehopping(self, pkt):
        text = raw(pkt)
        # generate digest
        digest = self.aes.decrypt(text)
        _ip, _tcp = pkt[IP], pkt[TCP]
        ip_src = int.from_bytes(inet_pton(socket.AF_INET, _ip.src), 'big')
        ip_dst = int.from_bytes(inet_pton(socket.AF_INET, _ip.dst), 'big')

        # hopping 
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

    def run(self, opera):
        opera_func = self.opera_units[opera]
        try:
            reader = PcapReader(self.rpath)
            writer = PcapWriter(self.wpath, append=True)
            for pkt in reader:
                if IP not in pkt or TCP not in pkt:
                    continue
                new_pkt = opera_func(pkt)
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
        elif opt == '-id':
            choice.append('ID')
        elif opt == '-seq':
            choice.append('SEQ')
        elif opt == '-h':
            opera = 'hopping'
        elif opt == '-d':
            opera = 'dehopping'
    sobj = P4NIS(rpath, wpath, choice)
    sobj.run(opera)