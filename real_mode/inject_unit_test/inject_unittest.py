from scapy.all import *
import sys
import random

class Inject:
	def __init__(self, rpath, wpath, prob):
		self.rpath = rpath
		self.wpath = wpath
		self.prob = prob

	def gen_pkt(self, pkt):
		new_pkt = pkt.copy()
		_ip, _tcp = new_pkt[IP], new_pkt[TCP]
		src_addr = _ip.src.split('.')
		dst_addr = _ip.dst.split('.')
		src_addr[-1] = str(random.randint(1,255))
		dst_addr[-1] = str(random.randint(1,255))
		_ip.src = '.'.join(src_addr)
		_ip.id = random.randint(0, 2**16-1)
		_ip.dst = '.'.join(dst_addr)
		_tcp.sport = random.randint(0, 2**16-1)
		_tcp.dport = random.randint(0, 2**16-1)
		_tcp.seq = random.randint(0, 2**32-1)
		_tcp.ack = random.randint(0, 2**32-1)
		return new_pkt

	def run(self):
		try:
			reader = PcapReader(self.rpath)
			writer = PcapWriter(self.wpath, append=True)
			for pkt in reader:
				if TCP not in pkt:
					continue
				writer.write(pkt)
				if random.random() <= self.prob:
					new_pkt = self.gen_pkt(pkt)
					writer.write(new_pkt)
			writer.close()
		except Exception as e:
			print(e)

if __name__ == '__main__':
	for i, opt in enumerate(sys.argv):
		if opt == '-r':
			rpath = sys.argv[i+1]
		elif opt == '-w':
			wpath = sys.argv[i+1]
		elif opt == '-p':
			prob = float(sys.argv[i+1])
	injector = Inject(rpath, wpath, prob)
	injector.run()