from scapy.all import *
import sys

class DumpSeq:
	def __init__(self, rpcap, wtxt, obj):
		self.rpcap = rpcap
		self.wtxt = wtxt
		self.obj = obj

	def dump(self, fp, pkt):
		if TCP in pkt:
			_ip, _tcp = pkt[IP], pkt[TCP]
			data_size = _ip.len - (_ip.ihl + _tcp.dataofs) * 4
			if obj == 'seq':
				if data_size == 0:
					return
				fp.write('{0}\n'.format(_tcp.seq))
			elif obj == 'ack':
				fp.write('{0}\n'.format(_tcp.ack))
			elif obj == 'id':
				fp.write('{0}\n'.format(_ip.id))

	def run(self):
		try:
			reader = PcapReader(self.rpcap)
			with open(self.wtxt, 'w+') as fp:
				for pkt in reader:
					self.dump(fp, pkt)
		except Exception as e:
			print(e)

if __name__ == '__main__':
	for i, opt in enumerate(sys.argv):
		if opt == '-r':
			rpcap = sys.argv[i+1]
		elif opt == '-w':
			wtxt = sys.argv[i+1]
		elif opt == '-s':
			obj = 'seq'
		elif opt == '-a':
			obj = 'ack'
		elif opt == '-i':
			obj = 'id'

	dumper = DumpSeq(rpcap, wtxt, obj)
	dumper.run()