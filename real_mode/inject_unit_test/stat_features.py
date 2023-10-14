from scapy.all import *
import sys
import numpy as np
import math 

class StatFeatures:
	def __init__(self, rpath, wpath):
		self.rpath = rpath
		self.wpath = wpath 
		self.ip_dict = {}
		self.port_dict = {}
		self.id_list = []
		self.seq_list = []
		self.ack_list = []
		self.size_mean = 0

	def stat(self):
		ip_entropy = self.calc_shannon_entropy(self.ip_dict, 8)
		port_entropy = self.calc_shannon_entropy(self.port_dict, 16)
		id_entropy = self.calc_permutation_entropy(self.id_list, 3, 1)
		seq_entropy = self.calc_permutation_entropy(self.seq_list, 3, 1)
		ack_entropy = self.calc_permutation_entropy(self.ack_list, 3, 1)
		
		log_info = '''
			[+] ip shannon entropy: {0}, \n
			[+] port shannon entropy: {1},\n
			[+] id permutation entropy : {2},\n
			[+] seq permutation entropy: {3},\n
			[+] ack permutation entropy: {4},\n
			[+] size average: {5}\n
			'''.format(ip_entropy, port_entropy, id_entropy, 
				seq_entropy, ack_entropy, self.size_mean)
		with open(self.wpath, 'w') as fp:
			fp.write(log_info)
		print(log_info)

	def calc_shannon_entropy(self, f_dict, mutation_space):
		values = np.array(list(f_dict.values()))
		value_sum = np.sum(values)
		shannon_entropy = -np.sum([(x/value_sum)*np.log2(x/value_sum) for x in values])	
		return shannon_entropy / mutation_space

	def calc_permutation_entropy(self, f_list, order, delay):
		# construct embed array 
		f_array = np.array(f_list)
		arr_size = len(f_array)
		embed_array = np.empty((order, arr_size - (order - 1) * delay))
		for i in range(order):
			embed_array[i] = f_array[i*delay : i*delay + embed_array.shape[1]]
		embed_array = embed_array.T
		# permutation 
		sorted_idx = embed_array.argsort(kind='quicksort')
		# calculation 
		hash_seed = np.power(order, np.arange(order))
		hash_value = np.sum(np.multiply(sorted_idx, hash_seed), axis=1)
		# counts 
		_, c = np.unique(hash_value, return_counts = True)
		p = np.true_divide(c, c.sum())
		pe = np.sum(-np.multiply(p, np.log2(p)))
		# normalize
		return pe / np.log2(math.factorial(order))
	
	def run(self):
		reader = PcapReader(self.rpath)
	
		for i, pkt in enumerate(reader):
			if TCP in pkt:
				_ip, _tcp = pkt[IP], pkt[TCP]
				if _tcp.flags.R:
					break 
				if _ip.src not in self.ip_dict:
					self.ip_dict[_ip.src] = 1
				else:
					self.ip_dict[_ip.src] += 1
				if _tcp.sport not in self.port_dict:
					self.port_dict[_tcp.sport] = 1
				else:
					self.port_dict[_tcp.sport] += 1
	
				self.id_list.append(_ip.id)
				self.seq_list.append(_tcp.seq)
				self.ack_list.append(_tcp.ack)
				self.size_mean = (i*self.size_mean + _ip.len)/(i+1)
		print('start stating...')
		self.stat()		
		try:
			pass 
		except Exception as e:
			print(e)

if __name__ == '__main__':
	for i, opt in enumerate(sys.argv):
		if opt == '-r':
			rpath = sys.argv[i+1]
		elif opt == '-w':
			wpath = sys.argv[i+1]
	stat = StatFeatures(rpath, wpath)
	stat.run()

