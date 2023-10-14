from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel
from functools import partial

class MyTopo(Topo):
	def __init__(self):
		super(MyTopo, self).__init__(self)
		self.init_topo()

	def init_topo(self):
		last_s = None 
		for i in range(1, 19):
			s = self.addSwitch('s%d' %i)
			host = self.addHost('h%d' %i, ip='192.168.%d.1' %i)
			self.addLink(host, s)
			if i > 1:
				self.addLink(last_s, s)
			else:
				last_s = s
			
def main():
	setLogLevel('info')
	topo = MyTopo()
	# OVSSwitch13 = partial(OVSSwitch, protocols='OpenFlow13')
	controller = RemoteController('c0', ip='127.0.0.1', port=6653)
	net = Mininet(topo=topo, controller=controller)
	net.start()
	CLI(net)
	net.stop()
	
if __name__ == '__main__':
	main()
