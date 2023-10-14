from mininet.topo import Topo

class MyTopo( Topo ):
	def __init__(self):
		super(MyTopo, self).__init__(self)
		
		h1 = self.addHost('h1', mac='00:00:00:00:00:01', ip='192.168.100.1')
		h2 = self.addHost('h2', mac='00:00:00:00:00:02', ip='192.168.100.2')
		h3 = self.addHost('h3', mac='00:00:00:00:00:03', ip='192.168.200.1')
		h4 = self.addHost('h4', mac='00:00:00:00:00:04', ip='192.168.200.2')
		h5 = self.addHost('h5', mac='00:00:00:00:00:05', ip='10.168.100.10')

		s1 = self.addSwitch('s1', dpid='1')
		s2 = self.addSwitch('s2', dpid='2')
		s3 = self.addSwitch('s3', dpid='3')
		s4 = self.addSwitch('s4', dpid='4')
		s5 = self.addSwitch('s5', dpid='5')

		#from up to bottom
		self.addLink(s1, h5, port1=1)
		self.addLink(s1, s2, port1=2, port2=1)
		self.addLink(s1, s3, port1=3, port2=1)

		self.addLink(s2, s4, port1=2, port2=1)
		self.addLink(s2, s5, port1=3, port2=2)

		self.addLink(s3, s5, port1=2, port2=1)
		self.addLink(s3, s4, port1=3, port2=2)

		self.addLink(s4, h1, port1=3)
		self.addLink(s4, h2, port1=4)

		self.addLink(s5, h3, port1=3)
		self.addLink(s5, h4, port1=4)

topos = {'mytopo': (lambda : MyTopo())}