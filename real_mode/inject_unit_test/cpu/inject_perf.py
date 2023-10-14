# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, in_proto, ipv4, tcp
from ryu.lib.packet import ether_types
from ryu.lib import hub
from ipaddress import IPv4Network, IPv4Address
import psutil
import random
import time 

MAGIC_ETHADDR = '00:00:00:10:00:00'
MAGIC_SRCADDR = '10.0.0.1'

class InjectorPerf(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(InjectorPerf, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_to_host = {}
        self.mac_to_pkts = {}
        self.dpid_to_dp = {}
        self.pkt_num = 100
        self.mon_start = False 
        hub.spawn(self.inject_routine)
        hub.spawn(self.monitor_routine)

    def make_packets(self):
        self.mac_to_pkts.clear()
        start_time = time.time()
        make_num = 0
        # check environments
        for dpid in self.dpid_to_dp:
            if dpid not in self.mac_to_port:
                print('dpid: {0}, dpid_to_dp: {1}, mac_to_port: {2}'.format(
                    dpid, self.dpid_to_dp, self.mac_to_port))
                return False 
        
        for mac_addr, host_addr in self.mac_to_host.items():
            for _ in range(self.pkt_num):
                pkt = packet.Packet()
                pkt.add_protocol(ethernet.ethernet(
                    ethertype = ether_types.ETH_TYPE_IP,
                    dst = mac_addr,
                    src = MAGIC_ETHADDR # outside domain
                ))
            
                lst_addr = host_addr.split('.')
                lst_addr[-1] = str(random.randint(1, 254))
                dst_addr = '.'.join(lst_addr)

                pkt.add_protocol(ipv4.ipv4(
                    proto = in_proto.IPPROTO_TCP,
                    dst = dst_addr,
                    src = MAGIC_SRCADDR # outside host
                ))
                pkt.add_protocol(tcp.tcp(
                    src_port = random.randint(10000, 65535),
                    dst_port = 3260, # storage service port
                    seq = random.randint(1, 2**32),
                    ack = random.randint(1, 2**32),
                ))
                # payload can change
                pkt.add_protocol(b'\x00' * 1440)

                if mac_addr not in self.mac_to_pkts:
                    self.mac_to_pkts[mac_addr] = [pkt]
                else:
                    value = self.mac_to_pkts[mac_addr]
                    value.append(pkt)
                make_num += 1
        print('make {0} pkts done: {1}'.format(make_num,time.time()-start_time))
        return True 

    def inject_packets(self):
        inject_num = 0 
        start_time = time.time()

        for mac_addr in self.mac_to_host:
            for dpid in self.mac_to_port:
                port_dict = self.mac_to_port[dpid]
                port_list = list(port_dict.values())
                outport = self.mac_to_port[dpid][mac_addr]
                if port_list.count(outport) == 1:
                    break

            datapath = self.dpid_to_dp[dpid]
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            for pkt in self.mac_to_pkts[mac_addr]:
                pkt.serialize()
                actions = [parser.OFPActionOutput(
                    port=self.mac_to_port[dpid][mac_addr]
                    )]
                outmsg = parser.OFPPacketOut(datapath=datapath,
                                        buffer_id=ofproto.OFP_NO_BUFFER,
                                        in_port=ofproto.OFPP_CONTROLLER,
                                        actions=actions,
                                        data=pkt.data)         
                datapath.send_msg(outmsg)
                inject_num += 1
        print('inject {0} pkts done: {1}'.format(inject_num, time.time()-start_time))

    def inject_routine(self):
        hub.sleep(30)
        dp_size = len(self.dpid_to_dp)
        host_size = dp_size
        while True:
            if len(self.mac_to_port) >= dp_size and \
                len(self.mac_to_host) >= host_size:
                self.mon_start = True 
                for _ in range(50):
                    if self.make_packets():
                        self.inject_packets()
                    hub.sleep(1)
                print('inject done...')
                self.mon_start = False 
                break
            else:
                print('initializing...')
                hub.sleep(3)

    def monitor_routine(self):
        while True:
            if self.mon_start:
                cpu_percent = psutil.cpu_percent(interval=1)
                with open('cpu_percent_{0}.txt'.format(
                        len(self.dpid_to_dp)), 'a+') as fp:
                    print(cpu_percent)
                    fp.write('{0}\n'.format(cpu_percent))
            else:
                hub.sleep(3)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.dpid_to_dp[datapath.id] = datapath
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        dst = eth.dst
        src = eth.src
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port
            
        if eth.ethertype == ether_types.ETH_TYPE_IP and \
            (src != MAGIC_ETHADDR and dst != MAGIC_ETHADDR):
            _ip = pkt.get_protocol(ipv4.ipv4)
            src_addr, dst_addr = _ip.src, _ip.dst
            self.mac_to_host[src] = src_addr 
            self.mac_to_host[dst] = dst_addr 
        else:
            src_addr, dst_addr = None, None
            
        if dst in self.mac_to_host and \
           dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD 
            
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, 
                                    eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_dst=self.mac_to_host[dst])
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
