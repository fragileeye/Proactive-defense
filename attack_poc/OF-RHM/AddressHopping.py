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
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import in_proto
from ryu.lib.dpid import *
import random
from ipaddress import *

class AddressHopping(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AddressHopping, self).__init__(*args, **kwargs)
        self.route_table = self.init_def_routes() 
        self.hopping_map = {}

#####################################################################
# system initialization, initialize default routes, and the channel 
# between switch and controller, and the table miss.
#####################################################################
    def install_table_miss(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # {dest_ip: outport} , and default taken as C-type network.
    def init_def_routes(self):
        s1_rules = {'192.168.100.0/24': 2, '192.168.200.0/24': 3, '10.168.100.0/24': 1}
        s2_rules = {'192.168.100.0/24': 2, '192.168.200.0/24': 3, '10.168.100.0/24': 1}
        s3_rules = {'192.168.100.0/24': 3, '192.168.200.0/24': 2, '10.168.100.0/24': 1}
        s4_rules = {'192.168.100.1': 3, '192.168.100.2': 4, '10.168.100.0/24': 1, '192.168.200.0/24':2}
        s5_rules = {'192.168.200.1': 3, '192.168.200.2': 4, '10.168.100.0/24': 1, '192.168.100.0/24':2}
        return [s1_rules, s2_rules, s3_rules, s4_rules, s5_rules]

    #install default rules for eatch switch
    def install_def_routes(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        if type(dpid) == str:
            dpid = str_to_dpid(dpid)
        rules = self.route_table[dpid - 1]
        for k, v in rules.items():
            #add ip routes
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst=k)
            actions = [parser.OFPActionOutput(v)]
            self.add_flow(datapath, 0, match, actions)
            #add arp routes! vital
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP,arp_tpa=k)
            actions = [parser.OFPActionOutput(v)]
            self.add_flow(datapath, 0, match, actions)            

    def install_hop_event(self, datapath):
        hopping_list = [1, 4, 5]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        if type(dpid) == str:
            dpid = str_to_dpid(dpid)
        if dpid in hopping_list:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ip_proto=in_proto.IPPROTO_TCP,
                                    tcp_flags=tcp.TCP_SYN)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            #set the priority to 1
            self.add_flow(datapath, 1, match, actions)

    #packet with syn, would be taken as tcp session start
    def is_session_start(self, pkt):
        _eth = pkt.get_protocol(ethernet.ethernet)
        if _eth.ethertype == ether_types.ETH_TYPE_IP:
            _ip = pkt.get_protocol(ipv4.ipv4)
            if _ip.proto == in_proto.IPPROTO_TCP:
                _tcp = pkt.get_protocol(tcp.tcp)
                if _tcp.has_flags(tcp.TCP_SYN):
                    return True
        return False

####################################################################################
#  some util functions and core functions for setting hopping and dehopping mechanism
#
####################################################################################
    def extract_addrs(self, pkt):
        _ip = pkt.get_protocol(ipv4.ipv4)
        return (_ip.src, _ip.dst)

    def extract_ports(self, pkt):
        _tcp = pkt.get_protocol(tcp.tcp)
        return (_tcp.src_port, _tcp.dst_port)

    def extract_outport(self, datapath, target_ip):
        dpid = datapath.id
        if type(dpid) == str:
            dpid = str_to_dpid(dpid)
        switch_routes = self.route_table[dpid-1]
        best_fitness, best_fitport = 0, 0
        target_addr = IPv4Address(target_ip)
        for k, v in switch_routes.items():
            addr = IPv4Network(k)
            if target_addr in addr and addr.prefixlen > best_fitness:
                best_fitness = addr.prefixlen
                best_fitport = v
        assert best_fitport != 0
        return best_fitport
            
    def hopping_addrs(self, src_ip, dst_ip):
        splited_sip = src_ip.split('.')
        splited_sip[-1] = str(random.randint(1, 254))
        splited_dip = dst_ip.split('.')
        splited_dip[-1] = str(random.randint(1, 254))
        return ('.'.join(splited_sip), 
                '.'.join(splited_dip))


    def hopping_ports(self, src_port, dst_port):
        return (random.randint(1025, 65535), 
                random.randint(1025, 65535))

    #the internal hopping process.
    #direction = 1, indicate the outgoing direction
    #direction = 0, indicate the incoming direction
    def hopping_internal(self, datapath, map_key, map_value, direction):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
    
        src_ip, src_port, dst_ip, dst_port = map_key
        src_ip_h, src_port_h, dst_ip_h, dst_port_h = map_value 

        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, 
                                ipv4_src=src_ip, 
                                ipv4_dst=dst_ip,
                                ip_proto=in_proto.IPPROTO_TCP,
                                tcp_src=src_port, 
                                tcp_dst=dst_port)

        target_ip = dst_ip if direction else dst_ip_h

        outport = self.extract_outport(datapath, target_ip)

        actions = [parser.OFPActionSetField(ipv4_src=src_ip_h),
                   parser.OFPActionSetField(ipv4_dst=dst_ip_h),
                   parser.OFPActionSetField(tcp_src=src_port_h),
                   parser.OFPActionSetField(tcp_dst=dst_port_h),
                   parser.OFPActionOutput(outport)]

        #self.add_timeout_flow(datapath, 2, match, actions, 30)
        #make it faster as to timeout
        self.add_timeout_flow(datapath, 2, match, actions, 10, 'hard')


    def hopping_routine(self, datapath, map_key):
        src_ip, src_port, dst_ip, dst_port = map_key
        src_ip_h, dst_ip_h = self.hopping_addrs(src_ip, dst_ip)
        src_port_h, dst_port_h = self.hopping_ports(src_port, dst_port)

        #hopping when forwarding
        map_value = (src_ip_h, src_port_h, dst_ip_h, dst_port_h)
        self.hopping_map[map_key] = map_value
        self.hopping_internal(datapath, map_key, map_value, 1)

        #hopping back
        re_map_key = (dst_ip_h, dst_port_h, src_ip_h, src_port_h)
        re_map_value = (dst_ip, dst_port, src_ip, src_port)
        self.hopping_internal(datapath, re_map_key, re_map_value, 0)

    def dehopping_routine(self, datapath, map_key, map_value):
        src_ip, src_port, dst_ip, dst_port = map_key
        src_ip_h, src_port_h, dst_ip_h, dst_port_h = map_value

        de_map_key = (src_ip_h, src_port_h, dst_ip_h, dst_port_h)
        de_map_value = (src_ip, src_port, dst_ip, dst_port)
        self.hopping_internal(datapath, de_map_key, de_map_value, 0)

        re_map_key = (dst_ip, dst_port, src_ip, src_port)
        re_map_value = (dst_ip_h, dst_port_h, src_ip_h, src_port_h)
        self.hopping_internal(datapath, re_map_key, re_map_value, 1)

    def dispatch_hopping(self, datapath, end_ips, end_ports):
        dpid = int(datapath.id)
        src_ip, dst_ip = end_ips
        src_port, dst_port = end_ports
        map_key = (src_ip, src_port, dst_ip, dst_port) 
        
        if map_key not in self.hopping_map:
            self.hopping_routine(datapath, map_key)
        else:
            map_value = self.hopping_map[map_key]
            self.dehopping_routine(datapath, map_key, map_value)

    def dispatch_forwarding(self, msg, target_ip):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inport = msg.match['in_port']
        outport = self.extract_outport(datapath, target_ip)
        actions = [parser.OFPActionOutput(outport)]
        out_msg = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=inport, actions=actions, data=msg.data)
        datapath.send_msg(out_msg)



##################################################################################
#      system routes: packet_in, switch_features, flow_removed, add_flow...
#
##################################################################################
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = datapath.id
        raw_pkt  = packet.Packet(msg.data)

        if type(dpid) == str:
            dpid = str_to_dpid(dpid)

        hopping_list = [1, 4, 5]
        #make switch 1, 4, 5 hopping, and switch 2, 3 forwarding as default
        if dpid in hopping_list:
            if self.is_session_start(raw_pkt):
                end_ips = self.extract_addrs(raw_pkt)
                end_ports = self.extract_ports(raw_pkt)
                self.dispatch_hopping(datapath, end_ips, end_ports)
                #forwarding this packet by controller, based on dst ip
                self.dispatch_forwarding(msg, end_ips[1])


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        #install default routes according to route_table
        self.install_def_routes(datapath)
        #install table miss handler
        self.install_table_miss(datapath)
        #install trigger event for tcp session starting
        self.install_hop_event(datapath)


    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        match = msg.match
        datapath = msg.datapath
        ofproto = datapath.ofproto

        if msg.reason == ofproto.OFPRR_IDLE_TIMEOUT or \
           msg.reason == ofproto.OFPRR_HARD_TIMEOUT:
            if match['ip_proto'] == in_proto.IPPROTO_TCP:
                src_ip, src_port = match['ipv4_src'], match['tcp_src']
                dst_ip, dst_port = match['ipv4_dst'], match['tcp_dst']
                map_key = (src_ip, src_port, dst_ip, dst_port)   
                if map_key in self.hopping_map:
                    self.hopping_routine(datapath, map_key)
                else:
                    map_key = (dst_ip, dst_port, src_ip, src_port)
                    if map_key in self.hopping_map:
                        map_value = self.hopping_map[map_key]
                        self.dehopping_routine(datapath, map_key, map_value)

####################################################################################
#              `add_timeout_flow` and `add_flow` routine
#
####################################################################################
    def add_timeout_flow(self, datapath, priority, match, actions, timeout, mode='idle'):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if mode == 'idle':
            mod = parser.OFPFlowMod(datapath=datapath, 
                                    priority=priority,
                                    match=match, 
                                    instructions=inst, 
                                    idle_timeout=timeout,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM)
            datapath.send_msg(mod)
        elif mode == 'hard':
            mod = parser.OFPFlowMod(datapath=datapath, 
                                    priority=priority,
                                    match=match, 
                                    instructions=inst, 
                                    hard_timeout=timeout,
                                    flags=ofproto.OFPFF_SEND_FLOW_REM)
        datapath.send_msg(mod)
        

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