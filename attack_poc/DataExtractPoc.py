'''
this program is a poc of verifying the 'one-way'(such as upload only) communication, which could be 
reconstructed only by [seq/ack] on some scale. So the 'session' we call in this program indicates 
the half session represents client to server.
'''

from io import BytesIO
from impacket.ImpactDecoder import *
from impacket.pcapfile import *
import socket
import struct

class SignatureManager:
    def __init__(self, signature):
        self.ack = self.first_seq = self.seq = signature['seq']
        self.start_time = self.end_time = signature['time']
        self.session_done = signature['done']
        self.buffer = BytesIO()
    
    # miss order, should handle these things
    # adjust first_seq, end_time, data 
    def _update_missorder(self, signature, data):
        seq = signature['seq']
        #adjust first_seq
        if seq < self.first_seq:
            delta = self.first_seq - seq
            self.first_seq = seq
            new_buffer = BytesIO(data)
            new_buffer.seek(delta)
            new_buffer.write(self.buffer.getvalue())
            self.buffer.close()
            self.buffer = new_buffer
        elif seq < self.seq:
            delta = seq - self.first_seq 
            self.buffer.seek(delta)
            self.buffer.write(data)
        #adjust end_time
        self.end_time = signature['time']   
        
    def _update_overlap(self, signature, data):
        self._update_normal(True, signature, data)
        
    def _update_emptyhole(self, signature, data):
        self._update_normal(True, signature, data)
    
    def _update_normal(self, c_2_s, signature, data):
        self.end_time = signature['time']
        seq, ack = signature['seq'], signature['ack']
        
        if c_2_s:
            self.seq = seq     
            if len(data) > 0:
                delta = seq - self.first_seq
                self.buffer.seek(delta)
                self.buffer.write(data)
        else:
            self.ack = ack
        
    def update(self, c_2_s, signature, data):
        seq, ack, stop = signature['seq'], signature['ack'], signature['done']
        if stop:
            self._update_normal(c_2_s, signature, data)
            return        
        
        if c_2_s:
            #miss order
            if seq < self.seq:
                self._update_missorder(signature, data)
            #retransmit or start to transmit data
            elif seq == self.seq:
                self._update_normal(c_2_s, signature, data)
            else: 
                #overlap
                if seq < self.ack:
                    self._update_overlap(signature, data)
                #normal 
                elif seq == self.ack:
                    self._update_normal(c_2_s, signature, data)
                #empty hole
                else:
                    self._update_emptyhole(signature, data)
        #s->c, only handle ack >= self.ack, or it's abnormal, just ignore
        elif ack >= self.ack:
            self._update_normal(c_2_s, signature, data)       
                         
    def extract_data(self):
        return self.buffer.getvalue()
    
    
class SessionManager:
    def __init__(self):
        self.hash_size = 1331
        self.hash_session = {} 
    
    def _get_hashvalue(self, connection):
        src_addr, dst_addr, src_port, dst_port = connection
        hash_value = (src_addr + dst_addr + src_port + dst_port) % self.hash_size        
        return hash_value
    
    def _get_bucket(self, connection):
        hash_value = self._get_hashvalue(connection)
        return self.hash_session.get(hash_value, None)    
    
    def _get_session(self, sessions, connection):
        src_addr, src_port, dst_addr, dst_port = connection
        for session in sessions:
            curr_conn, _ = session
            _src_addr, _src_port, _dst_addr, _dst_port = curr_conn
            result_match = (_src_addr == src_addr and _dst_addr == dst_addr \
                            and _src_port == src_port and _dst_port == dst_port) or (
                            _src_addr == dst_addr and _dst_addr == src_addr \
                            and _src_port == dst_port and _dst_port == src_port)
            if result_match: 
                return session
        return None
    
    # 1: c->s, 0: s->c
    def _get_direction(self, session, connection):
        curr_conn, _ = session
        return all([curr_conn[i] == connection[i] for i in range(4)])
            
    def add_session(self, connection, signature):
        hash_value = self._get_hashvalue(connection)       
        sessions = self.hash_session.get(hash_value, None)   
        sig_manager = SignatureManager(signature)
        if not sessions:
            sessions = [(connection, sig_manager)]
        else:
            sessions.append((connection, sig_manager))
        self.hash_session.update({hash_value : sessions})
            
    def del_session(self, connection):
        sessions = self._get_bucket(connection)        
        if not sessions:
            return
        target_session = self._get_session(sessions, connection)
        if not target_session:
            return
        sessions.remove(target_session)
        
    def update_session(self, connection, signature, data):
        # define signature
        sessions = self._get_bucket(connection)
        if not sessions:
            return
        target_session = self._get_session(sessions, connection)
        if not target_session:
            return
        _, sig_manager = target_session
        direction = self._get_direction(target_session, connection)
        sig_manager.update(direction, signature, data)
    
    def find_session(self, connection):
        sessions = self._get_bucket(connection)
        if not sessions:
            return False
        target_session = self._get_session(sessions, connection)
        if not target_session:
            return False
        return True
        
    def traverse_sessions(self):
        for k, v in self.hash_session.items():
            for session in v:
                curr_conn, sig_mgr = session
                src_addr, src_port, dst_addr, dst_port = curr_conn
                src_addr = socket.inet_ntoa(struct.pack('!I', src_addr))
                dst_addr = socket.inet_ntoa(struct.pack('!I', dst_addr))
                print('{0}({1}) <-> {2}({3})'.format(src_addr, src_port, dst_addr, dst_port))
                print('seq: {0} - ack: {1}'.format(sig_mgr.seq, sig_mgr.ack))
                data = sig_mgr.extract_data()
                print('time: {0} - {1}\ndata: {2}'.format(sig_mgr.start_time, sig_mgr.end_time, data))
    
    # it's strange that impacket couldn't get time from pcap correctly!
    # so we don't use endtime for filtering.
    def merge_sessions(self, reversed_sessions):
        for i, session in enumerate(reversed_sessions):
            curr_conn, sig_mgr = session
            for last_session in reversed_sessions[i+1:]:
                _, last_sig_mgr = last_session
                if sig_mgr.start_time > last_sig_mgr.end_time and sig_mgr.first_seq == last_sig_mgr.ack:
                    last_sig_mgr.buffer.seek(0, 2)
                    last_sig_mgr.buffer.write(sig_mgr.buffer.getvalue())
                    last_sig_mgr.ack = sig_mgr.ack
                    last_sig_mgr.end_time = sig_mgr.end_time
                    #essential to del session cause we've merged this session with its last one
                    self.del_session(curr_conn) 
                    
    def rebuild_sessions(self):
        def cmp_keys(session):
            curr_conn, sig_mgr = session
            start_time, first_seq = sig_mgr.start_time, sig_mgr.first_seq
            return (first_seq, start_time)
        
        sessions = []    
        for v in self.hash_session.values():
            for session in v: 
                sessions.append(session)
        reversed_sessions = sorted(sessions, key=cmp_keys, reverse=True)
        self.merge_sessions(reversed_sessions)
        self.traverse_sessions()
        
class SessionReconstructor:    
    PCAP_TYPE = 0
    PACKET_TYPE = 1
    def __init__(self, pkt_type):
        self.pkt_type = pkt_type
        self.session_manager = SessionManager()
        self.eth_decoder = EthDecoder()
        self.ip_decoder =  IPDecoder() 
        self.tcp_decoder = TCPDecoder()
    
    def _make_connection(self, ip_packet, tcp_packet):
        if ip_packet and tcp_packet:
            src_addr, dst_addr = ip_packet.get_long(12), ip_packet.get_long(16)
            src_port, dst_port = tcp_packet.get_th_sport(), tcp_packet.get_th_dport()
            connection = (src_addr, src_port, dst_addr, dst_port)        
            return connection
        return None

    def _make_signature(self, tcp_packet, time):
        seq, ack, fin, rst = tcp_packet.get_th_seq(), tcp_packet.get_th_ack(), \
            tcp_packet.get_FIN(), tcp_packet.get_RST()
        signature = {'seq' : seq, 'ack' : ack, 'done': fin or rst, 'time' : time}
        return signature
    
    def _split_packet(self, packet):
        packet_data = packet['data']
        packet_time = packet['tsec'] + packet['tmsec'] / 1000000
        ether_packet = self.eth_decoder.decode(packet_data)
        if ether_packet.get_ether_type() != ImpactPacket.IP.ethertype:
            return None
        ether_body = ether_packet.get_data_as_string()
        ip_packet = self.ip_decoder.decode(ether_body)
        if ip_packet.get_ip_p() != ImpactPacket.TCP.protocol:
            return None
        ip_body = ip_packet.get_data_as_string()
        tcp_packet = self.tcp_decoder.decode(ip_body)
        tcp_body = tcp_packet.get_data_as_string()
        split_info = (ip_packet, tcp_packet, tcp_body, packet_time)
        return split_info
    
    def _handle_packet(self, packet):
        split_info = self._split_packet(packet)
        if not split_info:
            return
        ip_packet, tcp_packet, data, time = split_info
        connection = self._make_connection(ip_packet, tcp_packet)
        signature = self._make_signature(tcp_packet, time)
        if not self.session_manager.find_session(connection):
            self.session_manager.add_session(connection, signature)
        self.session_manager.update_session(connection, signature, data)
            
    def handle_pcapfile(self, filename=None):
        pcap = PcapFile(fileName = filename)
        for packet in pcap.packets():
            self._handle_packet(packet)
    
    def handle_rawpackets(self, packets):
        for packet in packets:
            self._handle_packet(packet)
    
    def packet_handler(self, pkt_or_fname):
        if self.pkt_type == SessionReconstructor.PACKET_TYPE:
            self.handle_rawpackets(pkt_or_fname)
        elif self.pkt_type == SessionReconstructor.PCAP_TYPE:
            self.handle_pcapfile(pkt_or_fname)
        else:
            raise 
        #self.session_manager.traverse_sessions()
        self.session_manager.rebuild_sessions()

def main():
    sr = SessionReconstructor(SessionReconstructor.PCAP_TYPE)
    sr.packet_handler("hopping.pcap")
    
if __name__ == '__main__':
    main()
    