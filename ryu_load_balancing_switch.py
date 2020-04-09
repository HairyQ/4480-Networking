from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import ethernet, arp, ether_types, packet

# This app was built on top of the simple_switch_13.py app
#  linked in the ryu documentation. Keeps track of a bool that
#  serves as an 'alternating bit' to determine which server
#  interacts with a client so that the load is balanced between
#  the two servers, setting up the appropriate flows and
#  alternating the bit each time a new client ARP's the virtual
#  IP address
class LoadBalancingSwitch(app_manager.RyuApp):

    # Hardcoded addresses, ports
    V_IP  = '10.0.0.10'
    H1_IP = '10.0.0.1'
    H2_IP = '10.0.0.2'
    H3_IP = '10.0.0.3'
    H4_IP = '10.0.0.4'
    H5_IP = '10.0.0.5'
    H6_IP = '10.0.0.6'

    H1_MAC = '00:00:00:00:00:01'
    H2_MAC = '00:00:00:00:00:02'
    H3_MAC = '00:00:00:00:00:03'
    H4_MAC = '00:00:00:00:00:04'
    H5_MAC = '00:00:00:00:00:05'
    H6_MAC = '00:00:00:00:00:06'

    H1_PORT = 1
    H2_PORT = 2
    H3_PORT = 3
    H4_PORT = 4
    H5_PORT = 5
    H6_PORT = 6

    ip_to_port = {H1_IP : H1_PORT, 
                  H2_IP : H2_PORT, 
                  H3_IP : H3_PORT, 
                  H4_IP : H4_PORT}

    # Alternating "bit" for load balancing
    alt = True

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LoadBalancingSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, 
                                    eth_dst=dst, 
                                    eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        # ARP request - must reply, modify switch OF rules
        # This is hit when out_port == ofproto.OFPP_FLOOD
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            if pkt.get_protocol(arp.arp).opcode == arp.ARP_REQUEST:

                # Case: client requests server MAC
                if pkt.get_protocol(arp.arp).dst_ip == self.V_IP:

                    # Match for flow from client to server, regardless of which 
                    # actual server is being used
                    match = parser.OFPMatch(in_port = in_port, 
                                            eth_type = 0x800, 
                                            ipv4_dst = self.V_IP)

                    returned_mac = None

                    # Load balancing: choose address based on alternating 'bit'
                    if self.alt:
                        returned_mac = self.H5_MAC
                        actions = [parser.OFPActionSetField(ipv4_dst = self.H5_IP), 
                                   parser.OFPActionOutput(self.H5_PORT)]

                        # Set OF rules for client -> server
                        self.add_flow(datapath, 1, match, actions)
                        match = parser.OFPMatch(eth_type = 0x800, 
                                                in_port = self.H5_PORT, 
                                                ipv4_src = self.H5_IP, 
                                                ipv4_dst = pkt.get_protocol(arp.arp).src_ip)
                        actions = [parser.OFPActionSetField(ipv4_src = self.V_IP), 
                                   parser.OFPActionOutput(self.ip_to_port[pkt.get_protocol(arp.arp).src_ip])]
                        
                        # Set OF rules for server -> client
                        self.add_flow(datapath, 1, match, actions)
                    else:
                        returned_mac = self.H6_MAC
                        actions = [parser.OFPActionSetField(ipv4_dst = self.H6_IP), 
                                   parser.OFPActionOutput(self.H6_PORT)]

                        
                        # Set OF rules for client -> server
                        self.add_flow(datapath, 1, match, actions)
                        match = parser.OFPMatch(eth_type = 0x800, 
                                                in_port = self.H6_PORT, 
                                                ipv4_src = self.H6_IP, 
                                                ipv4_dst = pkt.get_protocol(arp.arp).src_ip)
                        actions = [parser.OFPActionSetField(ipv4_src = self.V_IP), 
                                   parser.OFPActionOutput(self.ip_to_port[pkt.get_protocol(arp.arp).src_ip])]
                        
                        
                        # Set OF rules for server -> client
                        self.add_flow(datapath, 1, match, actions)

                    # Alternate bit for next request
                    self.alt = not self.alt

                    # Build arp reply
                    e = ethernet.ethernet(dst = pkt.get_protocol(arp.arp).src_mac, 
                                          src = returned_mac, 
                                          ethertype = ether.ETH_TYPE_ARP)

                    a = arp.arp(opcode = arp.ARP_REPLY, 
                                src_mac = returned_mac, 
                                src_ip = self.V_IP, 
                                dst_mac = pkt.get_protocol(arp.arp).src_mac, 
                                dst_ip = pkt.get_protocol(arp.arp).src_ip)

                    p = packet.Packet()
                    p.add_protocol(e)
                    p.add_protocol(a)
                    p.serialize()

                    actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]

                    # Send OF reply from controller
                    out = parser.OFPPacketOut(datapath = datapath, 
                                              buffer_id = ofproto.OFP_NO_BUFFER, 
                                              in_port = in_port, 
                                              actions = actions, 
                                              data = p.data)

                    datapath.send_msg(out)
                    return

                # Case: server requests client MAC
                else:
                    returned_mac = None

                    if pkt.get_protocol(arp.arp).dst_ip == self.H1_IP:
                        returned_mac = self.H1_MAC
                    elif pkt.get_protocol(arp.arp).dst_ip == self.H2_IP:
                        returned_mac = self.H2_MAC
                    elif pkt.get_protocol(arp.arp).dst_ip == self.H3_IP:
                        returned_mac = self.H3_MAC
                    elif pkt.get_protocol(arp.arp).dst_ip == self.H4_IP:
                        returned_mac = self.H4_MAC

                    # Build arp reply
                    e = ethernet.ethernet(dst = pkt.get_protocol(arp.arp).src_mac, 
                                          src = returned_mac, 
                                          ethertype = ether.ETH_TYPE_ARP)

                    a = arp.arp(opcode = arp.ARP_REPLY, 
                                src_mac = returned_mac, 
                                src_ip = pkt.get_protocol(arp.arp).dst_ip, 
                                dst_mac = pkt.get_protocol(arp.arp).src_mac, 
                                dst_ip = pkt.get_protocol(arp.arp).src_ip)

                    p = packet.Packet()
                    p.add_protocol(e)
                    p.add_protocol(a)
                    p.serialize()

                    actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
                    out = parser.OFPPacketOut(datapath = datapath, 
                                              buffer_id = ofproto.OFP_NO_BUFFER, 
                                              in_port = in_port, 
                                              actions = actions, 
                                              data = p.data)

                    datapath.send_msg(out)
                    return

        # Normal behavior - important to leave this in so that initial ping 
        # can be sent following ARP
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, 
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port, 
                                  actions=actions, data=data)
        datapath.send_msg(out)

