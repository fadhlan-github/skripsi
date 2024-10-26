import random
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types, arp, tcp, ipv4, icmp
from ryu.ofproto import ether, inet
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.topology import switches

#from ryu.app.sdnhub_apps import learning_switch

class NetworkTopology:
    def __init__(self):
        self.network = {}
        self.pheromone = {}
        # Track learned MAC and IP addresses
        self.mac_to_port = {}
        self.ip_to_dpid = {}
        
    def add_link(self, dpid1, dpid2, port1, port2, capacity=1000):
        """Add bidirectional link between switches"""
        if dpid1 not in self.network:
            self.network[dpid1] = {}
        if dpid2 not in self.network:
            self.network[dpid2] = {}
            
        # Add forward and reverse links with port information
        self.network[dpid1][dpid2] = {'port': port1, 'capacity': capacity, 'load': 0}
        self.network[dpid2][dpid1] = {'port': port2, 'capacity': capacity, 'load': 0}
        
        # Initialize pheromone levels
        self.pheromone[(dpid1, dpid2)] = 1.0
        self.pheromone[(dpid2, dpid1)] = 1.0
    
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	
    _CONTEXTS = {'switches': switches.Switches}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.serverlist=[]                                                              #Creating a list of servers
        self.virtual_lb_ip = "10.0.0.100"                                               #Virtual Load Balancer IP
        self.virtual_lb_mac = "AB:BC:CD:EF:AB:BC"                                          #Virtual Load Balancer MAC Address
        self.counter = 0                                                                #Used to calculate mod in server selection below
        self.threads = []
        self.pheromone = {}
        self.topology = NetworkTopology()
        self.datapaths = {}
        self.topology_api_app = self
        self.switches = kwargs['switches']
        self.min_pheromone = 0.1  # Minimum pheromone level
        self.max_pheromone = 5.0  # Maximum pheromone level
        
        #Appending all given IP's, assumed MAC's and ports of switch to which servers are connected to the list created
        self.serverlist.append({'ip':"10.0.0.4", 'mac':"00:00:00:00:00:04", "outport":"4", 'active': True, 'switch': 4})             
        self.serverlist.append({'ip':"10.0.0.2", 'mac':"00:00:00:00:00:02", "outport":"2", 'active': True, 'switch': 2})
        self.serverlist.append({'ip':"10.0.0.3", 'mac':"00:00:00:00:00:03", "outport":"3", 'active': True, 'switch': 3})
        print("Done with initial setup related to server list creation.")
        
        self.alpha = 1  # Pheromone importance
        self.beta = 2   # Heuristic importance
        self.evaporation_rate = 0.1
        self.server_stats = {}
		
        self.switch_links = {}  # Store switch links
        self.switch_ports = {}  # Store switch ports
        
        self.pheromone = {'10.0.0.3': 1.0, '10.0.0.2': 1.0, '10.0.0.4': 1.0}
        
        for server in self.serverlist:
            self.server_stats[server['ip']] = {'last_response_time': 1.0,  # Start with neutral value
            'requests': 0,'total_response_time': 0}
        
        # Start pheromone evaporation thread
        self.threads.append(hub.spawn(self._pheromone_evaporation_thread))
		
        self.routes = [
		    {'source': 's1', 'destination': 's3'},
		    {'source': 's2', 'destination': 's3'},
		    {'source': 's4', 'destination': 's3'},
		    {'source': 's5', 'destination': 's3'},
		    {'source': 's4', 'destination': 's5'}
		    ]
        
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        """
        Get and store topology data when a switch enters.
        """
        switch_list = get_switch(self.topology_api_app, None)
        switches = [switch.dp.id for switch in switch_list]
        self.switches_list = switches
        
        links_list = get_link(self.topology_api_app, None)
        links = [(link.src.dpid, link.dst.dpid, link.src.port_no, link.dst.port_no) for link in links_list]
        
        # Store switch links and ports
        for src_dpid, dst_dpid, src_port, dst_port in links:
            if src_dpid not in self.switch_links:
                self.switch_links[src_dpid] = []
            if src_dpid not in self.switch_ports:
                self.switch_ports[src_dpid] = set()
                
            self.switch_links[src_dpid].append((dst_dpid, src_port, dst_port))
            self.switch_ports[src_dpid].add(src_port)
            
        self.logger.info("Switches: %s", switches)
        self.logger.info("Links: %s", links)

    def get_out_port(self, src_dpid, dst_dpid):
        """Get the output port for a given source and destination switch"""
        for src, dst, src_port, dst_port in self.links:
            if src == src_dpid and dst == dst_dpid:
                return src_port
        return None

    def get_path_to_server(self, src_dpid, server_dpid):
        """Simple path computation to server switch"""
        if src_dpid == server_dpid:
            return []
        if src_dpid == 3:  # Core switch
            return [(src_dpid, server_dpid)]
        else:
            return [(src_dpid, 3), (3, server_dpid)]
    def switch_enter_handler(self, ev):
        """Handle switch enter event to update topology"""
        switch_list = get_switch(self, None)
        switches = [switch.dp.id for switch in switch_list]
        
        links_list = get_link(self, None)
        for link in links_list:
            self.topology.add_link(
                link.src.dpid,
                link.dst.dpid,
                link.src.port_no,
                link.dst.port_no
            )
        
        # Calculate paths for all source-destination pairs
        self.calculate_all_paths()
    
    def calculate_all_paths(self):
        """Calculate paths for all defined routes"""
        for route in self.routes:
            src_dpid = self.get_dpid_from_name(route['source'])
            dst_dpid = self.get_dpid_from_name(route['destination'])
            if src_dpid and dst_dpid:
                paths = self.find_multipaths(src_dpid, dst_dpid)
                if paths:
                    self.install_paths(paths, src_dpid, dst_dpid)

    def find_multipaths(self, src_dpid, dst_dpid, num_paths=2):
        """Find multiple paths between source and destination switches"""
        paths = []
        for _ in range(num_paths):
            path = self._ant_path_search(src_dpid, dst_dpid)
            if path and self._is_path_diverse(path, paths):
                paths.append(path)
        return paths
    
    def _ant_path_search(self, src_dpid, dst_dpid):
        """Single ant path search implementation"""
        current = src_dpid
        path = [current]
        visited = {current}
        
        while current != dst_dpid:
            next_dpid = self._select_next_switch(current, dst_dpid, visited)
            if not next_dpid:
                return None
                
            path.append(next_dpid)
            visited.add(next_dpid)
            current = next_dpid
            
        return path

    def _select_next_switch(self, current_dpid, dst_dpid, visited):
        """Select next switch based on pheromone and heuristic information"""
        if current_dpid not in self.topology.network:
            return None
            
        neighbors = self.topology.network[current_dpid]
        if not neighbors:
            return None
            
        probabilities = {}
        total = 0
        
        for neighbor_dpid, link_info in neighbors.items():
            if neighbor_dpid in visited:
                continue
                
            pheromone = self.topology.pheromone.get((current_dpid, neighbor_dpid), 1.0)
            # Simple heuristic based on link load
            heuristic = 1.0 / (1 + link_info['load'])
            
            probability = (pheromone ** self.alpha) * (heuristic ** self.beta)
            probabilities[neighbor_dpid] = probability
            total += probability
            
        if not probabilities:
            return None
            
        # Normalize and select
        normalized_probs = {k: v/total for k, v in probabilities.items()}
        switches = list(normalized_probs.keys())
        probs = list(normalized_probs.values())
        
        return random.choices(switches, weights=probs, k=1)[0]

    def _is_path_diverse(self, new_path, existing_paths, threshold=0.5):
        """Check if new path is sufficiently different from existing paths"""
        if not existing_paths:
            return True
            
        for path in existing_paths:
            common_switches = set(new_path) & set(path)
            similarity = len(common_switches) / min(len(new_path), len(path))
            if similarity > threshold:
                return False
        return True

    def install_paths(self, paths, src_dpid, dst_dpid):
        """Install flow rules for all discovered paths"""
        for path in paths:
            self._install_path_flows(path)

    def _install_path_flows(self, path):
        """Install bidirectional flow rules along the path"""
        for i in range(len(path) - 1):
            # Forward direction
            current_dpid = path[i]
            next_dpid = path[i + 1]
            out_port = self.topology.network[current_dpid][next_dpid]['port']
            
            # Get datapath object
            datapath = self.datapaths.get(current_dpid)
            if datapath:
                # Install flow rule
                parser = datapath.ofproto_parser
                match = parser.OFPMatch(eth_type=0x0800)  # Match IPv4 traffic
                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 1, match, actions)
                
                # Install reverse flow rule
                in_port = self.topology.network[next_dpid][current_dpid]['port']
                datapath_next = self.datapaths.get(next_dpid)
                if datapath_next:
                    match = parser.OFPMatch(eth_type=0x0800)
                    actions = [parser.OFPActionOutput(in_port)]
                    self.add_flow(datapath_next, 1, match, actions)

    def get_dpid_from_name(self, switch_name):
        """Convert switch name (e.g., 's1') to datapath ID"""
        try:
            return int(switch_name[1:])  # Assumes format 's1', 's2', etc.
        except:
            return None
	
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

    def function_for_arp_reply(self, dst_ip, dst_mac):                                      #Function placed here, source MAC and IP passed from below now become the destination for the reply ppacket 
        print("(((Entered the ARP Reply function to build a packet and reply back appropriately)))")
        arp_target_ip = dst_ip
        arp_target_mac = dst_mac
        src_ip = self.virtual_lb_ip                         #Making the load balancers IP and MAC as source IP and MAC
        src_mac = self.virtual_lb_mac

        arp_opcode = 2                          #ARP opcode is 2 for ARP reply
        hardware_type = 1                       #1 indicates Ethernet ie 10Mb
        arp_protocol = 2048                       #2048 means IPv4 packet
        ether_protocol = 2054                   #2054 indicates ARP protocol
        len_of_mac = 6                  #Indicates length of MAC in bytes
        len_of_ip = 4                   #Indicates length of IP in bytes

        pkt = packet.Packet()
        ether_frame = ethernet.ethernet(dst_mac, src_mac, ether_protocol)               #Dealing with only layer 2
        arp_reply_pkt = arp.arp(hardware_type, arp_protocol, len_of_mac, len_of_ip, arp_opcode, src_mac, src_ip, arp_target_mac, dst_ip)   #Building the ARP reply packet, dealing with layer 3
        pkt.add_protocol(ether_frame)
        pkt.add_protocol(arp_reply_pkt)
        pkt.serialize()
        print("{{{Exiting the ARP Reply Function as done with processing for ARP reply packet}}}")
        return pkt
		
    def _pheromone_evaporation_thread(self):
        while True:
            self.logger.info("Evaporating pheromones...")
            for server_ip in self.pheromone:
                current_value = self.pheromone[server_ip]
            # Apply evaporation
                new_value = current_value * (1 - self.evaporation_rate)
            # Ensure value stays within bounds
                new_value = max(self.min_pheromone, min(self.max_pheromone, new_value))
                self.pheromone[server_ip] = new_value
                self.logger.info(f"Server {server_ip} pheromone: {new_value:.3f}")
            hub.sleep(10)  # Check every 10 seconds

	
    def aco_server_selection(self):
        total = 0
        server_weights = []
    
        for server in self.serverlist:
            pheromone = self.pheromone[server['ip']]
        # Use average response time for better load balancing
            avg_response_time = (
			self.server_stats[server['ip']]['total_response_time'] / 
            max(1, self.server_stats[server['ip']]['requests'])
            )
            heuristic = 1.0 / (avg_response_time + 0.1)  # Add small constant to avoid division by zero
            weight = (pheromone ** self.alpha) * (heuristic ** self.beta)
            server_weights.append(weight)
            total += weight
    
    # Normalize probabilities
        probabilities = [w/total for w in server_weights]
    
    # Select server based on probabilities
        selected_server = random.choices(self.serverlist, weights=probabilities, k=1)[0]
    
    # Update server statistics
        server_ip = selected_server['ip']
        self.server_stats[server_ip]['requests'] += 1
    
    # Simulate response time (in practice, you'd measure actual response time)
        response_time = random.uniform(0.1, 2.0)
        self.server_stats[server_ip]['last_response_time'] = response_time
        self.server_stats[server_ip]['total_response_time'] += response_time
    
    # Update pheromone for selected server
        self.update_pheromone(server_ip, response_time)
    
        return selected_server

        
    def update_pheromone(self, server_ip, response_time):
    # Calculate pheromone deposit based on response time
    # Better response time = more pheromone
        delta_pheromone = 1.0 / (response_time + 0.1)
    
    # Update pheromone with deposit and evaporation
        self.pheromone[server_ip] = (
		(1 - self.evaporation_rate) * self.pheromone[server_ip] +
        delta_pheromone
        )
    
    # Ensure minimum pheromone level
        self.pheromone[server_ip] = max(self.min_pheromone, self.pheromone[server_ip])
    
        self.logger.info(f"Updated pheromone for {server_ip}: {self.pheromone[server_ip]:.3f}")
    
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
        dpid = datapath.id
        #print("Debugging purpose dpid", dpid)
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        eth_dst = eth.dst
        eth_src = eth.src
        
        dst = eth_dst  # Assign to dst
        src = eth_src  # Assign to src

        
        self.logger.info(f"Packet in received at switch {datapath.id}, in_port {in_port}, eth_dst {eth.dst}, eth_src {eth.src}")

        

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        if eth.ethertype == 35020:
            return

        if eth.ethertype == ether.ETH_TYPE_ARP:                                   #If the ethernet frame has eth type as 2054 indicating as ARP packet..  
            arp_header = pkt.get_protocols(arp.arp)[0]
            
            if arp_header.dst_ip == self.virtual_lb_ip and arp_header.opcode == arp.ARP_REQUEST:                 #..and if the destination is the virtual IP of the load balancer and Opcode = 1 indicating ARP Request

                reply_packet=self.function_for_arp_reply(arp_header.src_ip, arp_header.src_mac)    #Call the function that would build a packet for ARP reply passing source MAC and source IP
                actions = [parser.OFPActionOutput(in_port)]
                packet_out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY, data=reply_packet.data, actions=actions, buffer_id=0xffffffff)    
                datapath.send_msg(packet_out)
                # print("::::Sent the packet_out::::")

            else:                                                                                #Not needed as we ARP only for the load balancer MAC address. This is needed when we ARP for other device's MAC 
                
                dst = eth.dst
                src = eth.src
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
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

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
            return
    
        try:
            if pkt.get_protocols(icmp.icmp)[0]:
                dst = eth.dst
                src = eth.src
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
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

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
            return
        except:
            pass
        
        ip_header = pkt.get_protocols(ipv4.ipv4)
        if len(ip_header) > 0:
            ip_header = ip_header[0]
            # Lanjutkan proses
        else:
            # Jika paket bukan IPv4, bisa dilewatkan atau log sebagai informasi
            self.logger.info("Paket bukan IPv4, jenis paket lain mungkin ARP atau IPv6")
            return
        
        if ip_header.proto == inet.IPPROTO_TCP:
            tcp_header = pkt.get_protocols(tcp.tcp)
            if not tcp_header:
                self.logger.warning("Received non-TCP packet, skipping...")
                return
                tcp_header = tcp_header[0]  # extract actual TCP header
        else:
            self.logger.warning("Non-TCP protocol detected, skipping...")
            return

        
        self.logger.info("Paket in diterima dari switch %s di port %s, dst %s, src %s", 
                 dpid, in_port, dst, src)

        # Coba deteksi jenis protokol lain selain IPv4
        arp_header = pkt.get_protocols(arp.arp)
        if len(arp_header) > 0:
            self.logger.info("Paket ARP diterima")
        else:
            self.logger.info("Protokol lain, mungkin IPv6 atau tidak diketahui")

        
        
        #print("IP_Header", ip_header)
        tcp_header = pkt.get_protocols(tcp.tcp)[0]
        #print("TCP_Header", tcp_header)

        selected_server = self.aco_server_selection()
        server_ip_selected = selected_server['ip']
        server_mac_selected = selected_server['mac']
        server_outport_selected = int(selected_server['outport'])
        server_dpid = selected_server['switch']  # Pastikan kunci ini sesuai dengan output
        self.logger.info(f"Selected server: {selected_server['ip']}")


        print("The selected server is ===> ", server_ip_selected)

        
        #Route to server
        match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype, eth_src=eth.src, eth_dst=eth.dst, ip_proto=ip_header.proto, ipv4_src=ip_header.src, ipv4_dst=ip_header.dst, tcp_src=tcp_header.src_port, tcp_dst=tcp_header.dst_port)
        actions = [parser.OFPActionSetField(ipv4_src=self.virtual_lb_ip), parser.OFPActionSetField(eth_src=self.virtual_lb_mac), parser.OFPActionSetField(eth_dst=server_mac_selected), parser.OFPActionSetField(ipv4_dst=server_ip_selected), parser.OFPActionOutput(server_outport_selected)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        cookie = random.randint(0, 0xffffffffffffffff)
        flow_mod = parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=7, instructions=inst, buffer_id = msg.buffer_id, cookie=cookie)
        datapath.send_msg(flow_mod)
        print("<========Packet from client: "+str(ip_header.src)+". Sent to server: "+str(server_ip_selected)+", MAC: "+str(server_mac_selected)+" and on switch port: "+str(server_outport_selected)+"========>")  


        #Reverse route from server
        match = parser.OFPMatch(in_port=server_outport_selected, eth_type=eth.ethertype, eth_src=server_mac_selected, eth_dst=self.virtual_lb_mac, ip_proto=ip_header.proto, ipv4_src=server_ip_selected, ipv4_dst=self.virtual_lb_ip, tcp_src=tcp_header.dst_port, tcp_dst=tcp_header.src_port)
        actions = [parser.OFPActionSetField(eth_src=self.virtual_lb_mac), parser.OFPActionSetField(ipv4_src=self.virtual_lb_ip), parser.OFPActionSetField(ipv4_dst=ip_header.src), parser.OFPActionSetField(eth_dst=eth.src), parser.OFPActionOutput(in_port)]
        inst2 = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        cookie = random.randint(0, 0xffffffffffffffff)
        flow_mod2 = parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=7, instructions=inst2, cookie=cookie)
        datapath.send_msg(flow_mod2)
        print("<++++++++Reply sent from server: "+str(server_ip_selected)+", MAC: "+str(server_mac_selected)+". Via load balancer: "+str(self.virtual_lb_ip)+". To client: "+str(ip_header.src)+"++++++++>")

    def _handle_arp(self, datapath, in_port, eth, arp_header):
        """Handle ARP packets"""
        if arp_header.opcode != arp.ARP_REQUEST:
            return
            
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether.ETH_TYPE_ARP,
            dst=eth.src,
            src=self.virtual_lb_mac))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=self.virtual_lb_mac,
            src_ip=self.virtual_lb_ip,
            dst_mac=arp_header.src_mac,
            dst_ip=arp_header.src_ip))
        pkt.serialize()
        
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data)
        datapath.send_msg(out)

    def _handle_lb_packet(self, datapath, in_port, pkt):
        # Select server using ACO
        selected_server = self.aco_server_selection()
        server_dpid = selected_server['switch']
        
        # Get path to server switch
        path = self.get_path_to_server(datapath.id, server_dpid)
        
        # Install flows along the path
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip = pkt.get_protocols(ipv4.ipv4)[0]
        
        # For each switch in the path
        for src_dpid, dst_dpid in path:
            switch_dp = self.switches.get(src_dpid)
  # Assuming switch dpids start from 1
            out_port = self.get_out_port(src_dpid, dst_dpid)
            
            self.install_path_flows(
                switch_dp, in_port, out_port,
                eth.ethertype, ip.src, selected_server['ip'],
                eth.src, eth.dst, selected_server['mac'],
                idle_timeout=10
            )
        
        # Forward packet to first hop
        if path:
            out_port = self.get_out_port(datapath.id, path[0][1])
            actions = [
                datapath.ofproto_parser.OFPActionOutput(out_port)
            ]
            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=datapath.ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=pkt.data)
            datapath.send_msg(out)
    
    def _handle_tcp_packet(self, datapath, in_port, eth, ip, tcp_header):
        """Handle incoming TCP packets"""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Select server using ACO
        selected_server = self.aco_server_selection()
        
        # Install flow for incoming traffic (client -> server)
        match = parser.OFPMatch(
            in_port=in_port,
            eth_type=ether.ETH_TYPE_IP,
            ip_proto=ip.proto,
            ipv4_src=ip.src,
            ipv4_dst=self.virtual_lb_ip,
            tcp_src=tcp_header.src_port,
            tcp_dst=tcp_header.dst_port
        )
        
        actions = [
            parser.OFPActionSetField(eth_dst=selected_server['mac']),
            parser.OFPActionSetField(ipv4_dst=selected_server['ip']),
            parser.OFPActionOutput(int(selected_server['outport']))
        ]
        
        self.add_flow(datapath, 10, match, actions, idle_timeout=30)
        
        # Install reverse flow (server -> client)
        match = parser.OFPMatch(
            in_port=int(selected_server['outport']),
            eth_type=ether.ETH_TYPE_IP,
            ip_proto=ip.proto,
            ipv4_src=selected_server['ip'],
            ipv4_dst=ip.src,
            tcp_src=tcp_header.dst_port,
            tcp_dst=tcp_header.src_port
        )
        
        actions = [
            parser.OFPActionSetField(eth_src=self.virtual_lb_mac),
            parser.OFPActionSetField(ipv4_src=self.virtual_lb_ip),
            parser.OFPActionOutput(in_port)
        ]
        
        self.add_flow(datapath, 9, match, actions, idle_timeout=30)
        
        # Forward the packet
        actions = [
            parser.OFPActionSetField(eth_dst=selected_server['mac']),
            parser.OFPActionSetField(ipv4_dst=selected_server['ip']),
            parser.OFPActionOutput(int(selected_server['outport']))
        ]
        
        data = None
        if eth.dst == self.virtual_lb_mac:
            data = self._build_packet(eth, ip, tcp_header, selected_server)
            
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data)
        
        datapath.send_msg(out)

    def _build_packet(self, eth, ip, tcp_header, selected_server):
        """Build a new packet with modified destination"""
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=eth.ethertype,
            dst=selected_server['mac'],
            src=eth.src))
        pkt.add_protocol(ipv4.ipv4(
            dst=selected_server['ip'],
            src=ip.src,
            proto=ip.proto))
        pkt.add_protocol(tcp.tcp(
            src_port=tcp_header.src_port,
            dst_port=tcp_header.dst_port))
        pkt.serialize()
        return pkt.data
