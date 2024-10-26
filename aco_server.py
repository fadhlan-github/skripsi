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


#Reference: https://bitbucket.org/sdnhub/ryu-starter-kit/src/7a162d81f97d080c10beb15d8653a8e0eff8a469/stateless_lb.py?at=master&fileviewer=file-view-default

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
import os
#from ryu.app.sdnhub_apps import learning_switch

    
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.serverlist=[]                                                              #Creating a list of servers
        self.virtual_lb_ip = "10.0.0.100"                                               #Virtual Load Balancer IP
        self.virtual_lb_mac = "AB:BC:CD:EF:AB:BC"                                          #Virtual Load Balancer MAC Address
        self.counter = 0                                                                #Used to calculate mod in server selection below
        self.threads = []
        self.pheromone = {}
        self.min_pheromone = 0.1  # Minimum pheromone level
        self.max_pheromone = 5.0  # Maximum pheromone level
        self.weights = {
            'response_time': 1.0,
            'cpu': 1.0,
            'memory': 1.0,
            'latency': 1.0,
            'bandwidth': 1.0
            }
        
        self.serverlist.append({'ip':"10.0.0.4", 'mac':"00:00:00:00:00:04", "outport":"4"})            #Appending all given IP's, assumed MAC's and ports of switch to which servers are connected to the list created 
        self.serverlist.append({'ip':"10.0.0.2", 'mac':"00:00:00:00:00:02", "outport":"2"})
        self.serverlist.append({'ip':"10.0.0.3", 'mac':"00:00:00:00:00:03", "outport":"3"})
        print("Done with initial setup related to server list creation.")
        
        self.alpha = 1  # Pheromone importance
        self.beta = 2   # Heuristic importance
        self.evaporation_rate = 0.1
        self.server_stats = {}
        
        self.pheromone = {'10.0.0.3': 1.0, '10.0.0.2': 1.0, '10.0.0.4': 1.0}
        
        for server in self.serverlist:
            self.server_stats[server['ip']] = {'last_response_time': 1.0,  # Start with neutral value
            'requests': 0,'total_response_time': 0}
        
        # Start pheromone evaporation thread
        self.threads.append(hub.spawn(self._pheromone_evaporation_thread))
        

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

	
    def measure_response_time(self, server_ip):
        """Simulate response time (1-100ms)"""
        return random.uniform(1, 100)

    def get_cpu_utilization(self, server_ip):
        """Simulate CPU utilization (0-100%)"""
        return random.uniform(0, 100)

    def get_memory_utilization(self, server_ip):
        """Simulate memory utilization (0-100%)"""
        return random.uniform(0, 100)

    def measure_network_latency(self, server_ip):
        """Simulate network latency (1-200ms)"""
        return random.uniform(1, 200)

    def get_network_bandwidth(self, server_ip):
        """Simulate network bandwidth (10-1000 Mbps)"""
        return random.uniform(10, 1000)

    def collect_server_stats(self, server_ip):
        """Collect all server statistics in one go"""
        stats = {}
    
        # Collect all metrics
        stats['response_time'] = self.measure_response_time(server_ip)
        stats['cpu_utilization'] = self.get_cpu_utilization(server_ip)
        stats['memory_utilization'] = self.get_memory_utilization(server_ip)
        stats['network_latency'] = self.measure_network_latency(server_ip)
        stats['network_bandwidth'] = self.get_network_bandwidth(server_ip)
    
        return stats

    def calculate_server_fitness(self, server):
        """Calculate overall server fitness based on multiple metrics"""
        stats = self.server_stats[server['ip']]
    
        # Response time score (lower is better)
        response_time_score = 1.0 / (stats['response_time'] + 0.1)
    
        # CPU score (lower utilization is better)
        cpu_score = 1.0 / (stats['cpu_utilization'] + 0.1)
    
        # Memory score (lower utilization is better)
        memory_score = 1.0 / (stats['memory_utilization'] + 0.1)
    
        # Network scores
        latency_score = 1.0 / (stats['network_latency'] + 0.1)
        bandwidth_score = stats['network_bandwidth']  # Higher bandwidth is better
    
        # Calculate weighted fitness score
        fitness = (
                self.weights['response_time'] * response_time_score +
                self.weights['cpu'] * cpu_score +
                self.weights['memory'] * memory_score +
                self.weights['latency'] * latency_score +
                self.weights['bandwidth'] * bandwidth_score
        )
    
        return fitness

    def aco_server_selection(self):
        total = 0
        server_weights = []

        # Update stats for all servers
        for server in self.serverlist:
            server_ip = server['ip']
            current_stats = self.collect_server_stats(server_ip)
            self.server_stats[server_ip].update(current_stats)

        # Calculate weights for server selection
        for server in self.serverlist:
            pheromone = self.pheromone[server['ip']]
            heuristic = self.calculate_server_fitness(server)
            weight = (pheromone ** self.alpha) * (heuristic ** self.beta)
            server_weights.append(weight)
        total += weight

        # Normalize probabilities
        probabilities = [w/total for w in server_weights]

        # Select server based on probabilities
        selected_server = random.choices(self.serverlist, weights=probabilities, k=1)[0]
        server_ip = selected_server['ip']

        # Update request count
        self.server_stats[server_ip]['requests'] += 1

        # Update pheromone based on current performance
        current_stats = self.server_stats[server_ip]
        self.update_pheromone(
            server_ip,
            current_stats['response_time'],
            current_stats['cpu_utilization'],
            current_stats['memory_utilization'],
            current_stats['network_latency'],
            current_stats['network_bandwidth']
        )

        return selected_server

    def update_pheromone(self, server_ip, response_time, cpu_util, memory_util, latency, bandwidth):
        # Calculate composite performance score
        performance_score = (
            self.weights['response_time'] * response_time +
            self.weights['cpu'] * cpu_util +
            self.weights['memory'] * memory_util +
            self.weights['latency'] * latency +
            self.weights['bandwidth'] * (1.0 / bandwidth)  # Invert bandwidth since higher is better
        )

        # Calculate pheromone deposit based on overall performance
        delta_pheromone = 1.0 / (performance_score + 0.1)

        # Update pheromone with deposit and evaporation
        self.pheromone[server_ip] = (
            (1 - self.evaporation_rate) * self.pheromone[server_ip] +
            delta_pheromone
        )

        # Ensure pheromone stays within bounds
        self.pheromone[server_ip] = max(self.min_pheromone, 
		                                min(self.max_pheromone, 
                                        self.pheromone[server_ip]))

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
        
        ip_header = pkt.get_protocols(ipv4.ipv4)[0]
        #print("IP_Header", ip_header)
        tcp_header = pkt.get_protocols(tcp.tcp)[0]
        #print("TCP_Header", tcp_header)

        selected_server = self.aco_server_selection()
        server_ip_selected = selected_server['ip']
        server_mac_selected = selected_server['mac']
        server_outport_selected = int(selected_server['outport'])
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
