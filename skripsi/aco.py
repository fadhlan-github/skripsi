from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import mac
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event, switches
from collections import defaultdict
import random
import numpy as np
import time
from ryu.lib import hub

# Global variables
switches = []
mymacs = {}
adjacency = defaultdict(lambda:defaultdict(lambda:None))
datapaths = {}  # Store active datapaths

# ACO parameters
INITIAL_PHEROMONE = 1
MIN_PHEROMONE = 0.5
MAX_PHEROMONE = 5
PHEROMONE_EVAPORATION = 0.5

ALPHA = 1.0  # Pheromone importance
BETA = 2.0   # Distance importance
Q = 1      # Pheromone deposit factor
N_ANTS = 10  # Number of ants per iteration
MAX_ITERATIONS = 100

class PheromoneTable:
    def __init__(self):
        self.pheromone = defaultdict(lambda: defaultdict(lambda: INITIAL_PHEROMONE))
    
    def deposit(self, path, total_distance):
        # Calculate deposit amount with better scaling
        path_length = len(path) - 1
        deposit_amount = (Q / path_length) * (1.0 / total_distance)
        
        # Calculate path length for proportional deposit
        path_length = len(path) - 1
        
        for i in range(path_length):
            current = path[i]
            next_node = path[i+1]
            
            # Get current pheromone value
            old_pheromone = self.pheromone[current][next_node]
            
            # Add new pheromone without immediate evaporation
            new_pheromone = old_pheromone + deposit_amount
            
            # Ensure bounds
            self.pheromone[current][next_node] = min(MAX_PHEROMONE, max(MIN_PHEROMONE, new_pheromone))
            # Maintain symmetry for bidirectional paths
            self.pheromone[next_node][current] = self.pheromone[current][next_node]
    
    def evaporate(self):
        """Separate evaporation process with safe dictionary handling"""
        # Create a list of all nodes first
        nodes = list(self.pheromone.keys())
        
        for i in nodes:
            # Get all connected nodes
            connected_nodes = list(self.pheromone[i].keys())
            for j in connected_nodes:
                current = self.pheromone[i][j]
                scaled_rate = PHEROMONE_EVAPORATION * 0.5
                evaporated = current * (1 - scaled_rate)
                self.pheromone[i][j] = max(MIN_PHEROMONE, evaporated)
                self.pheromone[j][i] = self.pheromone[i][j]  # Maintain symmetry
    
    def get_pheromone(self, i, j):
        return self.pheromone[i][j]
    
def get_path(src, dst, first_port, final_port):
    computation_start = time.time()
    print(f"\nAvailable paths from {src} to {dst} :")
    
    if src == dst:
        return [(src, first_port, final_port)]
    
    pheromone_table = PheromoneTable()
    best_paths = []
    
    # Initialize distance matrix with smaller initial pheromone
    distances = defaultdict(lambda: defaultdict(lambda: float('inf')))
    for s1 in switches:
        for s2 in switches:
            if adjacency[s1][s2] is not None:
                distances[s1][s2] = 1
    
    for iteration in range(MAX_ITERATIONS):
        paths_this_iteration = []
        
        # Apply evaporation to all pheromones
        pheromone_table.evaporate()
        
        for ant in range(N_ANTS):
            current = src
            path = [current]
            total_distance = 0
            
            while current != dst:
                next_nodes = [n for n in switches if adjacency[current][n] is not None]
                if not next_nodes or len(path) > len(switches):
                    break
                
                probabilities = []
                for next_node in next_nodes:
                    if next_node not in path:  # Avoid cycles
                        pheromone = pheromone_table.get_pheromone(current, next_node)
                        distance = distances[current][next_node]
                        probability = (pheromone ** ALPHA) * ((1.0 / distance) ** BETA)
                        probabilities.append((next_node, probability))
                
                if not probabilities:
                    break
                
                total = sum(prob for _, prob in probabilities)
                if total == 0:
                    break
                
                normalized_probs = [(node, prob/total) for node, prob in probabilities]
                rand_value = random.random()
                cumsum = 0
                for node, prob in normalized_probs:
                    cumsum += prob
                    if rand_value <= cumsum:
                        current = node
                        path.append(current)
                        if len(path) > 1:
                            total_distance += distances[path[-2]][path[-1]]
                        break
            
            if path[-1] == dst:
                path_str = str(path).replace(" ", "")
                if path_str not in [str(p[0]).replace(" ", "") for p in paths_this_iteration]:
                    paths_this_iteration.append((path, total_distance))
        
        # Update pheromones with reduced deposit amount
        for path, total_distance in paths_this_iteration:
            # Deposit smaller amount of pheromone
            pheromone_table.deposit(path, total_distance)  # Reduced deposit amount
            
            path_str = str(path).replace(" ", "")
            if path_str not in [str(p[0]).replace(" ", "") for p in best_paths]:
                path_pheromone = sum(pheromone_table.get_pheromone(path[i], path[i+1]) 
                                   for i in range(len(path)-1))
                best_paths.append((path, total_distance, path_pheromone))
    
    computation_end = time.time()
    execution_time = computation_end - computation_start
    print(f"Path Execution Time: {execution_time:.6f}")
    
    if not best_paths:
        return None
    
    # Calculate probabilities for each path
    total_quality = sum((p[2] / p[1]) for p in best_paths)  # pheromone/distance ratio
    path_probabilities = [(p[0], p[2], p[1], (p[2]/p[1])/total_quality) for p in best_paths]
    
    # Generate random number for path selection
    random_number = random.random()
    print(f"\nrandom_number_choose_path = {random_number:.4f}")
    
    # Print all paths with their details and probabilities
    for path, pheromone, distance, probability in path_probabilities:
        total_path_pheromone = sum(pheromone_table.get_pheromone(path[i], path[i+1]) 
                                 for i in range(len(path)-1))
        print(f"\n{path} pheromone = {total_path_pheromone:.3f}, total distance = {distance} probability = {probability:.4f}")
        for i in range(len(path)-1):
            s1, s2 = path[i], path[i+1]
            link_pheromone = pheromone_table.get_pheromone(s1, s2)
            link_distance = distances[s1][s2]
            print(f"s{s1}-s{s2}: pheromone={link_pheromone:.3f}, distance={link_distance}")
    
    # Choose path based on random number and probabilities
    cumsum = 0
    selected_path = None
    for path, pheromone, distance, probability in path_probabilities:
        cumsum += probability
        if random_number <= cumsum and selected_path is None:
            selected_path = path
    
    # Convert selected path to required format
    r = []
    in_port = first_port
    for s1, s2 in zip(selected_path[:-1], selected_path[1:]):
        out_port = adjacency[s1][s2]
        r.append((s1, in_port, out_port))
        in_port = adjacency[s2][s1]
    r.append((dst, in_port, final_port))
    return r    
    
class ACOSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ACOSwitch, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.datapath_list = []
        self.switches = []
        self.mymacs = {}
        self.mac_to_path = {}
        self.pheromone_table = PheromoneTable()
        self.distance_matrix = defaultdict(lambda: defaultdict(lambda: float('inf')))
        # Add cache for installed paths
        self.installed_paths = {}
        # Add timestamp for path installation
        self.path_timestamps = {}
        # Path timeout in seconds
        self.PATH_TIMEOUT = 30
        
    def update_distance_matrix(self):
        """Update distance matrix with more stable random values"""
        for s1 in self.switches:
            for s2 in self.switches:
                if adjacency[s1][s2] is not None:
                    # Use switch IDs to generate consistent random values
                    self.distance_matrix[s1][s2] = 1
                    self.distance_matrix[s2][s1] = 1
    
    def is_path_valid(self, src_mac, dst_mac):
        """Check if a path exists and is still valid"""
        path_key = (src_mac, dst_mac)
        if path_key in self.installed_paths and path_key in self.path_timestamps:
            # Check if path hasn't expired
            current_time = time.time()
            if current_time - self.path_timestamps[path_key] < self.PATH_TIMEOUT:
                # Verify all links in path still exist
                path = self.installed_paths[path_key]
                for i in range(len(path) - 1):
                    current_switch = path[i][0]
                    next_switch = path[i+1][0]
                    if adjacency[current_switch][next_switch] is None:
                        return False
                return True
        return False

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                  priority=priority, match=match,
                                  instructions=inst, idle_timeout=idle_timeout,
                                  hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                  match=match, instructions=inst,
                                  idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def remove_flows(self, datapath, match):
        """Remove all flows matching the given match criteria"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Create flow mod message to remove matching flows
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)

    def install_path(self, p, ev, src_mac, dst_mac):
        computation_start = time.time()
        print(f"Installing ACO Path: {p} from SRC: {src_mac} to DST: {dst_mac}")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        path_switches = [node[0] for node in p]
        total_distance = sum(self.distance_matrix[path_switches[i]][path_switches[i+1]] 
                           for i in range(len(path_switches)-1))
        
        self.pheromone_table.deposit(path_switches, total_distance)

        # Store the path and timestamp
        path_key = (src_mac, dst_mac)
        self.installed_paths[path_key] = p
        self.path_timestamps[path_key] = time.time()
        self.mac_to_path[path_key] = p
        
        for sw, in_port, out_port in p:
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            datapath = self.datapath_list[int(sw)-1]
            self.add_flow(datapath, 1, match, actions, idle_timeout=10, hard_timeout=30)
        
        print("Path installation finished in", time.time() - computation_start)


    def handle_link_down(self, link):
        """Handle link failure by recalculating affected paths"""
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
    
        print(f"Link down detected between switches {src_dpid} and {dst_dpid}")
    
        # Remove the link from adjacency matrix
        adjacency[src_dpid][dst_dpid] = None
        adjacency[dst_dpid][src_dpid] = None
    
        # Clear affected paths from cache
        affected_paths = []
        for (src_mac, dst_mac), path in self.installed_paths.items():
            for i in range(len(path) - 1):
                if (path[i][0] == src_dpid and path[i+1][0] == dst_dpid) or \
                   (path[i][0] == dst_dpid and path[i+1][0] == src_dpid):
                    affected_paths.append((src_mac, dst_mac))
                    break
    
        for src_mac, dst_mac in affected_paths:
            # Remove old flows
            for dp in self.datapath_list:
                match = dp.ofproto_parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
                self.remove_flows(dp, match)
        
            # Calculate new path if source and destination are still known
            if src_mac in mymacs and dst_mac in mymacs:
                start_time = time.time()
                new_path = get_path(mymacs[src_mac][0], mymacs[dst_mac][0],
                                  mymacs[src_mac][1], mymacs[dst_mac][1])
                if new_path:
                # Create a dummy event for install_path
                    class DummyMsg:
                        def __init__(self, datapath):
                            self.datapath = datapath
                
                    class DummyEv:
                        def __init__(self, msg):
                            self.msg = msg
                
                    dummy_msg = DummyMsg(self.datapath_list[0])
                    dummy_ev = DummyEv(dummy_msg)
                
                    self.install_path(new_path, dummy_ev, src_mac, dst_mac)
                    end_time = time.time()
                    print(f"Installed new path for {src_mac} -> {dst_mac}: {new_path} (time for recovery{end_time - start_time:.29f} seconds)")
                else:
                    end_time = time.time()
                    print(f"No alternative path found for {src_mac} -> {dst_mac} (time for recovery {end_time - start_time:.9f} seconds)")
        
        # Remove affected paths from cache
        for path_key in affected_paths:
            if path_key in self.installed_paths:
                del self.installed_paths[path_key]
            if path_key in self.path_timestamps:
                del self.path_timestamps[path_key]
            if path_key in self.mac_to_path:
                del self.mac_to_path[path_key]


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """
        Handle port statistics reply from switch
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.port_stats[dpid] = body
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in datapaths:
                print(f'register datapath: {datapath.id}')
                datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in datapaths:
                print(f'unregister datapath: {datapath.id}')
                del datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == 35020 or eth.ethertype == 34525:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if src not in mymacs.keys():
            mymacs[src] = (dpid, in_port)

        if dst in mymacs.keys():
            # Check if valid path exists before calculating new one
            if self.is_path_valid(src, dst):
                p = self.installed_paths[(src, dst)]
                out_port = p[0][2]
            else:
                p = get_path(mymacs[src][0], mymacs[dst][0], mymacs[src][1], mymacs[dst][1])
                if p is not None:
                    self.install_path(p, ev, src, dst)
                    out_port = p[0][2]
                else:
                    out_port = ofproto.OFPP_FLOOD
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
        
    @set_ev_cls([event.EventSwitchEnter, event.EventSwitchLeave,
                 event.EventPortAdd, event.EventPortDelete,
                 event.EventPortModify, event.EventLinkAdd,
                 event.EventLinkDelete])
    def get_topology_data(self, ev):
        global switches
        
        # Handle link deletion event specifically
        if isinstance(ev, event.EventLinkDelete):
            self.handle_link_down(ev.link)
            
        # Update topology information
        switch_list = get_switch(self.topology_api_app, None)  
        switches = [switch.dp.id for switch in switch_list]
        self.datapath_list = [switch.dp for switch in switch_list]
        self.datapath_list.sort(key=lambda dp: dp.id)

        links_list = get_link(self.topology_api_app, None)
        mylinks = [(link.src.dpid, link.dst.dpid, link.src.port_no, link.dst.port_no) for link in links_list]
        
        # Clear and update adjacency
        adjacency.clear()
         # Update distance_matrix when topology changes
        self.distance_matrix.clear()
        for s1, s2, port1, port2 in mylinks:
            adjacency[s1][s2] = port1
            adjacency[s2][s1] = port2
            self.distance_matrix[s1][s2] = 1
            self.distance_matrix[s2][s1] = self.distance_matrix[s1][s2]  # Make distances symmetric
