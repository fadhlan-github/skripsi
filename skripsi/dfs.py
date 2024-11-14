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
import time

# Global variables
switches = []
mymacs = {}
adjacency = defaultdict(lambda:defaultdict(lambda:None))
datapaths = {}  # Store active datapaths

def get_path(src, dst, first_port, final_port):
    """Find path using DFS"""
    print(f"DFS computing path from DPID: {src} port= {first_port} to DPID: {dst} port {final_port}")
    
    if src == dst:
        return [(src, first_port, final_port)]
    
    def dfs_paths(current, target, visited=None, path=None):
        if visited is None:
            visited = set()
        if path is None:
            path = []
            
        visited.add(current)
        path.append(current)
        
        if current == target:
            return path
            
        for next_switch in switches:
            if (next_switch not in visited) and (adjacency[current][next_switch] is not None):
                result = dfs_paths(next_switch, target, visited, path)
                if result is not None:
                    return result
                    
        path.pop()
        visited.remove(current)
        return None
    
    # Find the path using DFS
    path = dfs_paths(src, dst)
    
    if not path:
        return None
        
    # Convert path to route with ports
    r = []
    in_port = first_port
    for s1, s2 in zip(path[:-1], path[1:]):
        out_port = adjacency[s1][s2]
        r.append((s1, in_port, out_port))
        in_port = adjacency[s2][s1]
    r.append((dst, in_port, final_port))
    return r

class DFSSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DFSSwitch, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.datapath_list = []
        self.switches = []
        self.mymacs = {}
        self.mac_to_path = {}  # Store current paths for each src-dst MAC pair
        self.monitor_thread = None

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
        print(f"Installing DFS Path: {p} from SRC: {src_mac} to DST: {dst_mac}")
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Store the path for future reference
        self.mac_to_path[(src_mac, dst_mac)] = p

        for sw, in_port, out_port in p:
            match = parser.OFPMatch(in_port=in_port, eth_src=src_mac, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            datapath = self.datapath_list[int(sw)-1]
            self.add_flow(datapath, 1, match, actions, idle_timeout=10, hard_timeout=30)
        
        print("Path installation finished in", time.time() - computation_start)

    def handle_link_down(self, link):
        """Handle link failure by recalculating affected paths"""
        start_time = time.time()
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
    
        print(f"Link down detected between switches {src_dpid} and {dst_dpid}")
    
        # Remove the link from adjacency matrix
        adjacency[src_dpid][dst_dpid] = None
        adjacency[dst_dpid][src_dpid] = None
    
        # Find and update affected paths
        affected_paths = []
        for (src_mac, dst_mac), path in self.mac_to_path.items():
            # Check if the failed link is part of this path
            for i in range(len(path) - 1):
                if (path[i][0] == src_dpid and path[i+1][0] == dst_dpid) or \
                   (path[i][0] == dst_dpid and path[i+1][0] == src_dpid):
                    affected_paths.append((src_mac, dst_mac))
                    break
    
        # Recalculate affected paths
        for src_mac, dst_mac in affected_paths:
            # Remove old flows
            for dp in self.datapath_list:
                match = dp.ofproto_parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
                self.remove_flows(dp, match)
        
            # Calculate new path if source and destination are still known
            if src_mac in mymacs and dst_mac in mymacs:
                new_path = get_path(mymacs[src_mac][0], mymacs[dst_mac][0],
                                  mymacs[src_mac][1], mymacs[dst_mac][1])
                if new_path:
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
                    print(f"Installed new path for {src_mac} -> {dst_mac}: {new_path} (took {end_time - start_time:.9f} seconds)")
                else:
                    end_time = time.time()
                    print(f"No alternative path found for {src_mac} -> {dst_mac} (took {end_time - start_time:.9f} seconds)")
    
        print("Network has converged, continuing normal operation.")

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
        for s1, s2, port1, port2 in mylinks:
            adjacency[s1][s2] = port1
            adjacency[s2][s1] = port2
