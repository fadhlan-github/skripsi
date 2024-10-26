from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import Controller, OVSSwitch


class MyTopo(Topo):

    def addSwitch(self, name, **opts):
        kwargs = {'protocols': 'OpenFlow13'}
        kwargs.update(opts)
        return super(MyTopo, self).addSwitch(name, **kwargs)

    def __init__(self):
        "Custom Topology 5 Switch 10 Host - Topology Ring"
        Topo.__init__(self)

        # Add Hosts and Switches
        info('*** Add Hosts\n')
        
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')
        h8 = self.addHost('h8')
        h9 = self.addHost('h9')
        h10 = self.addHost('h10')

        # Add Switches
        s1 = self.addSwitch('s1', cls=OVSSwitch, stp=True)
        s2 = self.addSwitch('s2', cls=OVSSwitch, stp=True)
        s3 = self.addSwitch('s3', cls=OVSSwitch, stp=True)
        s4 = self.addSwitch('s4', cls=OVSSwitch, stp=True)
        s5 = self.addSwitch('s5', cls=OVSSwitch, stp=True)
        
        # Add Links between hosts and switches
        self.addLink(s1, h1)  # h1 to s1
        self.addLink(s1, h2)  # h2 to s1
        self.addLink(s2, h3)  # h3 to s2
        self.addLink(s3, h4)  # h4 to s3
        self.addLink(s3, h5)  # h5 to s3
        self.addLink(s3, h6)  # h6 to s3
        self.addLink(s4, h7)  # h7 to s4
        self.addLink(s4, h8)  # h8 to s4
        self.addLink(s5, h9)  # h9 to s5
        self.addLink(s5, h10)  # h10 to s5

        # Add Links between switches in a ring topology
        self.addLink(s1, s2)  # s1 to s2
        self.addLink(s2, s3)  # s2 to s3
        self.addLink(s3, s4)  # s3 to s4
        self.addLink(s4, s5)  # s4 to s5
        self.addLink(s5, s1)  # s5 to s1
	
def run():
    "The Topology for Server - Ant Colony Optimization LoadBalancing"
    topo = MyTopo()
    net = Mininet(topo=topo, controller=RemoteController, autoSetMacs=True, autoStaticArp=True, waitConnected=True)

    info("\n*** Disabling IPv6 ***\n")
    for host in net.hosts:
        info(f"Disabling IPv6 in {host}\n")
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")

    for sw in net.switches:
        info(f"Disabling IPv6 in {sw}\n")
        sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")

    # Start the network
    net.start()

    # Check if hosts are set up correctly
    info("\n*** Verifying host connections ***\n")
    dumpNodeConnections(net.hosts)

    # Setup h1, h2, and h3 as servers
    info("\n*** Starting HTTP servers on h1, h2, h3 ***\n")
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
    h1.cmd('python3 -m http.server 8080 &')
    h2.cmd('python3 -m http.server 8080 &')
    h3.cmd('python3 -m http.server 8080 &')

    # Open Mininet CLI
    CLI(net)

    # Stop the network
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()

