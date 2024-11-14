from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import OVSSwitch

class MyTopo(Topo):

    def addSwitch(self, name, **opts):
        kwargs = {'protocols': 'OpenFlow13'}
        kwargs.update(opts)
        return super(MyTopo, self).addSwitch(name, **kwargs)

    def __init__(self):
        "Custom Topology with 5 Switches and 10 Hosts in a Ring"
        Topo.__init__(self)

        # Add Hosts
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
        s6 = self.addSwitch('s6', cls=OVSSwitch, stp=True)
        s7 = self.addSwitch('s7', cls=OVSSwitch, stp=True)
        s8 = self.addSwitch('s8', cls=OVSSwitch, stp=True)
        s9 = self.addSwitch('s9', cls=OVSSwitch, stp=True)
        s10 = self.addSwitch('s10', cls=OVSSwitch, stp=True)


        # Add Links between hosts and switches
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s7)
        self.addLink(s2, s3)
        self.addLink(s2, s8)
        self.addLink(s3, s7)
        self.addLink(s3, s4)
        self.addLink(s3, s6)
        self.addLink(s4, s8)
        self.addLink(s4, s6)
        self.addLink(s5, s6)
        self.addLink(s5, s7)
        self.addLink(s5, s10)
        self.addLink(s6, s9)
        self.addLink(s6, s10)
        self.addLink(s8, s9)
        self.addLink(s9, s10)
        
        self.addLink(s1,h1)
        self.addLink(s2,h2)
        self.addLink(s3,h3)
        self.addLink(s4,h4)
        self.addLink(s5,h5)
        self.addLink(s6,h6)
        self.addLink(s7,h7)
        self.addLink(s8,h8)
        self.addLink(s9,h9)
        self.addLink(s10,h10)
        
def run():
    "Setup and run the network with the custom topology"
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
