import vxlan_setup
import check_wg
import iptables_setup
import routing_setup
import ip_rules_setup
import sys
import argparse, getopt

REMOTE_IP = "192.168.0.6"                       #VXLAN Peer Ip Address 
VXLAN_DEFAULT_GW = "192.168.100.6"              #VXLAN default gateway IP address
VXLAN_IP = "192.168.100.9/24"                   #VXLAN Interface IP address
VXLAN_ID = 100                                  #VXLAN ID
VXLAN_PORT = 8472                               #VXLAN Underlay Port
VXLAN_UNDERLAY_INTERFACE = "eth1"               #VXLAN undeylay traffic default outgoing interface
WG_INTERFACE = "wg0"                            #Wireguard Interface name 
VXLAN_INTERFACE = "vxlan_{}".format(VXLAN_ID)   #VXLAN interface name, the format is vxlan_xxx 
MARK_WG = 1234                                  #FWmark value for traffic from wireguard 
MARK_VXLAN = 4321                               #FWmark value for traffic from vxlan

def setup():
    print("Start to configure the wireguard network system:")
    step = 1

    print("Step{}: check if the wireguard interface is OK...".format(step))
    if not check_wg.check_wg(WG_INTERFACE):
        print("wireguard interface is not ready, please check your wireguard manager. exit with -1")
        sys.exit(-1)
    step += 1

    print("Step{}: setup the vxlan interface, with parameter: remote:{}, vxlan id:{}, port:{}".format(step, REMOTE_IP, VXLAN_ID, VXLAN_PORT))
    if not vxlan_setup.setup_vxlan(REMOTE_IP, VXLAN_ID, VXLAN_IP,VXLAN_PORT):
        print("Cannot setup the vxlan interface, please check the log. exit with -2")
        sys.exit(-2)
        return 

    step += 1

    print("Step{}: try to get wireguard ip...".format(step))
    wg_ip = check_wg.get_wg_ip(WG_INTERFACE)
    if wg_ip == "":
        print("Cannot get the wg_ip, please check you wg interface setting..., exit with -3")
        sys.exit(-3)
    step += 1
    print(wg_ip)
    print("Step{}: setup the iptables...".format(step))
    if not iptables_setup.setup_iptabels(wg_ip, WG_INTERFACE, MARK_WG):
        print("cannot setup the iptables for wg interface")
        sys.exit(-4)
    
    if not iptables_setup.setup_iptabels("0.0.0.0/0", VXLAN_INTERFACE, MARK_VXLAN):
        print("cannot setup the iptables for vxlan interface")
        sys.exit(-5)
    step += 1

    print("Step{}: setup the ip rules...".format(step))
    if not ip_rules_setup.setup_ip_rules(MARK_WG, MARK_WG):
        print("Cannot setup the ip rule for wg table")
        sys.exit(-6)

    if not ip_rules_setup.setup_ip_rules(MARK_VXLAN, MARK_VXLAN):
        print("Cannot setup the ip rule for vxlan table")
        sys.exit(-6)
    step += 1

    print("Step{}: setup the ip routing...".format(step))
    if not routing_setup.setup_vxlan_special_route(VXLAN_UNDERLAY_INTERFACE, REMOTE_IP, MARK_WG):
        print("Cannot setup the wg interface vxlan special routing table")
        sys.exit(-8)

    if not routing_setup.setup_routing(WG_INTERFACE, MARK_VXLAN, VXLAN_DEFAULT_GW):
        print("Cannot setup the vlxan interface routing table")
        sys.exit(-7)

    if not routing_setup.setup_routing(VXLAN_INTERFACE, MARK_WG, VXLAN_DEFAULT_GW):
        print("Cannot setup the wg interface routing table")
        sys.exit(-8)


def clear():
    print("Start to clear the wireguard system...")

    step = 1
    print("Step{}: clear the ip routing...".format(step))
    if not routing_setup.clean_routing(WG_INTERFACE, MARK_VXLAN, VXLAN_DEFAULT_GW):
        print("Cannot clear the wg interface routing table")

    if not routing_setup.clean_routing(VXLAN_INTERFACE, MARK_WG,VXLAN_DEFAULT_GW):
        print("Cannot clear the vxlan interface routing table")

    if not routing_setup.clean_vxlan_special_route(VXLAN_UNDERLAY_INTERFACE, REMOTE_IP, MARK_WG):
        print("Cannot clear the wg interface vxlan special routing table")
    
    step +=1
    print("Step{}: clear the ip rules...".format(step))
    if not ip_rules_setup.clear_ip_rule(MARK_WG, MARK_WG):
        print("Cannot setup the ip rule for wg table")

    if not ip_rules_setup.clear_ip_rule(MARK_VXLAN, MARK_VXLAN):
        print("Cannot setup the ip rule for vxlan table")

    step +=1
    print("Step{}: clear the iptables...".format(step))
    if not iptables_setup.clear_iptabels():
        print("Cannot clear the mangle iptables")

    step +=1
    print("Step{}: clear the vxlan interface...".format(step))
    if not vxlan_setup.delete_vxlan(VXLAN_INTERFACE):
        print("Cannot delete the vxlan interface")

    print("successfully clear the wireguard system")

if __name__ == "__main__":
    opts,_= getopt.getopt(sys.argv[1:], "sc", ["setup", "clear"])

    print(opts)

    for opt in opts:
        if opt[0] in ("-s", "--setup"):
            setup()
            break
        elif opt[0] in ("-c", "--clear"):
            clear()
            break
    