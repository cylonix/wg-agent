import subprocess
import logging

ip_forward_enable = "sysctl -w net.ipv4.ip_forward={}"
ip_route_command = "ip route {} {} {} dev {} table {} scope {}"
ip_route_show_command = "ip route {} {} dev {} table {}"

# we also need to setup the vxlan interface underlay routing info 

def setup_routing(interface:str, table:int, gateway:str)->bool:
    if check_if_routing_created(interface, table):
        return True
    if interface.startswith("wg"):
        via = ""
    else:
        via = "via "+ gateway

    return _routing_operation("add", "default", via, interface, table, "global")

def clean_routing(interface:str, table:int, gateway:str = "" )->bool:
    if not check_if_routing_created(interface, table):
        return True

    if interface.startswith("wg"):
        via = ""
    else:
        via = "via "+ gateway
    return _routing_operation("delete", "default", "",  interface, table, "global")

def _routing_operation(op:str, ip:str, via :str, interface:str, table:int, scope:str) ->bool:
    command =ip_route_command.format(op, ip, via, interface, table, scope)
    print(command)
    with subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        ret_code = proc.wait(1)        
        if ret_code != 0:
            logging.warn("Cannot create/delete ip routing, reason:{}".format(str(proc.stderr.read())))
            return False
        return True
    return False

def enable_forwading () ->bool:
    command = ip_forward_enable.format(1)
    with subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        ret_code = proc.wait(1)        
        if ret_code != 0:
            logging.warn("Cannot enable forward, reason:{}".format(str(proc.stderr.read())))
            return False
        return True
    return False

def check_if_routing_created(interface:str, table:int )->bool:
    command =ip_route_show_command.format("show", "default", interface, table)
    with subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        ret_code = proc.wait(1)        
        if ret_code != 0:
            logging.warn("Cannot show ip route operation, reason:{}".format(str(proc.stderr.read())))
            return False

        contents = proc.stdout.read()
        if len(contents) == 0:
            return False
        return True


def setup_vxlan_special_route(interface:str, vxlanip:str, table:int)->bool: 
    return _routing_operation("add", vxlanip, "", interface, table, "link")

def clean_vxlan_special_route(interface:str, vxlanip:str, table:int)->bool: 
    return _routing_operation("delete",  vxlanip, "", interface,table, "link")