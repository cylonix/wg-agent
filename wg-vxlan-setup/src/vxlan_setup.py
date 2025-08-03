
import subprocess
import logging

ip_command_setup_vxlan = "ip link add {0} type vxlan remote {1} dstport {2} id {3}"
ip_command_check_interface_created = "ip link show dev {0}"
ip_command_delete_vxlan = "ip link delete dev {}"
ip_command_interface_up = "ip link set dev {} up"
ip_command_add_addr = "ip addr add {} dev {}"

def check_if_interface_created(interface:str)->bool:
    command = ip_command_check_interface_created.format(interface)
    with subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        ret_code = proc.wait(1)        
        if ret_code != 0:
            return False
        return True

# create vlan interface // check if created 
def setup_vxlan(remote_ip:str, id:int, vxlanip:str, port:int=8472) -> bool: 
    if check_if_interface_created("vxlan_{0}".format(str(id))):
        return True
    # create the interface 
    command = ip_command_setup_vxlan.format("vxlan_{0}".format(str(id)), remote_ip, port, id)
    with subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        ret_code = proc.wait(1)        
        if ret_code != 0:
            logging.warn("Cannot create vxlan interface, reason:{}".format(str(proc.stderr.read())))
            return False

    interface = "vxlan_{0}".format(str(id))
    # up the interface 
    if not _up_interface(interface):
        return False 
    
    # Add  Addr 
    if not _add_add_to_interface(interface, vxlanip):
        return False
    return True

def delete_vxlan(interface:str)->bool:
    if not  check_if_interface_created(interface):
        return True 

    command = ip_command_delete_vxlan.format(interface)
    with subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        ret_code = proc.wait(1)        
        if ret_code != 0:
            return False
        return True

    return False

def _up_interface(interface:str)->bool:
    if not check_if_interface_created(interface):
        return False

    command = ip_command_interface_up.format(interface)
    with subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        ret_code = proc.wait(1)        
        if ret_code != 0:
            return False
        return True

    return False

def _add_add_to_interface(interface:str, ip:str)->bool:
    if not check_if_interface_created(interface):
        return False
    command = ip_command_add_addr.format(ip, interface)
    with subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        ret_code = proc.wait(1)        
        if ret_code != 0:
            return False
        return True

    return False