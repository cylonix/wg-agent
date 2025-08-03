import subprocess
import logging 

iptables_command = "iptables {} PREROUTING -t mangle -i {} -s {} -j MARK --set-mark {}"
iptables_command_flush = "iptables -t mangle -F"

# setup the iptables for wg0, for stratagy routing
def setup_iptabels(src_ip :str, interface:str, mark:int)->bool:
    return _iptables_operation("-A", src_ip, interface, mark)
#delete the iptables
def clear_iptabels()->bool:
    command = iptables_command_flush
    with subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        ret_code = proc.wait(1)        
        if ret_code != 0:
            logging.warn("Cannot flush mangle iptable entries, reason:",str(proc.stderr.read()))
            return False
        return True
    return False


def _iptables_operation(operation:str, src_ip :str, interface:str, mark:int) ->bool:
    command = iptables_command.format(operation, interface, src_ip, mark)
    with subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        ret_code = proc.wait(1)        
        if ret_code != 0:
            logging.warn("Cannot create vxlan interface, reason:",str(proc.stderr.read()))
            return False
        return True
    return False