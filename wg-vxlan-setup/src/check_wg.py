import subprocess
import re
import logging

WG_SHOW_COMMAND = "wg show all".split()
wg_ip = ""
wg_interface_regex = re.compile("interface:\s*(\w+)")
priviledge_error_pattern = re.compile("Operation not permitted")
ip_addr_command = "ip addr show dev".split()
ip_pattern = re.compile("inet\s*((\d+\.){3}\d+\/\d+)")

def check_wg(interface:str)->bool:
    global wg_ip
    interfaces = list()
    outputs = None
    with subprocess.Popen(WG_SHOW_COMMAND, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        err = proc.stderr.read()
        priv = priviledge_error_pattern.search(str(err))
        if priv:
            return False

        contents = proc.stdout.read()
        contents = str(contents).split("\\n")
        outputs = contents
        # Search the wg interface
        for line in contents:
            ret = wg_interface_regex.search(str(line))
            if ret: 
                interfaces.append(ret.group(1))

    if interface not in interfaces:
        return False

    if outputs != None:
        print("\n".join(outputs))

    #Try to get IP address 
    ip_command = [x for x in ip_addr_command]
    ip_command.append(interface)

    with subprocess.Popen(ip_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        err = proc.stderr.read()
        priv = priviledge_error_pattern.search(str(err))
        if priv:
            return False

        contents = proc.stdout.read()
        contents = str(contents).split("\\n")
        outputs = contents
        # Search the wg interface
        for line in contents:
            ret =ip_pattern.search(str(line))
            if ret: 
                wg_ip = ret.group(1)
    return True

def get_wg_ip(interface:str)->str:
    if wg_ip != "":
        return wg_ip
    #try to get the wg_ip 
    if check_wg(interface) and wg_ip != "":
        return wg_ip
    return ""
