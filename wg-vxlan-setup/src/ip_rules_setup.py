import subprocess 
import logging
ip_rule_command = "ip rule {} fwmark {} lookup {} pref 100"

def setup_ip_rules(mark:int, table:int)->bool: 
    if check_if_rule_created(mark, table):
        return True
    return _iprules_operation(mark, table, "add")

def clear_ip_rule(mark:int , table:int)->bool:
    if not check_if_rule_created(mark, table):
        return True
    return _iprules_operation(mark, table, "delete")

def _iprules_operation(mark:int, table:int, operation:str) ->bool:
    command =ip_rule_command.format(operation, mark, table)
    with subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        ret_code = proc.wait(1)        
        if ret_code != 0:
            logging.warn("Cannot add/clear ip rule operation, reason:{}".format(str(proc.stderr.read())))
            return False
        return True
    return False

def check_if_rule_created(mark:int , table:int)->bool:
    command =ip_rule_command.format("show", mark, table)
    with subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc: 
        ret_code = proc.wait(1)        
        if ret_code != 0:
            logging.warn("Cannot show ip rule operation, reason:{}".format(str(proc.stderr.read())))
            return False

        contents = proc.stdout.read()
        if len(contents) == 0:
            return False
        return True
    return False