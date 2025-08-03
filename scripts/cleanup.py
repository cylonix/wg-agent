import subprocess
import re

# sudo ip l del dev vxlan_1043
# sudo ip l del dev wg100
# sudo iptables -t mangle -F
# sudo ip rule del fwmark 0x413
# sudo ip route del 0.0.0.0/0 via 192.168.88.1 table 1043
# sudo ip route del 192.168.88.33 dev enp7s0 table 1043

WG_CLI = "wg show"
IP_DETAIL_CLI = "ip -d link show"
IP_ROUTE_CLI = "ip route show table {table}"
IPTABLES_MANGLE_CLI = "iptables -t mangle -S PREROUTING"
IPTABLES_FILTER_CLI = "iptables -t filter -S FORWARD"

#
# List all the wg interface
#


def list_all_wg_interfaces() -> list:
    ret = list()
    with subprocess.Popen(WG_CLI.split(" "),
                          stdout=subprocess.PIPE,
                          shell=True) as proc:
        contents = proc.stdout.read()
        # Start to analyze the contents
        contents = contents.decode(encoding="ascii", errors="strict")
        content_lines = contents.split("\n")
        regex = "^interface:(.+)"
        for content in content_lines:
            matches = re.match(regex, content)
            if matches is not None:
                ret.append(matches.groups()[0].strip())

    return ret

#
# List all the vxlan interfaces
#


def list_all_vxlan_interfaces() -> {}:
    ret = {}
    with subprocess.Popen(IP_DETAIL_CLI.split(" "),
                          stdout=subprocess.PIPE,
                          shell=False) as proc:
        contents = proc.stdout.read()
        # Start to analyze the contents
        contents = contents.decode(encoding="ascii", errors="strict")
        regex = r"\n*\d+:\s+(\w+):\s+"
        contents = re.split(regex, contents)

        retMap = {}
        for i in range((len(contents) - 1)//2):
            interface_index = i * 2 + 1
            content_index = interface_index + 1
            retMap[contents[interface_index]] \
                = contents[content_index].split(r"\n")

        # Seach the vlan interface
        for interface in retMap:
            contents = retMap[interface]
            vxlan_regex = r"vxlan\s+id\s+(\d+)"
            for content in contents:
                matches = re.search(vxlan_regex, content)
                if matches is not None:
                    ret[interface] = matches.groups()[0]
                    break
    return ret
#
# calc ip rule based on vxlan
# sudo ip rule del fwmark 0x413


def caculate_ip_rule_cli(vxlan_vni: str) -> str:
    # We need to convert the vni to int
    vni = int(vxlan_vni)
    ip_rule = r"ip rule del fwmark " + hex(vni)
    return ip_rule

#
# Calc the ip route based on ip rule table
#


def list_all_routes_with_table(table: str) -> list:
    ret = list()
    iproute = IP_ROUTE_CLI.format(table=table)
    print(iproute)
    with subprocess.Popen(iproute.split(" "),
                          stdout=subprocess.PIPE,
                          shell=False) as proc:
        contents = proc.stdout.read()
        # Start to analyze the contents
        contents = contents.decode(encoding="ascii", errors="strict")
        content_lines = contents.split("\n")

        for content in content_lines:
            if content.strip() == "":
                continue
            ret.append("ip route delete table {table} {content}".\
                format(table=table, content=content.strip()))
            
    return ret


def list_commands_delete_iptables(table: str) -> list:
    ret = list()
    ip_list = list()
    with subprocess.Popen(IPTABLES_MANGLE_CLI.split(" "),
                          stdout=subprocess.PIPE,
                          shell=False) as proc:
        contents = proc.stdout.read()
        # Start to analyze the contents
        contents = contents.decode(encoding="ascii", errors="strict")
        content_lines = contents.split("\n")

        regex = r"^-A\s+(.*-s\s+(.*)/\d+.*set-xmark\s+{hex}/0xffffffff)"\
                .format(hex=hex(int(table)))

        for content in content_lines:
            matches = re.search(regex, content)
            if matches is not None:
                ret\
                    .append("iptables -t mangle -D " + matches.groups()[0])
                ip_list.append(matches.groups()[1])
    if len(ip_list) == 0:
        return ret

    with subprocess.Popen(IPTABLES_FILTER_CLI.split(" "),
                          stdout=subprocess.PIPE,
                          shell=False) as proc:
        contents = proc.stdout.read()
        # Start to analyze the contents
        contents = contents.decode(encoding="ascii", errors="strict")
        content_lines = contents.split("\n")

        regex = r"^-A\s+(.*-[s|d]\s+{ip}.*)"
        for content in content_lines:
            for ip in ip_list:
                regex_ip = regex.format(ip=ip)
                matches = re.search(regex_ip, content)
                if matches is not None:
                    ret.append("iptables -t filter -D " + matches.groups()[0])

    return ret


def generate_interface_del_commands(interface: str) -> str:
    return "ip link delete dev {interface}".format(interface=interface)


def execute_command(cmd: str):
    print("Execute cmd '{command}'...".format(command=cmd))
    with subprocess.Popen(cmd.split(" "),
                          stdout=subprocess.PIPE,
                          shell=False) as proc:
        output = proc.stdout.read().decode(encoding="ascii")
        if output != "":
            print("Output:{output}" .format(output=output))
        proc.wait(timeout=10)

        if proc.returncode != 0:
            print("Execute '{command}' error, return code:{code}".format(command=cmd, code=proc.returncode))
        else:
            print("Execute '{command}' successfully".format(command=cmd))


def main():
    wg_interfaces = list_all_wg_interfaces()
    vxlan_interfaces = list_all_vxlan_interfaces()

    all_interfaces = []
    all_interfaces.extend(wg_interfaces)
    all_interfaces.extend(vxlan_interfaces.keys())

    commands = []
    for interface in vxlan_interfaces:
        vni = vxlan_interfaces[interface]
        commands.extend(list_all_routes_with_table(vni))
        commands.extend(list_commands_delete_iptables(vni))
        commands.append(caculate_ip_rule_cli(vni))
    for interface in all_interfaces:
        commands.append(generate_interface_del_commands(interface))


    print("\n".join(commands))

    for command in commands:
        execute_command(command)

if __name__ == "__main__":
    main()