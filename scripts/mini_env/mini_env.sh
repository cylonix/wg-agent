#!/bin/bash  

WG_API="http://192.168.121.102:8080"

# TOPO
# WG-client1 <-> WG-agent
# vxlan1 <-> wg-agent
# wg-client1: 192.168.121.237
# wg-agent: 192.168.121.102
# vxlan: 192.168.121.107
# Etcd: 192.168.121.153


#common part 
NS_WG_IP="10.100.0.1"
NS_WG_PREFIX=16
NS_VXLAN_REMOTE="192.168.0.10"
NS_VXLAN_DSTPORT=8472
NS_VXLAN_UNDERLAY_IF="eth0"
NS_VXLAN_UNDERLAY_GW="192.168.0.1"


NS1_NAME="wg_100"
NS1_WG_PORT=51233
NS1_VXLAN_VID=1043
NS1_VXLAN_IP="172.1.1.2/24"
NS1_VXLAN_GW="172.1.1.1"

NS2_NAME="wg_200"
NS2_WG_PORT=51234
NS2_VXLAN_VID=1044
NS2_VXLAN_IP="172.1.2.2/24"
NS2_VXLAN_GW="172.1.2.1"


USR_SK="+Hgrrk+ZvUr2/NATu23qik9mTyHlEKQYlCcH41LAzH8="
USR_PK="LZ0/MHTHEq0JKejCo+CtBZvXUzJrVl03eAJ6nDNhGR4="

USR_IP="10.100.0.2"
USR_NAME="mike"
USR_ID="1000"


case $1 in 
    "create_ns")
    curl \
        --header "Content-Type: application/json"   \
        --request POST   \
        --verbose \
        --data "$(cat <<EOF
[{
        "name":"$NS1_NAME",
        "ip":"${NS_WG_IP}", 
        "prefix":${NS_WG_PREFIX}, 
        "port":${NS1_WG_PORT},
        "vxlan" :{
            "ip": "${NS1_VXLAN_IP}", 
            "vid":${NS1_VXLAN_VID}, 
            "dstport": ${NS_VXLAN_DSTPORT}, 
            "gw":"${NS1_VXLAN_GW}",  
            "remote": "${NS_VXLAN_REMOTE}", 
            "underlayIf": "${NS_VXLAN_UNDERLAY_IF}", 
            "underlayGw":"${NS_VXLAN_UNDERLAY_GW}" 
        }
}]
EOF
)" ${WG_API}/v1/namespace 

    curl \
        --header "Content-Type: application/json"   \
        --request POST   \
        --verbose \
        --data "$(cat <<EOF
[{
        "name":"$NS2_NAME",
        "ip":"${NS_WG_IP}", 
        "prefix":${NS_WG_PREFIX}, 
        "port":${NS2_WG_PORT},
        "vxlan" :{
            "ip": "${NS2_VXLAN_IP}", 
            "vid":${NS2_VXLAN_VID}, 
            "dstport": ${NS_VXLAN_DSTPORT}, 
            "gw":"${NS2_VXLAN_GW}",  
            "remote": "${NS_VXLAN_REMOTE}", 
            "underlayIf": "${NS_VXLAN_UNDERLAY_IF}", 
            "underlayGw":"${NS_VXLAN_UNDERLAY_GW}" 
        }
}]
EOF
)" ${WG_API}/v1/namespace 
    ;;
    "clear_ns")
    curl \
        --header "Content-Type: application/json"   \
        --request DELETE   \
        --verbose \
        --data "$(cat <<EOF
[{
        "name":"$NS1_NAME"
}]
EOF
)" ${WG_API}/v1/namespace 
    curl \
        --header "Content-Type: application/json"   \
        --request DELETE   \
        --verbose \
        --data "$(cat <<EOF
[{
        "name":"$NS2_NAME"
}]
EOF
)" ${WG_API}/v1/namespace 
    ;;
    "create_user")
    curl --header "Content-Type: application/json" \
      --request POST \
      --verbose \
      --data "$(cat <<EOF
[{
    "namespace":"${NS1_NAME}", 
    "id":"${USR_ID}",
    "name":"${USR_NAME}", 
    "pubkey":"${USR_PK}", 
    "allowed_ips":["${USR_IP}/32", "172.1.1.0/24"]
}]
EOF
)" ${WG_API}/v1/user

    curl --header "Content-Type: application/json" \
      --request POST \
      --verbose \
      --data "$(cat <<EOF
[{
    "namespace":"${NS2_NAME}", 
    "name":"${USR_NAME}", 
    "id":"${USR_ID}",
    "pubkey":"${USR_PK}", 
    "allowed_ips":["${USR_IP}/32", "172.1.1.0/24"]
}]
EOF
)" ${WG_API}/v1/user
    ;;
    "delete_user")
    curl --header "Content-Type: application/json" \
      --request DELETE \
      --data "$(cat <<EOF
[{
    "namespace":"${NS1_NAME}", 
    "id":"${USR_ID}",
    "name":"${USR_NAME}", 
    "pubkey":"${USR_PK}"
}]
EOF
)" ${WG_API}/v1/user

    curl --header "Content-Type: application/json" \
      --request DELETE \
      --data "$(cat <<EOF
[{
    "namespace":"${NS2_NAME}", 
    "id":"${USR_ID}",
    "name":"${USR_NAME}", 
    "pubkey":"${USR_PK}"
}]
EOF
)" ${WG_API}/v1/user

    ;;
esac
