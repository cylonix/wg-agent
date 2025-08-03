#!/bin/bash  

curl \
    --header "Content-Type: application/json"   \
    --request POST   \
    --data '[{"name":"wg100","ip":"10.100.0.1", "prefix":16, "port":51223, "vxlan" :{"ip": "172.100.1.100/24", "vid":1043, "dstport": 8472, "gw":"172.100.1.1",  "remote": "192.168.88.33", "underlay_if": "enp7s0" }}]' \
    http://localhost:8080/v1/namespace \
    --verbose

   
