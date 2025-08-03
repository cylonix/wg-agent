#!/bin/bash  

curl \
    --header "Content-Type: application/json"   \
    --request POST   \
    --data '[{"name":"wg_100","ip":"10.100.0.1", "prefix":16, "port":51223, "vxlan" :{"ip": "172.1.1.1/32", "vid":1043, "dstport": 8472, "gw":"192.168.100.1",  "remote": "192.168.100.33", "underlayIf": "wlp5s0", "underlayGw":"192.168.100.1" }}]'   \
    http://localhost:8080/v1/namespace \
    --verbose
