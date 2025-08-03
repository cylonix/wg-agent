#!/bin/bash  

curl --header "Content-Type: application/json" \
  --request POST \
  --data '[{"namespace":"wg100", "name":"user-error", "pubkey":"L3TCbSZkpnCoFwGHb5g0WFDjM51NQ/E02RoUTXE3fSk=", "allowed_ips":["0.0.0.0/0"]}]' \
  http://localhost:8080/v1/user