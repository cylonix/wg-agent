#!/bin/bash  

curl --header "Content-Type: application/json" \
  --request POST \
  --data '[{"namespace":"wg100", "name":"cylonix", "pubkey":"v5rrqGUYEHpQd0ujsENkmYgsPA1NWwfahhqcgEuKvAs=", "allowed_ips":["10.1.0.0/24", "10.1.1.0/24"]}]' \
  http://localhost:8080/v1/user