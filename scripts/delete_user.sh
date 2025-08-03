#!/bin/bash  

curl --header "Content-Type: application/json" \
  --request DELETE \
  --data '[{"namespace":"wg100", "name":"cylonix", "pubkey":"v5rrqGUYEHpQd0ujsENkmYgsPA1NWwfahhqcgEuKvAs="}]' \
  http://localhost:8080/v1/user