#!/bin/bash  

curl --header "Content-Type: application/json" \
  --request DELETE \
  --data '[{"name":"wg_100"}]' \
  http://localhost:8080/v1/namespace
