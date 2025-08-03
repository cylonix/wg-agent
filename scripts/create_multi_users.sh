#!/bin/bash  

curl --header "Content-Type: application/json" \
  --request POST \
  --data '[{"namespace":"wg100", "name":"cylonix2", "pubkey":"v5rrqGUYEHpQd0ujsENkmYgsPA1NWwfahhqcgEuKvAs=", "allowed_ips":["10.1.0.0/24", "10.1.1.0/24"]}]' \
  http://localhost:8080/v1/user

curl --header "Content-Type: application/json" \
  --request POST \
  --data '[{"namespace":"wg100", "name":"cylonix1", "pubkey":"KfrHaiEWkMeIo2YmXgrP/7NXFyq9XA5qY+c7nnF1bkg=", "allowed_ips":["10.1.2.0/24", "10.1.3.0/24"]}]' \
  http://localhost:8080/v1/user