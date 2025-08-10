#! /bin/bash

# Function to parse response and handle output
parse_response() {
    local response="$1"
    local http_code=$(tail -n1 <<< "$response" | tr -dc '0-9')
    local body=$(sed '$ d' <<< "$response")

    if [ -n "$http_code" ] && [ "$http_code" -eq 200 ]; then
        echo "$body" | jq '.' || echo "$body"
    else
        echo "Error: HTTP status code $http_code"
        echo "Response: $body"
    fi
}

echo -e "\nFetching namespaces..."
response=$(curl -s -w "\n%{http_code}" http://192.168.50.10:8080/v1/namespace)
parse_response "$response"

echo -e "\nFetching users..."
response=$(curl -s -w "\n%{http_code}" http://192.168.50.10:8080/v1/users)
parse_response "$response"