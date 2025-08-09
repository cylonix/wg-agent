#!/bin/bash

# This script is designed to be run after all VMs are provisioned
# It will collect the public keys from all clients and set up the server

# Check for --clean flag
if [ "$1" == "--clean" ]; then
    echo "Cleaning up existing WireGuard configurations..."

    # Clean up server configurations
    echo "Cleaning up server namespaces..."
    curl -X DELETE \
        --header "Content-Type: application/json" \
        --data '[{
                    "name":"ns1_143",
                    "ip":"10.10.10.1",
                    "prefix":16,
                    "vxlan" :{
                        "ip":"",
                        "vid":1043,
                        "dstport":8472,
                        "gw":"",
                        "remote":"",
                        "underlayIf": "",
                        "underlayGw": ""
                    }
                },
                {
                    "name":"ns2_144",
                    "ip":"10.10.20.1",
                    "prefix":16,
                    "vxlan" :{
                        "ip":"",
                        "vid":1044,
                        "dstport":8472,
                        "gw":"",
                        "remote":"",
                        "underlayIf": "",
                        "underlayGw": ""
                    }
                },
                {
                    "name":"ns3_145",
                    "ip":"10.10.30.1",
                    "prefix":16,
                    "vxlan" :{
                        "ip":"",
                        "vid":1045,
                        "dstport":8472,
                        "gw":"",
                        "remote":"",
                        "underlayIf": "",
                        "underlayGw": ""
                    }
                }]' \
        http://192.168.50.10:8080/v1/namespace 2>/dev/null || true

   # Stop WireGuard on clients
    echo "Stopping WireGuard on clients..."
    for CLIENT in client1 client2 client3 client4; do
        echo "Cleaning up WireGuard on $CLIENT..."
        vagrant ssh $CLIENT -c "sudo wg-quick down wg0 2>/dev/null || true"
    done

    echo -e "\nCleanup complete!"
    echo "Run the script without --clean to set up new configurations"
    exit 0
fi

VXLAN1=''
VXLAN2=''
VXLAN3=''
if [ "$1" == "--vxlan" ]; then
    VXLAN1='"vxlan" :{
            "ip":"172.1.1.1/30",
            "vid":1043,
            "dstport":8472,
            "gw":"",
            "remote":"172.1.1.2",
            "underlayIf": "eth0",
            "underlayGw": ""
        },'
    VXLAN2='"vxlan" :{
            "ip":"172.2.1.1/30",
            "vid":1044,
            "dstport":8472,
            "gw":"",
            "remote":"172.2.1.2",
            "underlayIf": "eth0",
            "underlayGw": ""
        },'
    VXLAN3='"vxlan" :{
            "ip":"172.3.1.1/30",
            "vid":1045,
            "dstport":8472,
            "gw":"",
            "remote":"172.3.1.2",
            "underlayIf": "eth0",
            "underlayGw": ""
        },'
fi
echo "Setting up WireGuard connections between server and clients..."

# Generate server keys if they don't exist
if ! vagrant ssh wg-server -c "sudo test -f /etc/wireguard/privatekey"; then
    echo 'Generating WireGuard server keys...'
    vagrant ssh wg-server -c "
        sudo mkdir -p /etc/wireguard
        sudo wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey
        sudo chmod 600 /etc/wireguard/privatekey"
else
    echo 'WireGuard server keys already exist.'
fi

# Get server keys
SERVER_PUBKEY=$(vagrant ssh wg-server -c "sudo cat /etc/wireguard/publickey" | tr -d '\r')
SERVER_PRIVKEY=$(vagrant ssh wg-server -c "sudo cat /etc/wireguard/privatekey" | tr -d '\r')
echo "Server public key: $SERVER_PUBKEY, private key: $SERVER_PRIVKEY"

# Get client public keys
CLIENT1_PUBKEY=$(vagrant ssh client1 -c "sudo cat /etc/wireguard/publickey" | tr -d '\r')
CLIENT2_PUBKEY=$(vagrant ssh client2 -c "sudo cat /etc/wireguard/publickey" | tr -d '\r')
CLIENT3_PUBKEY=$(vagrant ssh client3 -c "sudo cat /etc/wireguard/publickey" | tr -d '\r')
CLIENT4_PUBKEY=$(vagrant ssh client4 -c "sudo cat /etc/wireguard/publickey" | tr -d '\r')

echo "Client 1 public key: $CLIENT1_PUBKEY"
echo "Client 2 public key: $CLIENT2_PUBKEY"
echo "Client 3 public key: $CLIENT3_PUBKEY"
echo "Client 4 public key: $CLIENT4_PUBKEY"

# Update client configurations with server public key
for CLIENT in client1 client2 client3 client4; do
  vagrant ssh $CLIENT -c "sudo sed -i 's|PublicKey = .*|PublicKey = $SERVER_PUBKEY|' /etc/wireguard/wg0.conf"
done

# Create server configuration for namespace 1 (clients 1 and 2)
echo "Creating server configuration namespace 1..."
curl \
    --header "Content-Type: application/json"   \
    --request POST   \
    --data "[{
        \"name\":\"ns1_143\",
        \"ip\":\"10.10.10.1\",
        \"prefix\":16,
        \"port\":51223,
        $VXLAN1
        \"public_key\":\"${SERVER_PUBKEY}\",
        \"private_key\":\"${SERVER_PRIVKEY}\"}]" \
    http://192.168.50.10:8080/v1/namespace

echo -e "\nCreating user1 for namespace 1..."
curl \
    --header "Content-Type: application/json"   \
    --request POST   \
    --data "[{
        \"id\": \"wg_user_id_11\", \
        \"device_id\": \"wg_device_id_11\", \
        \"namespace\":\"ns1_143\", \
        \"name\":\"user11\", \
        \"pubkey\":\"$CLIENT1_PUBKEY\", \
        \"allowed_ips\":[\"10.10.10.21/32\"]}]" \
    http://192.168.50.10:8080/v1/user

echo -e "\nCreating user2 for namespace 1..."
curl \
    --header "Content-Type: application/json"   \
    --request POST   \
    --data "[{
        \"id\": \"wg_user_id_12\", \
        \"device_id\": \"wg_device_id_12\", \
        \"namespace\":\"ns1_143\", \
        \"name\":\"user12\", \
        \"pubkey\":\"$CLIENT2_PUBKEY\", \
        \"allowed_ips\":[\"10.10.10.22/32\"]}]" \
    http://192.168.50.10:8080/v1/user

echo -e "\nCreating server configuration for namespace 2..."
curl \
    --header "Content-Type: application/json"   \
    --request POST   \
    --data "[{
        \"name\":\"ns2_144\",
        \"ip\":\"10.10.20.1\",
        \"prefix\":16,
        \"port\":51224,
        $VXLAN2
        \"public_key\":\"${SERVER_PUBKEY}\",
        \"private_key\":\"${SERVER_PRIVKEY}\"}]" \
    http://192.168.50.10:8080/v1/namespace

echo -e "\nCreating user for namespace 2..."
curl \
    --header "Content-Type: application/json"   \
    --request POST   \
    --data "[{
        \"id\": \"wg_user_id_21\", \
        \"device_id\": \"wg_device_id_21\", \
        \"namespace\":\"ns2_144\", \
        \"name\":\"user21\", \
        \"pubkey\":\"$CLIENT3_PUBKEY\", \
        \"allowed_ips\":[\"10.10.20.0/24\"]}]" \
    http://192.168.50.10:8080/v1/user

echo -e "\nCreating server configuration for namespace 3..."
curl \
    --header "Content-Type: application/json"   \
    --request POST   \
    --data "[{
        \"name\":\"ns3_145\",
        \"ip\":\"10.10.30.1\",
        \"prefix\":16,
        \"port\":51225,
        $VXLAN3
        \"public_key\":\"${SERVER_PUBKEY}\",
        \"private_key\":\"${SERVER_PRIVKEY}\"}]" \
    http://192.168.50.10:8080/v1/namespace

echo -e "\nCreating user for namespace 3..."
curl \
    --header "Content-Type: application/json"   \
    --request POST   \
    --data "[{
        \"id\": \"wg_user_id_31\", \
        \"device_id\": \"wg_device_id_31\", \
        \"namespace\":\"ns3_145\", \
        \"name\":\"user31\", \
        \"pubkey\":\"$CLIENT4_PUBKEY\", \
        \"allowed_ips\":[\"10.10.30.0/24\"]}]" \
    http://192.168.50.10:8080/v1/user

# Start WireGuard on clients
echo -e "\nStarting WireGuard on clients..."
for CLIENT in client1 client2 client3 client4; do
  vagrant ssh $CLIENT -c "sudo wg-quick up wg0"
done

echo "Testing connectivity..."
#vagrant ssh client1 -c "ping -c 4 10.10.10.1"
#vagrant ssh client2 -c "ping -c 4 10.10.10.1"
#vagrant ssh client3 -c "ping -c 4 10.10.20.1"
#vagrant ssh client4 -c "ping -c 4 10.10.30.1"

echo "WireGuard connections setup complete!"
echo "To verify configuration on the server:"
echo "vagrant ssh wg-server -c 'sudo wg show'"
echo "To test client1 to client2 connectivity (same namespace/VRF):"
echo "vagrant ssh client1 -c 'ping -c 4 10.10.10.22'"
