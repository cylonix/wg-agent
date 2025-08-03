# WG-Agent Setup Guide

## Network Configuration

- **Infra**: 192.168.121.118/24
- **Agent**: 192.168.121.42/24
- **VXLAN**: 192.168.121.241/24
- **WG-Client**: 192.168.121.195/24

## Setup Steps

### 1. Update the system

```bash
sudo apt update 
sudo apt install wireguard -y
```

### 2. Generate the secret key for wg-client

- **Secret Key (sk)**: `WH5mpuSLg3sRX/6DG+qVx2/VuwLu1snW3NvNkdP0QnE=`
- **Public Key (pk)**: `3bpkrgzBBWQx9CaiqdbACsbud2iZ2I8ru5QHlKLtQn8=`

### 3. Start the wg-agent

```bash
RUST_LOG=debug ./wg-agent --etcd http://192.168.121.118:12379
```

### 4. Create the namespace

```bash
# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# Navigate to the scripts directory
cd scripts/mini_env

# Create namespace
./one_user.sh create_ns
```

#### Check the WG setting in wg-agent

```bash
wg show
```

Expected output:

```bash
interface: wg_100
  public key: 2dZgHj/Md9Gy7+ChJWpGwNZ3UaVh+ywaCoQ7vY68Xw4=
  private key: (hidden)
  listening port: 51233
```

### 5. Create the WG interface in wg-client

```bash
ip link del wg0
ip link add wg100 type wireguard
ip addr add 10.100.0.1/32 dev wg100
ip route add 172.1.1.0/24 via 10.100.0.1
wg set wg100 private-key sk
ip link set wg100 up
wg set wg100 peer 2dZgHj/Md9Gy7+ChJWpGwNZ3UaVh+ywaCoQ7vY68Xw4= allowed-ips 10.100.0.1/32,172.1.1.0/24 endpoint 192.168.121.42:51233
```

### 6. Create the user

```bash
cd scripts/mini_env
./one_user.sh create_user
```

### 7. Test the link between client and wg-agent

```bash
ping 10.100.0.1  # Should be OK now
```

### 8. Create the VXLAN interface

```bash
ip link add dev vxlan_1043 type vxlan id 1043 dstport 8472 remote 192.168.121.42
ip link set dev vxlan_1043 up
ip addr add 172.1.1.1/24 dev vxlan_1043
ip route add 10.100.0.1/32 via 172.1.1.2
ip route add 10.100.0.2/32 via 172.1.1.2
ping 172.1.1.2
```
