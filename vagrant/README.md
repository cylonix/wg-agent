# WireGuard Manager Test Environment

This Vagrant setup creates a 5-VM test environment for the WireGuard Manager service:

- 1 server VM (`wg-server`) running the wg-mgr-rs service
- 4 client VMs connecting to the server:
  - `client1` and `client2` share the same namespace (ns1) and VRF (vrf1)
  - `client3` uses namespace ns2 and VRF vrf2
  - `client4` uses namespace ns3 and VRF vrf3

## Requirements

- Vagrant 2.2+
- libvirt plugin
- At least 4GB RAM available

## Getting Started

1. Start the VMs:

   ```bash
   cd vagrant
   vagrant up
   ```

2. After all VMs are running, run the test script:

   ```bash
   ./setup.sh
   ```

## VM Details

### Server VM (wg-server)

- IP: 192.168.50.10
- WireGuard interfaces:
  - wg0: 10.10.10.1/24 (for clients 1 & 2)
  - wg1: 10.20.20.1/24 (for client 3)
  - wg2: 10.30.30.1/24 (for client 4)

### Client VMs

- client1: 192.168.50.21, WireGuard IP: 10.10.10.21/24
- client2: 192.168.50.22, WireGuard IP: 10.10.10.22/24
- client3: 192.168.50.23, WireGuard IP: 10.20.20.23/24
- client4: 192.168.50.24, WireGuard IP: 10.30.30.24/24

## Testing the WireGuard Manager Service

The wg-mgr-rs service is set up to run on startup on the server VM. To manually restart it:

```bash
vagrant ssh wg-server -c 'sudo service wg-agent restart'
```

## Update code and rebuild for testing

- update code first
- then sync the code the wg-server vm and rebuild in the wg-server vm and restart service

  ```bash
  cd vagrant
  ./update.sh
  ```

- re-test

  ```bash
  cd vagrant
  ./setup.sh
  ```

## Cleanup

To remove all VMs:

```bash
vagrant destroy -f
```
