# How to test a wg-agent

## Common Test commands

* create a namespace with curl

```bash
curl --header "Content-Type: application/json"   --request POST   --data '[{"name":"wg100","ip":"10.100.0.1", "prefix":16, "port":51223, "vxlan" :{"ip": "172.1.1.1/32", "vid":1043, "dstport": 8472, "gw":"192.168.88.1",  "remote": "192.168.88.33", "underlay_if": "enp7s0" }}]'   http://localhost:8080/v1/namespace --verbose 

or 

curl --header "Content-Type: application/json"   --request POST   --data '[{"name":"wg100","ip":"10.100.0.1", "prefix":16, "port":51223, "vxlan" :{"ip": "172.1.1.1/32", "vid":1043, "dstport": 8472, "gw":"192.168.100.1",  "remote": "192.168.100.33", "underlay_if": "enp0s8" }}]'   http://localhost:8080/v1/namespace --verbose

```

* delete a namespace

```bash
curl --header "Content-Type: application/json" \
  --request DELETE \
  --data '[{"name":"wg100"}]' \
  http://localhost:8080/v1/namespace
```

* get the namespace

```bash
curl --header "Content-Type: application/json" \
  --request GET \
  --data '[{"name":"wg100"}]' \
  http://localhost:8080/v1/namespace
```

* get namespace user stats

```bash
curl --header "Content-Type: application/json" \
  --request GET \
  --data '[{"name":"wg100"}]' \
  http://localhost:8080/v1/namespace/userstats
```

* create user

```bash
curl --header "Content-Type: application/json" \
  --request POST \
  --data '[{"namespace":"wg100", "name":"cylonix", "pubkey":"v5rrqGUYEHpQd0ujsENkmYgsPA1NWwfahhqcgEuKvAs=", "allowed_ips":["10.1.0.0/24", "10.1.1.0/24"]}]' \
  http://localhost:8080/v1/user
```

* delete user(s)
  
```bash
curl --header "Content-Type: application/json" \
  --request DELETE \
  --data '[{"namespace":"wg100", "name":"cylonix", "pubkey":"v5rrqGUYEHpQd0ujsENkmYgsPA1NWwfahhqcgEuKvAs="}]' \
  http://localhost:8080/v1/user
```

* list users

```bash
curl --header "Content-Type: application/json" \
  --request GET \
  http://localhost:8080/v1/users
```

* get user stats

```bash
curl --header "Content-Type: application/json" \
  --request GET --data '{"namespace":"wg100", "name":"cylonix", "pubkey":"pk:v5rrqGUYEHpQd0ujsENkmYgsPA1NWwfahhqcgEuKvAs="}' \
  http://localhost:8080/v1/user/stats
```

* get user detail

```bash
curl --header "Content-Type: application/json"   --request GET --data '{"namespace":"wg100", "name":"cylonix", "pubkey":"pk:v5rrqGUYEHpQd0ujsENkmYgsPA1NWwfahhqcgEuKvAs="}' http://localhost:8080/v1/user --verbose

```

* get namespace stats

```bash
curl --header "Content-Type: application/json"   --request GET   --data '[{"name":"wg100"}]'   http://localhost:8080/v1/namespace/stats | python3 -m json.tool

```

## Start a test etcd server

```bash
 docker run -d --name etcd-server      --publish 2379:2379     --publish 2380:2380     --env ALLOW_NONE_AUTHENTICATION=yes     --env ETCD_ADVERTISE_CLIENT_URLS=http://etcd-server:2379 bitnami/etcd:latest
```

## Verify the etcd client

```bash
export ETCDCTL_API=3 
sudo apt install etcd-client
#to test if the servre is ready 
etcdctl member list 
```
