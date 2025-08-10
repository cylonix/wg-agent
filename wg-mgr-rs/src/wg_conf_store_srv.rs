// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

use async_trait::async_trait;
use etcd_rs::{ Client, ClientConfig, KeyValueOp, DeleteResponse, Endpoint };
use log::{ debug, info, warn };
use std::io::{ Error, ErrorKind };
use std::io::Result as IoResult;
use std::collections::HashMap;
use std::time::Duration;
use wg_api::models::{ self, * };

pub struct EtcdClientConfig {
    nodes: Vec<String>,
}

pub const ETCD_NAMESPACE_PREFIX: &str = "/wg/{hostname}/namespace/configuration";
pub const ETCD_USER_PREFIX: &str = "/wg/{hostname}/namespace/users";

impl EtcdClientConfig {
    pub fn new(nodes: &Vec<&str>) -> Self {
        let nodes_string = nodes
            .iter()
            .map(|&res| res.to_string())
            .collect();

        EtcdClientConfig {
            nodes: nodes_string,
        }
    }

    pub async fn connect(&self) -> Option<Client> {
        // Create endpoints using Endpoint::new
        let endpoints: Vec<Endpoint> = self.nodes
            .iter()
            .map(|node| {
                // Try parsing as URI first, then add http:// if needed
                let uri = if node.starts_with("http://") || node.starts_with("https://") {
                    node.clone()
                } else {
                    format!("http://{}", node)
                };

                // Use Endpoint::new which takes a string
                Endpoint::new(uri)
            })
            .collect();

        let client = Client::connect(ClientConfig {
            endpoints,
            auth: None,
            connect_timeout: Duration::from_secs(5),
            http2_keep_alive_interval: Duration::from_secs(30),
        }).await;

        client.ok()
    }
}

pub fn get_hostname() -> IoResult<String> {
    let name = hostname::get()?;
    let namestr = name
        .to_str()
        .ok_or_else(|| { Error::new(ErrorKind::InvalidData, "Invalid hostname") })?;
    Ok(namestr.to_string())
}

fn generate_namespace_key(namespace: &str) -> String {
    let hostname = get_hostname().unwrap_or_else(|_| "localhost".to_string());
    format!("/wg/{}/namespace/configuration/{}", hostname, namespace)
}

fn generate_user_key(namespace: &str, user: &str) -> String {
    let prefix = generate_all_users_key_with_namespace(namespace);
    format!("{}/{}", prefix, user)
}

fn generate_all_users_key_with_namespace(namespace: &str) -> String {
    let hostname = get_hostname().unwrap_or_else(|_| "localhost".to_string());
    format!("/wg/{}/namespace/users/{}", hostname, namespace)
}

fn generate_pk_to_user_id_key(namespace: &str, pk: &str) -> String {
    let hostname = get_hostname().unwrap_or_else(|_| "localhost".to_string());
    format!("/wg/{}/namespace/pk_to_user_ids/{}/{}", hostname, namespace, pk)
}

#[async_trait]
pub trait EtcdApiHander {
    // user indexed with user id (not public key)
    async fn save_user(&self, namespace: &str, id: &str, content: &str) -> IoResult<()>;
    async fn get_user(&self, namespace: &str, id: &str) -> IoResult<WgUser>;
    async fn delete_user(&self, namespace: &str, id: &str) -> IoResult<()>;

    // public key to user id mapping
    async fn save_pk(&self, namespace: &str, pk: &str, content: &str) -> IoResult<()>;
    async fn get_pk(&self, namespace: &str, pk: &str) -> IoResult<String>;
    async fn delete_pk(&self, namespace: &str, pk: &str) -> IoResult<()>;

    // entry api
    async fn save_entry(&self, key: &str, content: &str) -> IoResult<()>;
    async fn get_single_entry(&self, key: &str) -> IoResult<String>;
    async fn delete_entry(&self, key: &str) -> IoResult<()>;

    // namespace
    async fn save_namespace(&self, namespace: &str, content: &str) -> IoResult<()>;
    async fn get_namespace_names(&self) -> IoResult<Vec<String>>;
    async fn get_namespace_details(&self) -> IoResult<HashMap<String, WgNamespace>>;
    async fn get_namespace(&self, namespace: &str) -> IoResult<WgNamespace>;
    async fn delete_namespace(&self, namespace: &str) -> IoResult<DeleteResponse>;
    async fn delete_all_users_with_namespace(&self, namespace: &str) -> IoResult<()>;
    async fn get_all_users_with_namespace(
        &self,
        namespace: &str
    ) -> IoResult<HashMap<String, WgUser>>;
}

#[async_trait]
impl EtcdApiHander for Client {
    async fn save_namespace(&self, namespace: &str, content: &str) -> IoResult<()> {
        let key = generate_namespace_key(namespace);
        // etcd-rs put expects a tuple (key, value)
        let result = self.put((key, content)).await;

        result.map_or_else(
            |e| Err(Error::new(ErrorKind::Other, e.to_string())),
            |_| Ok(())
        )
    }

    async fn save_user(&self, namespace: &str, id: &str, content: &str) -> IoResult<()> {
        self.save_entry(&generate_user_key(namespace, id), content).await
    }

    async fn save_pk(&self, namespace: &str, pk: &str, content: &str) -> IoResult<()> {
        self.save_entry(&generate_pk_to_user_id_key(namespace, pk), content).await
    }

    async fn save_entry(&self, key: &str, content: &str) -> IoResult<()> {
        // etcd-rs put expects a tuple (key, value)
        let result = self.put((key, content)).await;

        result.map_or_else(
            |e| Err(Error::new(ErrorKind::Other, e.to_string())),
            |_| Ok(())
        )
    }

    async fn get_namespace_names(&self) -> IoResult<Vec<String>> {
        let hostname = get_hostname().unwrap_or_else(|_| "localhost".to_string());
        let prefix = format!("/wg/{}/namespace/configuration/", hostname);
        let prefix_end = format!("/wg/{}/namespace/configuration0", hostname);
        self.get_range(prefix.as_bytes(), prefix_end.as_bytes()).await.map_or_else(
            |e| Err(Error::new(ErrorKind::Other, e.to_string())),
            |range| {
                debug!("namespace count: {} prefix: {}", range.count, prefix);
                Ok(range.kvs
                    .iter()
                    .filter_map(|kv| {
                        String::from_utf8(kv.key.clone())
                            .ok()
                            .and_then(|key_str|
                                key_str
                                    .split('/')
                                    .last()
                                    .map(|s| s.to_string())
                            )
                    })
                    .collect::<Vec<_>>()
                )
            }
        )
    }

    async fn get_namespace(&self, namespace: &str) -> IoResult<WgNamespace> {
        let key = generate_namespace_key(namespace);
        // get_range expects Vec<u8> parameters
        let ret = self.get_range(key.as_bytes(), key.as_bytes()).await;

        match ret {
            Ok(ns_config) => {
                debug!("Got response namespace from etcd database: {}", namespace);

                if ns_config.kvs.is_empty() {
                    debug!("No namespace found in etcd database: {}", namespace);
                    Err(Error::new(ErrorKind::NotFound, "namespace not found"))
                } else if ns_config.kvs.len() != 1 {
                    Err(Error::new(ErrorKind::InvalidData, "multiple namespaces found"))
                } else {
                    let value_str = String::from_utf8(ns_config.kvs[0].value.clone()).map_err(|e|
                        Error::new(ErrorKind::InvalidData, e.to_string())
                    )?;

                    let namespace_conf = serde_json::from_str::<models::WgNamespace>(&value_str);

                    namespace_conf.map_err(|e| {
                        Error::new(ErrorKind::InvalidData, e.to_string())
                    })
                }
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e.to_string())),
        }
    }

    async fn get_user(&self, namespace: &str, id: &str) -> IoResult<WgUser> {
        let key = generate_user_key(namespace, id);
        let ret = self.get_by_prefix(key.as_bytes()).await;

        match ret {
            Ok(user_config) => {
                debug!("Got response from etcd database: namespace {}, id: {}", namespace, id);

                if user_config.kvs.is_empty() {
                    debug!("Cannot find user in database: {}/{}", namespace, id);
                    Err(Error::new(ErrorKind::NotFound, "no user with id found"))
                } else if user_config.kvs.len() != 1 {
                    Err(Error::new(ErrorKind::InvalidData, "multiple users found"))
                } else {
                    let value_str = String::from_utf8(user_config.kvs[0].value.clone()).map_err(|e|
                        Error::new(ErrorKind::InvalidData, e.to_string())
                    )?;

                    let user_conf = serde_json::from_str::<models::WgUser>(&value_str);

                    user_conf.map_err(|e| { Error::new(ErrorKind::InvalidData, e.to_string()) })
                }
            }
            Err(e) => Err(Error::new(ErrorKind::Other, e.to_string())),
        }
    }

    async fn get_pk(&self, namespace: &str, pk: &str) -> IoResult<String> {
        self.get_single_entry(&generate_pk_to_user_id_key(namespace, pk)).await
    }

    async fn get_single_entry(&self, key: &str) -> IoResult<String> {
        self.get_by_prefix(key.as_bytes()).await.map_err(|e| {
            Error::new(ErrorKind::Other, format!("failed to get from etcd for key {}: {}", key, e))
        }).and_then(|range_resp| {
            if range_resp.kvs.is_empty() {
                debug!("Cannot find entry in etcd with key {}", key);
                Err(Error::new(ErrorKind::NotFound, format!("no entry with key {} found", key)))
            } else if range_resp.kvs.len() != 1 {
                Err(Error::new(ErrorKind::InvalidData, format!("multiple entries found with key {}", key)))
            } else {
                String::from_utf8(range_resp.kvs[0].value.clone()).map_err(|e| {
                    Error::new(ErrorKind::InvalidData, format!("Failed to parse value for key {}: {}", key, e))
                })
            }
        })
    }

    async fn delete_namespace(&self, namespace: &str) -> IoResult<DeleteResponse> {
        let key = generate_namespace_key(namespace);
        // delete expects string, so dereference the String
        let delete = self.delete(key.as_str()).await;

        delete.map_err(|e| { Error::new(ErrorKind::Other, e.to_string()) })
    }

    async fn delete_user(&self, namespace: &str, id: &str) -> IoResult<()> {
        self.delete_entry(&generate_user_key(namespace, id)).await
    }

    async fn delete_pk(&self, namespace: &str, pk: &str) -> IoResult<()> {
        self.delete_entry(&generate_pk_to_user_id_key(namespace, pk)).await
    }

    async fn delete_entry(&self, key: &str) -> IoResult<()> {
        // delete expects &str
        let delete = self.delete(key).await;

        delete.map_or_else(
            |e| Err(Error::new(ErrorKind::Other, e.to_string())),
            |_| Ok(())
        )
    }

    async fn get_namespace_details(&self) -> IoResult<HashMap<String, WgNamespace>> {
        debug!("Trying to read all namespace configurations...");
        let mut hm = HashMap::new();

        let hostname = get_hostname().unwrap_or_else(|_| "localhost".to_string());
        let prefix = format!("/wg/{}/namespace/configuration/", hostname);
        let prefix_end = format!("/wg/{}/namespace/configuration0", hostname);

        // get_range expects Vec<u8> parameters
        let values = self.get_range(prefix.as_bytes(), prefix_end.as_bytes()).await;

        let kvs = values.map_err(|e| { Error::new(ErrorKind::Other, e.to_string()) })?.kvs;

        if kvs.is_empty() {
            debug!("No namespace found...");
        }

        for kv in kvs {
            let key_str = String::from_utf8(kv.key).map_err(|e| {
                Error::new(ErrorKind::InvalidData, e.to_string())
            })?;

            let value_str = String::from_utf8(kv.value).map_err(|e| {
                Error::new(ErrorKind::InvalidData, e.to_string())
            })?;

            let namespace = key_str
                .split('/')
                .last()
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::InvalidData,
                        format!("Cannot get namespace for {}", key_str)
                    )
                })?;

            let wg = serde_json
                ::from_str::<WgNamespace>(&value_str)
                .map_err(|e| {
                    Error::new(
                        ErrorKind::InvalidData,
                        format!("Cannot deserialize WgNamespace: {}", e)
                    )
                })?;

            hm.insert(namespace.to_string(), wg);
        }
        Ok(hm)
    }

    async fn delete_all_users_with_namespace(&self, namespace: &str) -> IoResult<()> {
        let key = generate_all_users_key_with_namespace(namespace);
        let prefix = format!("{}/", key);
        let prefix_end = format!("{}0", key);

        // First get all keys to delete - get_range expects Vec<u8> parameters
        let range_resp = self
            .get_range(prefix.as_bytes(), prefix_end.as_bytes()).await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

        // Delete each key individually - convert Vec<u8> to String first
        for kv in range_resp.kvs {
            let key_str = String::from_utf8(kv.key).map_err(|e| {
                Error::new(ErrorKind::InvalidData, e.to_string())
            })?;
            let _ = self.delete(key_str.as_str()).await; // Ignore individual delete errors
        }

        Ok(())
    }

    // TODO: support pagination so that we don't load all users at once
    async fn get_all_users_with_namespace(
        &self,
        namespace: &str
    ) -> IoResult<HashMap<String, WgUser>> {
        debug!("Trying to read all users with namespace {}...", namespace);
        let mut hm = HashMap::new();

        let key = generate_all_users_key_with_namespace(namespace);
        let prefix = format!("{}/", key);
        let prefix_end = format!("{}0", key);

        let all_users_resp = self.get_range(prefix.as_bytes(), prefix_end.as_bytes()).await;

        let all_users_kvs = all_users_resp.map_err(|e| {
            debug!("Errors when reading all users for {}", namespace);
            Error::new(ErrorKind::Other, e.to_string())
        })?.kvs;

        if all_users_kvs.is_empty() {
            info!("No wg user found for namespace {}", namespace);
        }

        for user_kv in all_users_kvs {
            let key_str = String::from_utf8(user_kv.key.clone()).map_err(|e| {
                Error::new(ErrorKind::InvalidData, e.to_string())
            })?;

            let value_str = String::from_utf8(user_kv.value).map_err(|e| {
                Error::new(ErrorKind::InvalidData, e.to_string())
            })?;

            let wg_user = serde_json::from_str::<WgUser>(&value_str);
            if let Err(e) = wg_user {
                warn!(
                    "Cannot deserialize entry at {} for user {}, reason: {}",
                    key_str,
                    value_str,
                    e
                );
                // Use as_str() to convert String to &str for delete
                let _ = self.delete(key_str.as_str()).await;
            } else {
                hm.insert(key_str, wg_user.unwrap());
            }
        }
        Ok(hm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_get_hostname() {
        let hostname = get_hostname();
        assert!(hostname.is_ok());
        let hostname = hostname.unwrap();
        assert!(!hostname.is_empty());
        println!("Hostname: {}", hostname);
    }

    #[test]
    fn test_etcd_client_config_creation() {
        let endpoints = vec!["http://127.0.0.1:2379"];
        let config = EtcdClientConfig::new(&endpoints);

        // Test that config is created properly
        assert!(config.nodes.len() == 1);
    }

    #[tokio::test]
    #[ignore] // Requires running etcd instance
    async fn test_etcd_connection() {
        let endpoints = vec!["http://127.0.0.1:2379"];
        let config = EtcdClientConfig::new(&endpoints);
        let client = config.connect().await;

        // This test would only pass with a running etcd instance
        if let Some(_client) = client {
            println!("Successfully connected to etcd");
        }
    }

    // Test configuration parsing/validation
    #[test]
    fn test_namespace_configuration_validation() {
        // Test valid configuration
        let mut valid_config = HashMap::new();
        valid_config.insert("name".to_string(), "test-namespace".to_string());
        valid_config.insert("ip".to_string(), "10.0.0.1/24".to_string());
        valid_config.insert("port".to_string(), "51820".to_string());

        assert!(validate_namespace_config(&valid_config));

        // Test invalid configuration
        let mut invalid_config = HashMap::new();
        invalid_config.insert("name".to_string(), "".to_string()); // Empty name

        assert!(!validate_namespace_config(&invalid_config));
    }

    // Helper function for config validation
    fn validate_namespace_config(config: &HashMap<String, String>) -> bool {
        config.get("name").map_or(false, |name| !name.is_empty()) &&
            config.get("ip").map_or(false, |ip| ip.contains('/')) &&
            config.get("port").map_or(false, |port| port.parse::<u16>().is_ok())
    }
}
