// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

use async_trait::async_trait;
use etcd_rs::{
    Client, ClientConfig, KeyValueOp, DeleteResponse,
    Endpoint,
};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::time::Duration;
use wg_api::models::{self, *};
use std::io;

pub struct EtcdClientConfig {
    nodes: Vec<String>,
}

pub const ETCD_NAMESPACE_PREFIX: &str = "/wg/{hostname}/namespace/configuration";
pub const ETCD_USER_PREFIX: &str = "/wg/{hostname}/namespace/users";

impl EtcdClientConfig {
    pub fn new(nodes: &Vec<&str>) -> Self {
        let nodes_string = nodes.iter().map(|&res| res.to_string()).collect();

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
        })
        .await;

        client.ok()
    }
}

pub fn get_hostname() -> io::Result<String> {
    let name = hostname::get()?;
    let namestr = name.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "Invalid hostname")
    })?;
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
    async fn save_user(&self, namespace: &str, id: &str, content: &str) -> std::io::Result<()>;
    async fn get_user(&self, namespace: &str, id: &str) -> std::io::Result<WgUser>;
    async fn delete_user(&self, namespace: &str, id: &str) -> std::io::Result<()>;

    // public key to user id mapping
    async fn save_pk(&self, namespace: &str, pk: &str, content: &str) -> std::io::Result<()>;
    async fn get_pk(&self, namespace: &str, pk: &str) -> std::io::Result<String>;
    async fn delete_pk(&self, namespace: &str, pk: &str) -> std::io::Result<()>;

    // entry api
    async fn save_entry(&self, key: &str, content: &str) -> std::io::Result<()>;
    async fn get_single_entry(&self, key: &str) -> std::io::Result<String>;
    async fn delete_entry(&self, key: &str) -> std::io::Result<()>;

    // namespace
    async fn save_into_namespace(&self, namespace: &str, content: &str) -> std::io::Result<()>;
    async fn get_namespace_summary(&self) -> Option<Vec<String>>;
    async fn get_namespace_details(&self) -> std::io::Result<HashMap<String, WgNamespace>>;
    async fn get_namespace(&self, namespace: &str) -> std::io::Result<WgNamespace>;
    async fn delete_namespace(&self, namespace: &str) -> std::io::Result<DeleteResponse>;
    async fn delete_all_users_with_namespace(&self, namespace: &str) -> std::io::Result<()>;
    async fn get_all_users_with_namespace(
        &self,
        namespace: &str,
    ) -> std::io::Result<HashMap<String, WgUser>>;
}

#[async_trait]
impl EtcdApiHander for Client {
    async fn save_into_namespace(&self, namespace: &str, content: &str) -> std::io::Result<()> {
        let key = generate_namespace_key(namespace);
        // etcd-rs put expects a tuple (key, value)
        let result = self.put((key, content)).await;

        result.map_or_else(
            |e| Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
            |_| Ok(()),
        )
    }

    async fn save_user(&self, namespace: &str, id: &str, content: &str) -> std::io::Result<()> {
        self.save_entry(&generate_user_key(namespace, id), content).await
    }

    async fn save_pk(&self, namespace: &str, pk: &str, content: &str) -> std::io::Result<()> {
        self.save_entry(&generate_pk_to_user_id_key(namespace, pk), content).await
    }

    async fn save_entry(&self, key: &str, content: &str) -> std::io::Result<()> {
        // etcd-rs put expects a tuple (key, value)
        let result = self.put((key, content)).await;

        result.map_or_else(
            |e| Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
            |_| Ok(()),
        )
    }

    async fn get_namespace_summary(&self) -> Option<Vec<String>> {
        let hostname = get_hostname().unwrap_or_else(|_| "localhost".to_string());
        let prefix = format!("/wg/{}/namespace/configuration", hostname);
        let prefix_end = format!("/wg/{}/namespace/configuration{}", hostname, '\u{0}');
        
        // get_range expects Vec<u8> parameters
        let values = self.get_range(prefix.as_bytes(), prefix_end.as_bytes()).await;
        
        values
            .map(|value| {
                value
                    .kvs
                    .into_iter()
                    .filter_map(|kv| {
                        String::from_utf8(kv.key).ok()
                            .and_then(|key_str| key_str.split('/').last().map(|s| s.to_string()))
                    })
                    .collect::<Vec<_>>()
            })
            .ok()
    }

    async fn get_namespace(&self, namespace: &str) -> std::io::Result<WgNamespace> {
        let key = generate_namespace_key(namespace);
        // get_range expects Vec<u8> parameters
        let ret = self.get_range(key.as_bytes(), key.as_bytes()).await;

        match ret {
            Ok(ns_config) => {
                debug!("Got response namespace from etcd database: {}", namespace);

                if ns_config.kvs.is_empty() {
                    debug!("No namespace found in etcd database: {}", namespace);
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "namespace not found",
                    ))
                } else if ns_config.kvs.len() != 1 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "multiple namespaces found",
                    ))
                } else {
                    let value_str = String::from_utf8(ns_config.kvs[0].value.clone())
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
                    
                    let namespace_conf = serde_json::from_str::<models::WgNamespace>(&value_str);

                    namespace_conf.map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })
                }
            }
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )),
        }
    }

    async fn get_user(&self, namespace: &str, id: &str) -> std::io::Result<WgUser> {
        let key = generate_user_key(namespace, id);
        // get_range expects Vec<u8> parameters
        let ret = self.get_range(key.as_bytes(), key.as_bytes()).await;

        match ret {
            Ok(user_config) => {
                debug!("Got response from etcd database: namespace {}, id: {}", namespace, id);

                if user_config.kvs.is_empty() {
                    debug!("Cannot find user in database: {}/{}", namespace, id);
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no user with id found",
                    ))
                } else if user_config.kvs.len() != 1 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "multiple users found",
                    ))
                } else {
                    let value_str = String::from_utf8(user_config.kvs[0].value.clone())
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
                    
                    let user_conf = serde_json::from_str::<models::WgUser>(&value_str);

                    user_conf.map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })
                }
            }
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )),
        }
    }

    async fn get_pk(&self, namespace: &str, pk: &str) -> std::io::Result<String> {
        self.get_single_entry(&generate_pk_to_user_id_key(namespace, pk)).await
    }

    async fn get_single_entry(&self, key: &str) -> std::io::Result<String> {
        // get_range expects Vec<u8> parameters
        let ret = self.get_range(key.as_bytes(), key.as_bytes()).await;

        match ret {
            Ok(range_resp) => {
                debug!("Got response from etcd database: key: {}", key);

                if range_resp.kvs.is_empty() {
                    debug!("Cannot find entry in etcd with key {}", key);
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no entry with key found",
                    ))
                } else if range_resp.kvs.len() != 1 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "multiple entries found",
                    ))
                } else {
                    String::from_utf8(range_resp.kvs[0].value.clone())
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
                }
            }
            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            )),
        }
    }

    async fn delete_namespace(&self, namespace: &str) -> std::io::Result<DeleteResponse> {
        let key = generate_namespace_key(namespace);
        // delete expects string, so dereference the String
        let delete = self.delete(key.as_str()).await;
        
        delete.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })
    }

    async fn delete_user(&self, namespace: &str, id: &str) -> std::io::Result<()> {
        self.delete_entry(&generate_user_key(namespace, id)).await
    }

    async fn delete_pk(&self, namespace: &str, pk: &str) -> std::io::Result<()> {
        self.delete_entry(&generate_pk_to_user_id_key(namespace, pk)).await
    }

    async fn delete_entry(&self, key: &str) -> std::io::Result<()> {
        // delete expects &str
        let delete = self.delete(key).await;
        
        delete.map_or_else(
            |e| Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
            |_| Ok(()),
        )
    }

    async fn get_namespace_details(&self) -> std::io::Result<HashMap<String, WgNamespace>> {
        debug!("Trying to read all namespace configurations...");
        let mut hm = HashMap::new();

        let hostname = get_hostname().unwrap_or_else(|_| "localhost".to_string());
        let prefix = format!("/wg/{}/namespace/configuration", hostname);
        let prefix_end = format!("/wg/{}/namespace/configuration{}", hostname, '\u{0}');

        // get_range expects Vec<u8> parameters
        let values = self.get_range(prefix.as_bytes(), prefix_end.as_bytes()).await;
        
        let kvs = values.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })?.kvs;

        if kvs.is_empty() {
            debug!("No namespace found...");
        }

        for kv in kvs {
            let key_str = String::from_utf8(kv.key).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?;
            
            let value_str = String::from_utf8(kv.value).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?;
            
            let namespace = key_str.split('/').last().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Cannot get namespace for {}", key_str),
                )
            })?;

            let wg = serde_json::from_str::<WgNamespace>(&value_str).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Cannot deserialize WgNamespace: {}", e),
                )
            })?;

            hm.insert(namespace.to_string(), wg);
        }
        Ok(hm)
    }

    async fn delete_all_users_with_namespace(&self, namespace: &str) -> std::io::Result<()> {
        let prefix = generate_all_users_key_with_namespace(namespace);
        let prefix_end = format!("{}{}", prefix, '\u{0}');
        
        // First get all keys to delete - get_range expects Vec<u8> parameters
        let range_resp = self.get_range(prefix.as_bytes(), prefix_end.as_bytes()).await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        
        // Delete each key individually - convert Vec<u8> to String first
        for kv in range_resp.kvs {
            let key_str = String::from_utf8(kv.key).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?;
            let _ = self.delete(key_str.as_str()).await; // Ignore individual delete errors
        }
        
        Ok(())
    }

    async fn get_all_users_with_namespace(
        &self,
        namespace: &str,
    ) -> std::io::Result<HashMap<String, WgUser>> {
        debug!("Trying to read all users with namespace {}...", namespace);
        let mut hm = HashMap::new();

        let prefix = generate_all_users_key_with_namespace(namespace);
        let prefix_end = format!("{}{}", prefix, '\u{0}');

        // get_range expects Vec<u8> parameters
        let all_users_resp = self.get_range(prefix.as_bytes(), prefix_end.as_bytes()).await;

        let all_users_kvs = all_users_resp.map_err(|e| {
            debug!("Errors when reading all users for {}", namespace);
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })?.kvs;

        if all_users_kvs.is_empty() {
            info!("No wg user found for namespace {}", namespace);
        }

        for user_kv in all_users_kvs {
            let key_str = String::from_utf8(user_kv.key.clone()).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?;
            
            let value_str = String::from_utf8(user_kv.value).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            })?;

            let wg_user = serde_json::from_str::<WgUser>(&value_str);
            if let Err(e) = wg_user {
                warn!(
                    "Cannot deserialize entry at {} for user {}, reason: {}",
                    key_str, value_str, e,
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