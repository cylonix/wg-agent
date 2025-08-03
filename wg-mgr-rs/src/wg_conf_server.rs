// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

#![allow(unused_must_use)]
use crate::wg_api_handler::ApiHandler;
use crate::wg_conf_store_srv::EtcdApiHander;
use crate::wg_network_conf_srv::NetworkConfClient;
use etcd_rs::Client;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::string::String;
use std::sync::{Arc, Mutex};
use wg_api::models::*;
#[derive(Clone)]
pub struct ConfServer {
    etcd_client: Client,
    network_config_client: Arc<Mutex<NetworkConfClient>>,
}

impl ConfServer {
    pub fn new(etcd_client: Client, network_config_client: Arc<Mutex<NetworkConfClient>>) -> Self {
        debug!("Creating a configuration server object, with etcd client and linux networking utils enabled...");
        ConfServer {
            etcd_client: etcd_client,
            network_config_client: network_config_client,
        }
    }

    pub async fn serve_namespace_startup_config(
        &self,
        hm: &HashMap<String, WgNamespace>,
    ) -> std::io::Result<()> {
        for kv in hm {
            info!("Restore configuration for {}", kv.0);
            let create_ret = self.create_namespace_handler(kv.1, true, false, true).await;

            match create_ret {
                Err(e) => {
                    error!(
                        "Cannot retore configurations, reason: {}, restore it ",
                        e.to_string()
                    );

                    // Should we be deleting the name space?
                    // This will result in etcd to remove all the information.
                    // self.delete_namespace_handler(kv.1).await;
                    // Panic and wait for systemd to restart us instead.
                    panic!();
                    //Err(e)
                }
                Ok(_) => {
                    let namespace = kv.0.as_str();
                    info!(
                        "Successfully restore namespace configurations for {}, continue to restore users",
                        namespace,
                    );

                    let all_users_rsp = self
                        .etcd_client
                        .get_all_users_with_namespace(namespace)
                        .await;
                    if let Err(e) = all_users_rsp {
                        warn!(
                            "Cannot get users for namespace {}, reason:{}",
                            namespace,
                            e.to_string()
                        );
                        continue;
                    }

                    let all_users = all_users_rsp.unwrap();

                    // Remove the wg peer entris that are not in the db.
                    // TODO: check if this helps system resilency or actually
                    // causes problems due to race conditions.
                    let _ = self.remove_peers_not_in_db(namespace).await;

                    for key_user in &all_users {
                        // if a user has no valid id, it must be a legacy old
                        // entry that needs to be deleted.
                        let key = key_user.0;
                        let user = key_user.1;
                        if user.id.is_empty() {
                            warn!(
                                "stale entry for at {} for {}/{}/{}",
                                key, namespace, user.name, user.pubkey,
                            );
                            let _ = self.etcd_client.delete_entry(key.as_str()).await;
                            let _ = self
                                .etcd_client
                                .delete_pk(namespace, user.pubkey.as_str())
                                .await;
                            continue;
                        }

                        let ret = self.create_wireguard_user(user, true, false).await;
                        if let Err(e) = ret {
                            warn!(
                                "Cannot create wireguard user {}/{}, reason:{}",
                                namespace,
                                key,
                                e.to_string()
                            );
                            continue;
                        }

                        info!(
                            "created user {}/{}/{}/{}",
                            namespace, user.name, user.id, user.pubkey
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

impl AsRef<Arc<Mutex<NetworkConfClient>>> for ConfServer {
    fn as_ref(&self) -> &Arc<Mutex<NetworkConfClient>> {
        &self.network_config_client
    }
}

impl AsRef<Client> for ConfServer {
    fn as_ref(&self) -> &Client {
        &self.etcd_client
    }
}

pub async fn create(etcd_client: Client, network_config_client: Arc<Mutex<NetworkConfClient>>) {
    debug!("Creating a startup configuration service...");
    let server = ConfServer::new(etcd_client, network_config_client);
    let ns = server.etcd_client.get_namespace_details().await;

    if let Err(e) = ns {
        warn!(
            "Cannot read all the namespace details from etcd database, reason:{}",
            e.to_string()
        );
        return;
    } else {
        let ns = ns.unwrap();
        if ns.len() == 0 {
            info!("No namespace found...");
        }
        server.serve_namespace_startup_config(&ns).await;
    };
}
