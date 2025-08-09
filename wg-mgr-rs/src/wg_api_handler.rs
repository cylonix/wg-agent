// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

use crate::wg_conf_store_srv::EtcdApiHander;
use crate::wg_network_conf_srv::{ NetApiHandler, NetworkConfClient };
use async_trait::async_trait;
use etcd_rs::Client;
use log::{ debug, error, info, warn };
use std::io::{ Error, ErrorKind, Result };
use std::sync::Arc;
use tokio::sync::Mutex;
use wg_api::models::{ self, * };
use wg_rs::collect_wireguard_info;
use wg_rs::{ ConvertToBase58, WgPeer };

fn extract_table_id_from_namespace(namespace: &str) -> Result<(&str, u32)> {
    let table_id = namespace.split('_').nth(1);
    let vrf_name = namespace.split('_').nth(0);

    if let Some(table_id) = table_id {
        let table_id = table_id
            .parse::<u32>()
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Cannot parse table id from namespace {}: {}", namespace, e)
                )
            })?;
        if let Some(vrf_name) = vrf_name {
            Ok((vrf_name, table_id))
        } else {
            Err(
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Cannot parse vrf name from namespace {}", namespace)
                )
            )
        }
    } else {
        Err(
            Error::new(
                ErrorKind::InvalidInput,
                format!("Cannot parse table id from namespace {}", namespace)
            )
        )
    }
}
#[async_trait]
pub trait ApiHandler {
    async fn create_namespace_handler(
        &self,
        wg_param: &WgNamespace,
        skip_store_into_db: bool,
        skip_if_exist_in_db: bool,
        reuse_wg: bool
    ) -> Result<()>;
    async fn delete_namespace_handler(&self, namespace: &WgNamespace) -> Result<()>;
    async fn get_namespace_stats(&self, namespace: &str) -> Result<models::InterfaceStats>;
    async fn create_wireguard_user(
        &self,
        wg_user: &WgUser,
        skip_store_into_db: bool,
        skip_if_exist_in_db: bool
    ) -> Result<()>;
    async fn delete_wireguard_user(&self, wg_user: &WgUser) -> Result<()>;

    fn peer_to_wg_user_stats(
        &self,
        peer: &WgPeer,
        namespace: &str,
        id: &str,
        pubkey: &str
    ) -> models::WgUserStats;
    async fn get_user_statistics(&self, wg_user: &WgUser) -> Result<models::WgUserStats>;
    async fn get_all_user_stats(&self, namespace: &str) -> Result<Vec<models::WgUserStats>>;
    async fn get_namespace_users(&self, namespace: &str) -> Result<Vec<models::WgUser>>;
    async fn remove_peers_not_in_db(&self, namespace: &str) -> Result<()>;
}

#[async_trait]
impl<T> ApiHandler for T where T: AsRef<Client> + AsRef<Arc<Mutex<NetworkConfClient>>> + Send + Sync {
    async fn delete_namespace_handler(&self, namespace: &WgNamespace) -> Result<()> {
        let namespace_name = namespace.name.as_str();
        let wg_interface_name = format!("wg_{}", namespace_name);
        let vrf_interface_name = format!("vrf_{}", namespace_name);

        info!("Deleting namespace {}", namespace_name);
        let _ = self.delete_wg_interface(wg_interface_name.as_str()).await.inspect_err(|e| {
            warn!("Cannot delete wg interface {}: {}", namespace_name, e.to_string());
        });

        if let Some(vxlan) = namespace.vxlan.as_ref() {
            let _ = self
                .delete_vxlan_interface(format!("vxlan_{}", vxlan.vid).as_str()).await
                .inspect_err(|e| {
                    warn!("Cannot delete vxlan interface vxlan_{}: {}", vxlan.vid, e.to_string());
                });

            if let Some(ip) = namespace.ip.as_ref() {
                if let Some(prefix) = namespace.prefix {
                    let network = format!("{}/{}", ip, prefix);
                    let _ = self
                        .delete_iptable_fwmark_entry(
                            wg_interface_name.as_str(),
                            network.as_str(),
                            vxlan.vid as u32
                        ).await
                        .inspect_err(|e| {
                            warn!(
                                "Cannot delete fwmark entry for {}: {}",
                                namespace_name,
                                e.to_string()
                            );
                        });

                    let _ = self
                        .add_del_ip_rule(
                            false,
                            Some(vxlan.vid as u32),
                            vxlan.vid as u32,
                            100 as u32,
                            None
                        ).await
                        .inspect_err(|e| {
                            warn!(
                                "Cannot delete ip rule entry for {}: {}",
                                namespace_name,
                                e.to_string()
                            );
                        });
                    let _ = self
                        .flush_route_table(vxlan.vid as u32).await
                        .inspect_err(|e| {
                            warn!(
                                "Cannot flush route table for {}: {}",
                                namespace_name,
                                e.to_string()
                            );
                        });
                }
            }
        }

        if let Some(ip) = namespace.ip.as_ref() {
            if let Some(prefix) = namespace.prefix {
                let network = format!("{}/{}", ip, prefix);
                let _ = self
                    .delete_iptable_filter_rules(
                        vrf_interface_name.as_str(),
                        wg_interface_name.as_str(),
                        ip,
                        network.as_str()
                    ).await
                    .inspect_err(|e| {
                        warn!("Cannot delete ip table filter rule {}: {}", network, e.to_string());
                    });
            }
        }

        let _ = self.delete_vrf_interface(vrf_interface_name.as_str()).await.inspect_err(|e| {
            warn!("Cannot delete vrf interface vrf_{}: {}", namespace_name, e.to_string());
        });

        let etcd_client: &Client = self.as_ref();
        etcd_client.delete_namespace(namespace_name).await.inspect_err(|e| {
            warn!("Cannot delete namespace {}: {}", namespace_name, e.to_string());
        })?;
        etcd_client.delete_all_users_with_namespace(namespace_name).await.inspect_err(|e| {
            warn!("Cannot delete all users for {}: {}", namespace_name, e.to_string());
        })?;
        info!("Namespace {} deleted", namespace_name);
        Ok(())
    }

    /// create_namespace_handler creates a namespace in etcd and its
    /// wg interface and vxlan interface
    async fn create_namespace_handler(
        &self,
        namespace: &WgNamespace,
        skip_store_into_db: bool,
        skip_if_exist_in_db: bool,
        reuse_wg: bool
    ) -> Result<()> {
        info!("Creating namespace {}", namespace.name);

        // Guard code, checking the parameter is valid
        if let None = namespace.ip {
            return Err(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "IP address is missing in namespace parameter"
                )
            );
        }
        if let None = namespace.prefix {
            return Err(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "IP prefix is missing in namespace parameter"
                )
            );
        }
        if let None = namespace.port {
            return Err(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "Port is missing in namespace parameter"
                )
            );
        }

        // Namespace name has two parts. The 1st part is original namespace,
        // the 2nd part is the vrf table ID. They are joined with '_'.
        let table_id = extract_table_id_from_namespace(namespace.name.as_str()).map_err(|e| {
            error!("Cannot extract table id from namespace {}: {}", namespace.name, e.to_string());
            e
        })?.1;

        let namespace_name = namespace.name.as_str();
        let wg_interface_name = format!("wg_{}", namespace.name);
        let vrf_interface_name = format!("vrf_{}", namespace.name);

        // Search it in db
        let etcd_handler: &Client = self.as_ref();
        let mut ns = namespace.clone();
        if skip_if_exist_in_db {
            match etcd_handler.get_namespace(namespace_name).await {
                Ok(old) => {
                    // Double check if there is a change in config.
                    // We can do deepeuqal or just compare the json string
                    // Copy the private key to namespace
                    if ns.private_key.is_none() && old.private_key.is_some() {
                        ns.private_key = old.private_key.clone();
                    }
                    let new_json = serde_json::to_string(&ns).unwrap();
                    let old_json = serde_json::to_string(&old).unwrap();
                    if new_json.eq(&old_json) {
                        debug!(
                            "Namespace {} exists with the same config. Skip setting it up again.",
                            ns.name
                        );
                        return Ok(());
                    } else {
                        debug!(
                            "Namespace {} exists but config changed. Need to set it up again.",
                            ns.name
                        );
                        debug!("New config: {}", new_json);
                        debug!("Old config: {}", old_json);
                        // Force to create a new wg intf with the new setting
                        // Note private key may change.
                        self.delete_wg_interface(wg_interface_name.as_str()).await?;
                    }
                }
                Err(_) => {
                    debug!("Namespace {} does not exist", ns.name);
                }
            };
        }

        let vrf_index = self
            .create_vrf_interface(vrf_interface_name.as_str(), table_id).await
            .inspect_err(|e| {
                error!("Cannot create vrf interface for {}: {}", ns.name, e.to_string());
            })?;

        let wg_interface_ip = namespace.ip.as_ref().unwrap().as_str();
        let wg_interface_prefix = namespace.prefix.unwrap() as u8;
        let ip_with_prefix = std::format!("{}/{}", wg_interface_ip, wg_interface_prefix);

        // If we are restoring from DB or repeating creation, check if wg
        // interface already exists so that we don't re-generate the key.
        let mut create_wg = true;
        let mut private_key = ns.private_key.as_ref().map_or_else(
            || {
                debug!("{} has no private key, need to create a new one", ns.name);
                None
            },
            |k| {
                debug!("{} has private key, reusing it", ns.name);
                Some(k.as_str())
            }
        );
        let mut sk: String;
        if reuse_wg {
            match collect_wireguard_info(wg_interface_name.as_str()) {
                Ok(wd) => {
                    let mut delete_wg = false;
                    sk = wd.get_base64_from_sk().inspect(|k| {
                        if let Some(sk) = private_key {
                            if sk.eq(k.as_str()) {
                                debug!("{} wg interface private key matches config", ns.name);
                            } else {
                                debug!(
                                    "{} wg interface private key does not match config",
                                    ns.name
                                );
                                delete_wg = true;
                            }
                        }
                    })?;
                    private_key = Some(sk.as_str());

                    match (wd.listen_port, ns.port) {
                        (Some(p), Some(new_p)) => {
                            if (new_p as u16) != p {
                                debug!("{} port mis-match with config", ns.name);
                                delete_wg = true;
                            }
                        }
                        _ => {
                            debug!("{} port mis-match with config", ns.name);
                            delete_wg = true;
                        }
                    }

                    if delete_wg {
                        self.delete_wg_interface(wg_interface_name.as_str()).await?;
                    } else {
                        create_wg = false;
                    }
                }
                Err(_) => {
                    debug!("{} does not exist. Need new one", wg_interface_name);
                }
            };
        }
        if create_wg {
            debug!("{} create a new wg interface", ns.name);
            let ret = self.create_wg_interface(
                wg_interface_name.as_str(),
                ip_with_prefix.as_str(),
                ns.port.unwrap() as u16,
                private_key
            ).await;
            if let Err(e) = ret {
                if e.kind() != ErrorKind::AlreadyExists {
                    error!("Cannot create wg interface for {}: {}", ns.name, e.to_string());
                    return Err(e);
                }
                info!("{} new wg interface exists", ns.name);
            } else {
                sk = collect_wireguard_info(wg_interface_name.as_str()).map_or_else(
                    |e| {
                        error!("Cannot collect wireguard info for {}", ns.name);
                        Err(e)
                    },
                    |wd| wd.get_base64_from_sk()
                )?;
                debug!("{} new wg interface sk: {:?}...", ns.name, &sk[..10]);
                private_key = Some(sk.as_str());
            }
        } else {
            debug!("{} skip creating a new wg interface", ns.name);
        }

        // TODO: move private key to a 400 mod restricted file
        if !skip_store_into_db || create_wg {
            ns.private_key = Some(private_key.unwrap().to_string());
            let namespace_json = serde_json::to_string(&ns).unwrap();
            let etcd_handler: &Client = self.as_ref();
            etcd_handler
                .save_into_namespace(namespace_name, namespace_json.as_str()).await
                .inspect_err(|e| {
                    error!("Cannot save namespace {} into store: {}", ns.name, e.to_string());
                })?;
        }

        let wg_intf_index = self
            .get_interface_index(wg_interface_name.as_str()).await
            .inspect_err(|e| {
                error!(
                    "Cannot get wg interface index for {}: {}",
                    wg_interface_name,
                    e.to_string()
                );
            })?;

        self.move_interface_to_vrf(wg_intf_index, vrf_index).await.inspect_err(|e| {
            error!("Cannot put wg interface into vrf {}: {}", wg_interface_name, e.to_string());
        })?;

        // If vxlan is configured, the vxlan interface will direct all upstream
        // traffic to the vxlan tunnel interface. This is to support multiple
        // networks routing via the VPP at the end of the vxlan tunnel.
        if let Some(vxlan) = ns.vxlan.as_ref() {
            // Check vxlan underlay route
            if vxlan.underlay_if == "" {
                warn!("configuration underlay is nil");
                let err_type = ErrorKind::InvalidInput;
                let err_msg = "underlay interface is nil";
                return Err(std::io::Error::new(err_type, err_msg));
            }
            let vxlan_interface_name = format!("vxlan_{}", vxlan.vid);

            self
                .create_vxlan_interface(
                    vxlan.ip.as_str(),
                    vxlan.vid as u32,
                    vxlan.remote.as_str(),
                    vxlan.dstport as u16
                ).await
                .map_or_else(
                    |e| {
                        if e.kind() != ErrorKind::AlreadyExists {
                            error!(
                                "Cannot create vxlan interface for {}: {}",
                                ns.name,
                                e.to_string()
                            );
                            Err(e)
                        } else {
                            info!("Vxlan interface for {} already exists", ns.name);
                            Ok(())
                        }
                    },
                    |_| {
                        info!("Created vxlan interface for {} with vid {}", ns.name, vxlan.vid);
                        Ok(())
                    }
                )?;
            let vxlan_if_index = self
                .get_interface_index(vxlan_interface_name.as_str()).await
                .inspect_err(|e| {
                    error!("Cannot get vxlan interface index for {}: {}", ns.name, e.to_string());
                })?;

            self.move_interface_to_vrf(vxlan_if_index, vrf_index).await.inspect_err(|e| {
                error!("Cannot put vxlan interface into vrf {}: {}", ns.name, e.to_string());
            })?;

            let ip = format!("{}/{}", wg_interface_ip, wg_interface_prefix);
            self
                .create_iptable_fwmark_entry(
                    wg_interface_name.as_str(),
                    ip.as_str(),
                    vxlan.vid as u32
                ).await
                .map_or_else(
                    |e| {
                        if e.kind() != ErrorKind::AlreadyExists {
                            error!(
                                "Cannot create iptables fwmark entry for {}: {}",
                                ns.name,
                                e.to_string()
                            );
                            Err(e)
                        } else {
                            info!("Iptables fwmark entry for {} already exists", ns.name);
                            Ok(())
                        }
                    },
                    |_| {
                        info!(
                            "Created iptables fwmark entry for {} with vid {}",
                            ns.name,
                            vxlan.vid
                        );
                        Ok(())
                    }
                )?;

            // Create the ip rules to lookup a vxlan vid as table-id's routing
            // table. Note that this is different than the vrf routing table
            // which is used for downstream traffic.
            self
                .add_del_ip_rule(
                    true,
                    Some(vxlan.vid as u32),
                    vxlan.vid as u32,
                    100 as u32,
                    None
                ).await
                .map_or_else(
                    |e| {
                        if e.kind() != ErrorKind::AlreadyExists {
                            error!("Cannot create ip rule for {}: {}", ns.name, e.to_string());
                            Err(e)
                        } else {
                            info!("IP rule for {} already exists", ns.name);
                            Ok(())
                        }
                    },
                    |_| {
                        info!("Created ip rule for {} with vid {}", ns.name, vxlan.vid);
                        Ok(())
                    }
                )?;

            // Add route to make all upstream traffic forwarded to the vxlan tunnel
            self
                .create_route_entry(
                    "0.0.0.0",
                    0,
                    if vxlan.gw == "" {
                        None
                    } else {
                        Some(vxlan.gw.as_str())
                    },
                    Some(vxlan_interface_name.as_str()),
                    Some(vxlan.vid as u32)
                ).await
                .map_or_else(
                    |e| {
                        if e.kind() != ErrorKind::AlreadyExists {
                            error!("Cannot create route entry for {}: {}", ns.name, e.to_string());
                            Err(e)
                        } else {
                            info!("Route entry for {} already exists", ns.name);
                            Ok(())
                        }
                    },
                    |_| {
                        info!("Created route entry for {} with vid {}", ns.name, vxlan.vid);
                        Ok(())
                    }
                )?;

            self
                .create_route_entry(
                    vxlan.remote.as_str(),
                    32,
                    None,
                    Some(vxlan.underlay_if.as_str()),
                    Some(vxlan.vid as u32)
                ).await
                .map_or_else(
                    |e| {
                        if e.kind() != ErrorKind::AlreadyExists {
                            error!(
                                "Cannot create underlay route entry for {}: {}",
                                ns.name,
                                e.to_string()
                            );
                            Err(e)
                        } else {
                            info!("Underlay route entry for {} already exists", ns.name);
                            Ok(())
                        }
                    },
                    |_| {
                        info!(
                            "Created underlay route entry for {} with vid {}",
                            ns.name,
                            vxlan.vid
                        );
                        Ok(())
                    }
                )?;
        }

        // create the ip filter tables rule to allow traffic to pass
        let network = std::format!("{}/{}", wg_interface_ip, wg_interface_prefix);
        self
            .create_iptable_filter_rules(
                vrf_interface_name.as_str(),
                wg_interface_name.as_str(),
                wg_interface_ip,
                network.as_str()
            ).await
            .map_or_else(
                |e| {
                    if e.kind() != ErrorKind::AlreadyExists {
                        error!("Cannot create filter rules for {}: {}", ns.name, e.to_string());
                        Err(e)
                    } else {
                        info!("Filter rules for {} already exists", ns.name);
                        Ok(())
                    }
                },
                |_| {
                    info!("Created filter rules for {}", ns.name);
                    Ok(())
                }
            )?;

        info!("Namespace {} created successfully", ns.name);
        Ok(())
    }
    async fn get_namespace_stats(&self, namespace: &str) -> Result<models::InterfaceStats> {
        let stats = self.get_interface_stats(namespace).await?;

        let stats_ret = models::InterfaceStats {
            name: Some(namespace.to_string()),
            rx_packets: stats.rx_packets as i64,
            tx_packets: stats.tx_packets as i64,
            rx_bytes: stats.rx_bytes as i64,
            tx_bytes: stats.tx_bytes as i64,
            rx_errors: stats.rx_errors as i64,
            tx_errors: stats.tx_errors as i64,
            rx_dropped: stats.rx_dropped as i64,
            tx_dropped: stats.tx_dropped as i64,
            multicast: stats.multicast as i64,
            collisions: stats.collisions as i64,
            rx_length_errors: stats.rx_length_errors as i64,
            rx_over_errors: stats.rx_over_errors as i64,
            rx_crc_errors: stats.rx_crc_errors as i64,
            rx_frame_errors: stats.rx_frame_errors as i64,
            rx_fifo_errors: stats.rx_frame_errors as i64,
            rx_missed_errors: stats.rx_missed_errors as i64,
            tx_aborted_errors: stats.tx_aborted_errors as i64,
            tx_carrier_errors: stats.tx_carrier_errors as i64,
            tx_fifo_errors: stats.tx_fifo_errors as i64,
            tx_heartbeat_errors: stats.tx_heartbeat_errors as i64,
            tx_window_errors: stats.tx_window_errors as i64,
            rx_compressed: stats.rx_compressed as i64,
            tx_compressed: stats.tx_compressed as i64,
            rx_nohandler: stats.rx_nohandler as i64,
        };

        Ok(stats_ret)
    }
    async fn create_wireguard_user(
        &self,
        wg_user: &WgUser,
        skip_store_into_db: bool,
        skip_if_exist_in_db: bool
    ) -> Result<()> {
        let etcd_handler: &Client = self.as_ref();

        // Check if there is an existing pk for this wg user.
        if
            let Ok(wg_user_in_db) = etcd_handler.get_user(
                wg_user.namespace.as_str(),
                wg_user.id.as_str()
            ).await
        {
            let namespace = wg_user_in_db.namespace.as_str();
            let pk = wg_user_in_db.pubkey.as_str();
            if pk.eq(wg_user.pubkey.as_str()) {
                if skip_if_exist_in_db {
                    debug!(
                        "User [{}/{}/{}] has been created, skip recreating it",
                        namespace,
                        wg_user.id,
                        pk
                    );
                    return Ok(());
                }
            } else {
                info!("removing peer with older public key: {}", pk);
                etcd_handler.delete_pk(namespace, pk).await.inspect_err(|e| {
                    warn!(
                        "Cannot delete pk {} in db for user {}: {}",
                        pk,
                        wg_user.id,
                        e.to_string()
                    );
                })?;
                self
                    .delete_wg_user(format!("wg_{}", wg_user.namespace).as_str(), pk).await
                    .inspect_err(|e| {
                        warn!(
                            "Cannot delete wg user {} with pk {}: {}",
                            wg_user.id,
                            pk,
                            e.to_string()
                        );
                    })?;
                info!("User [{}/{}/{}] has been deleted.", namespace, wg_user.id, pk);
            }
        }

        self.create_wireguard_peer(
            format!("wg_{}", wg_user.namespace).as_str(),
            wg_user.pubkey.as_str(),
            wg_user.allowed_ips
                .as_ref()
                .unwrap()
                .iter()
                .map(|ip| ip.as_str())
                .collect()
        ).await?;
        info!("User [{}/{}/{}] has been created.", wg_user.name, wg_user.id, wg_user.pubkey);

        let content_json = serde_json
            ::to_string(wg_user)
            .map_err(|e| { std::io::Error::new(ErrorKind::InvalidData, e.to_string()) })?;

        if !skip_store_into_db {
            etcd_handler.save_user(
                wg_user.namespace.as_str(),
                wg_user.id.as_str(),
                content_json.as_str()
            ).await?;
            etcd_handler.save_pk(
                wg_user.namespace.as_str(),
                wg_user.pubkey.as_str(),
                wg_user.id.as_str()
            ).await
        } else {
            Ok(())
        }
    }
    async fn delete_wireguard_user(&self, wg_user: &WgUser) -> Result<()> {
        let etcd_handler: &Client = self.as_ref();
        let user = etcd_handler.get_user(wg_user.namespace.as_str(), wg_user.id.as_str()).await?;

        self.delete_wg_user(format!("wg_{}", wg_user.namespace).as_str(), &user.pubkey).await?;
        info!("User [{}/{}/{}] has been deleted.", wg_user.namespace, wg_user.id, user.pubkey);

        etcd_handler.delete_user(wg_user.namespace.as_str(), user.id.as_str()).await?;
        etcd_handler.delete_pk(wg_user.namespace.as_str(), user.pubkey.as_str()).await
    }

    fn peer_to_wg_user_stats(
        &self,
        peer: &WgPeer,
        namespace: &str,
        id: &str,
        pubkey: &str
    ) -> models::WgUserStats {
        let last_seen = peer.last_handshake_time.map_or(0, |a| a);
        debug!("last seen at {}", last_seen);

        models::WgUserStats {
            name: "".to_string(),
            device_id: "".to_string(),
            id: id.to_string(),
            pubkey: pubkey.to_string(),
            tx_bytes: peer.tx_bytes.map_or(0, |a| a as i64),
            rx_bytes: peer.rx_bytes.map_or(0, |a| a as i64),
            namespace: namespace.to_string(),
            last_handshake_time: last_seen,
        }
    }
    async fn get_user_statistics(&self, wg_user: &WgUser) -> Result<models::WgUserStats> {
        let namespace = wg_user.namespace.as_str();
        debug!(
            "get user stats for {}/{}, pubey {}",
            wg_user.namespace,
            wg_user.name,
            wg_user.pubkey
        );

        let id = wg_user.id.as_str();
        let pubkey = wg_user.pubkey.as_str();
        let user_pk = "pk:".to_string() + wg_user.pubkey.as_str();
        let ret = self.get_all_users(namespace).await.and_then(|peers| {
            let a = peers
                .iter()
                .find(|&peer| {
                    let ret = peer.public_key.as_ref().and_then(|_pk| {
                        let ret = peer.get_base64_from_pk().map_or(false, |pk| pk == user_pk);
                        Some(ret)
                    });
                    ret.map_or(false, |s| s)
                })
                .and_then(|peer| {
                    // Found it
                    Some(self.peer_to_wg_user_stats(peer, namespace, id, pubkey))
                });
            match a {
                None => {
                    error!("get user stats: user {}/{} not found", wg_user.name, pubkey);
                    Err(Error::new(ErrorKind::Other, "User not found"))
                }
                Some(a) => {
                    info!("get user stats: user {}/{} found", wg_user.name, pubkey);
                    Ok(a)
                }
            }
        });
        ret
    }
    async fn get_all_user_stats(&self, namespace: &str) -> Result<Vec<models::WgUserStats>> {
        debug!("get all user stats for {}", namespace);

        let peers = self.get_all_users(namespace).await?;
        let mut ret_vec = Vec::new();

        for peer in &peers {
            debug!("parsing each peer...");
            let _ = peer.get_base64_from_pk().and_then(|pubkey| {
                let pk = pubkey.trim_start_matches("pk:");
                let stats = self.peer_to_wg_user_stats(peer, namespace, "", pk);
                // Only push those with non-zero stats
                if stats.rx_bytes != 0 {
                    (&mut ret_vec).push(stats);
                }
                Ok(())
            });
        }

        Ok(ret_vec)
    }
    async fn get_namespace_users(&self, namespace: &str) -> Result<Vec<models::WgUser>> {
        let mut wg_users = Vec::<models::WgUser>::new();
        let wgd = collect_wireguard_info(namespace)?;
        let etcd_handler: &Client = self.as_ref();
        match wgd.get_users() {
            Some(peers) => {
                for peer in peers.into_iter() {
                    let pubkey = peer.get_base64_from_pk()?;
                    let pk = pubkey.trim_start_matches("pk:").to_string();
                    let user_id = etcd_handler.get_pk(namespace, pk.as_str()).await?;
                    let user = etcd_handler.get_user(namespace, user_id.as_str()).await?;
                    wg_users.push(user.clone());
                }
            }
            None => {}
        }
        Ok(wg_users)
    }
    async fn remove_peers_not_in_db(&self, namespace: &str) -> Result<()> {
        let wgd = collect_wireguard_info(namespace)?;
        let etcd_handler: &Client = self.as_ref();
        match wgd.get_users() {
            Some(peers) => {
                for peer in peers.into_iter() {
                    let pubkey = peer.get_base64_from_pk()?;
                    let pk = pubkey.trim_start_matches("pk:").to_string();
                    // If pk has no user id mapping or user id's pk is not
                    // matching, then this entry is a stale one.
                    match etcd_handler.get_pk(namespace, pk.as_str()).await {
                        Err(_e) => {
                            warn!("removing peer {} that's not in db", pk);
                            let _ = self.delete_wg_user(&namespace.to_string(), &pk);
                        }
                        Ok(user_id) => {
                            let to_delete: bool;
                            let user = etcd_handler.get_user(namespace, user_id.as_str()).await;
                            match user {
                                Err(_e) => {
                                    to_delete = true;
                                }
                                Ok(u) => {
                                    to_delete = u.pubkey != pk;
                                }
                            }
                            if to_delete {
                                let _ = etcd_handler.delete_pk(namespace, pk.as_str()).await;
                                warn!("removing peer {} that's not in db", pk);
                                let _ = self.delete_wg_user(&namespace.to_string(), &pk);
                            }
                        }
                    }
                }
            }
            None => {}
        }
        Ok(())
    }
}
