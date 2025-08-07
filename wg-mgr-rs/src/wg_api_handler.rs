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
    let table_id = namespace.split('_').nth(1); // Get the table id from the namespace
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
    async fn get_namespace_stats(&self, namespace: String) -> Result<models::InterfaceStats>;
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
        pubkey: String
    ) -> models::WgUserStats;
    async fn get_user_statistics(&self, wg_user: &WgUser) -> Result<models::WgUserStats>;
    async fn get_all_user_stats(&self, namespace: &str) -> Result<Vec<models::WgUserStats>>;
    async fn get_namespace_users(&self, namespace: &str) -> Result<Vec<models::WgUser>>;
    async fn remove_peers_not_in_db(&self, namespace: &str) -> Result<()>;
}

#[async_trait]
impl<T> ApiHandler for T where T: AsRef<Client> + AsRef<Arc<Mutex<NetworkConfClient>>> + Send + Sync {
    async fn delete_namespace_handler(&self, namespace: &WgNamespace) -> Result<()> {
        let namespace_name = namespace.name.to_owned();

        info!("Deleting namespace {}", namespace_name);
        let _ = self.delete_wg_interface(namespace_name.as_str()).await.map_err(|e| {
            warn!("Cannot delete wg interface {}: {}", namespace_name, e.to_string());
            // Ignore error as deletion is best effort
        });

        if let Some(vxlan) = namespace.vxlan.as_ref() {
            let _ = self
                .delete_vxlan_interface(format!("vxlan_{}", vxlan.vid).as_str()).await
                .map_err(|e| {
                    warn!("Cannot delete vxlan interface {}: {}", vxlan.vid, e.to_string());
                    // Ignore error as deletion is best effort
                });
        }

        let _ = self
            .delete_vrf_interface(format!("vrf_{}", namespace_name).as_str()).await
            .map_err(|e| {
                warn!("Cannot delete vrf interface {}: {}", namespace_name, e.to_string());
                // Ignore error as deletion is best effort
            });

        let etcd_client: &Client = self.as_ref();
        etcd_client.delete_namespace(namespace_name.as_str()).await.map_err(|e| {
            warn!("Cannot delete namespace {}: {}", namespace_name, e.to_string());
            e
        })?;
        etcd_client.delete_all_users_with_namespace(namespace_name.as_str()).await.map_err(|e| {
            warn!("Cannot delete all users with namespace {}: {}", namespace_name, e.to_string());
            e
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
        let wg_interface = namespace.name.to_owned();

        // If we are restoring from DB or repeating creation,
        // check if wg interface already exists so that
        // we don't change/re-generate the key.
        let mut create_wg = true;

        // Search it in db
        let etcd_handler: &Client = self.as_ref();
        let mut new = namespace.clone();
        if skip_if_exist_in_db {
            match etcd_handler.get_namespace(wg_interface.as_str()).await {
                Ok(old) => {
                    // Double check if there is a change in config.
                    // We can do deepeuqal or just compare the json string
                    // Copy the private key to namespace
                    new.private_key = old.private_key.clone();
                    let new_json = serde_json::to_string(&new).unwrap();
                    let old_json = serde_json::to_string(&old).unwrap();
                    if new_json.eq(&old_json) {
                        debug!("Namespace {} exists with the same config. Skip setting it up again.", wg_interface);
                        return Ok(());
                    } else {
                        debug!("Namespace {} exists but config changed. Need to set it up again.", wg_interface);
                        debug!("New config: {}", new_json);
                        debug!("Old config: {}", old_json);
                        //Force to create a new wg intf with the new setting
                        //Note private key may change.
                        match self.delete_wg_interface(new.name.as_str()) {
                            _ => (),
                        };
                    }
                }
                Err(_) => {
                    debug!("Namespace {} does not exist", wg_interface);
                }
            };
        }

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

        if let None = namespace.vxlan {
            return Err(
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "Vxlan is missing in namespace parameter"
                )
            );
        }

        let wg_interface_ip = namespace.ip.as_ref().unwrap().to_owned();
        let wg_interface_prefix = namespace.prefix.unwrap() as u8;
        let vxlan = namespace.vxlan.as_ref().unwrap().to_owned();
        let ip_with_prefix = std::format!("{}/{}", wg_interface_ip, wg_interface_prefix);

        let mut private_key = String::from("");
        if reuse_wg {
            match collect_wireguard_info(namespace.name.as_str()) {
                Ok(wd) => {
                    private_key = wd.get_base64_from_sk().map_or_else(
                        |_e| "None".to_string(),
                        |k| k
                    );
                    debug!("{} existing wg interface sk: {}", namespace.name, private_key);

                    // Double check if port and key matches.
                    let mut delete_wg = false;
                    let ns = new.clone();
                    match ns.private_key {
                        Some(k) => {
                            if !k.eq(&private_key) {
                                debug!("{} sk mis-match with config", ns.name);
                                delete_wg = true;
                            }
                        }
                        _ => (),
                    }
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
                        match self.delete_wg_interface(ns.name.as_str()) {
                            _ => (),
                        };
                    } else {
                        create_wg = false;
                    }
                }
                Err(_) => {
                    debug!("{} does not exist. Need new one", namespace.name);
                }
            };
        }

        if create_wg {
            debug!("{} create a new wg interface", namespace.name);
            let ret = self.create_wg_interface(
                namespace.name.as_str(),
                ip_with_prefix.as_str(),
                namespace.port,
                &new.private_key
            ).await;
            if let Err(e) = ret {
                if e.kind() != ErrorKind::AlreadyExists {
                    error!(
                        "Cannot create wg interface for namespace {}: {}",
                        namespace.name,
                        e.to_string()
                    );
                    return Err(e);
                }
                info!("{} new wg interface exists", namespace.name);
            } else {
                match collect_wireguard_info(namespace.name.as_str()) {
                    Ok(wd) => {
                        private_key = wd.get_base64_from_sk().map_or_else(
                            |_e| "None".to_string(),
                            |k| k
                        );
                        debug!("{} new wg interface sk: {}", namespace.name, private_key);
                    }
                    Err(e) => {
                        error!(
                            "Cannot collect wireguard info for namespace {}: {}",
                            namespace.name,
                            e.to_string()
                        );
                        // ignore the error for now.
                    }
                };
            }
        } else {
            debug!("{} skip creating a new wg interface", namespace.name);
        }

        // TODO: move private key to a 400 mod restricted file
        let force_store_in_db;
        if let None = namespace.private_key {
            debug!("{} has no private key", namespace.name);
            force_store_in_db = true;
        } else {
            let ns_sk = namespace.private_key.as_ref().unwrap().to_owned();
            if ns_sk.eq(&private_key) {
                force_store_in_db = false;
                debug!("{} has private key matches config", namespace.name);
            } else {
                force_store_in_db = true;
                warn!("{} has private key does not match config", namespace.name);
            }
        }

        let mut ret = Ok(());
        if !skip_store_into_db || force_store_in_db {
            let mut ns = namespace.clone();
            ns.private_key = Some(private_key.to_string());
            let namespace_json = serde_json::to_string(&ns).unwrap();
            let etcd_handler: &Client = self.as_ref();
            ret = etcd_handler.save_into_namespace(
                namespace.name.as_str(),
                namespace_json.as_str()
            ).await;
        }

        if let Err(e) = ret {
            warn!("Cannot save namespace{} into store: {}", namespace.name, e.to_string());
            return Err(e);
        }

        // Start to create the vxlan interface
        let ret = self.create_vxlan_interface(
            vxlan.ip.clone(),
            vxlan.vid as u32,
            vxlan.remote.clone(),
            vxlan.dstport as u16
        ).await;
        if let Err(e) = ret {
            if e.kind() != ErrorKind::AlreadyExists {
                error!(
                    "Cannot create vxlan interface for namespace {}: {}",
                    namespace.name,
                    e.to_string()
                );
                return Err(e);
            }
            info!(
                "Vxlan interface for namespace {} already exists, skipping creation",
                namespace.name
            );
        } else {
            info!(
                "Created vxlan interface for namespace {} with vid {}",
                namespace.name,
                vxlan.vid
            );
        }

        // After the wg and the vxlan interfaces are created,
        // then we will follow the next steps
        // 1. create the vrf interface
        // 2. put the vxlan & wg interfaces into the vrf interface
        // 3. config the ip address, if needed
        // 4. config the default route, if needed

        // namespace name has two parts. The 1st part is original namespace,
        // the 2nd part is the vrf table ID. They are joined with '_'.
        let ret = extract_table_id_from_namespace(namespace.name.as_str());
        if let Err(e) = ret {
            error!("Cannot get table id from namespace {}: {}", namespace.name, e.to_string());
            return Err(e);
        }

        let table_id = ret.as_ref().unwrap().1;
        let vrf_name = ret.as_ref().unwrap().0;
        debug!("{} table id: {}", namespace.name, table_id);
        let ret = self.create_vrf_interface(format!("vrf_{}", vrf_name), table_id).await;

        // put the vxlan & wg interface into the vrf interface
        if let Err(e) = ret {
            error!(
                "Cannot create vrf interface for namespace {}: {}",
                namespace.name,
                e.to_string()
            );
            return Err(e);
        }

        let vrf_index = ret.unwrap();
        let wg_intf_index_ret = self.get_interface_index(namespace.name.as_str()).await;
        let wg_intf_index;
        if let Err(e) = wg_intf_index_ret {
            error!(
                "Cannot get wg interface index for namespace {}: {}",
                namespace.name,
                e.to_string()
            );
            return Err(e);
        }

        wg_intf_index = wg_intf_index_ret.unwrap();
        let ret = self.move_interface_to_vrf(wg_intf_index, vrf_index).await;
        if let Err(e) = ret {
            error!("Cannot put wg interface into vrf {}: {}", namespace.name, e.to_string());
            return Err(e);
        }

        let vxlan_if_index_ret = self.get_interface_index(
            format!("vxlan_{}", vxlan.vid).as_str()
        ).await;
        let vxlan_if_index;
        if let Err(e) = vxlan_if_index_ret {
            error!(
                "Cannot get vxlan interface index for namespace {}: {}",
                format!("vxlan_{}", vxlan.vid),
                e.to_string()
            );
            return Err(e);
        } else {
            vxlan_if_index = vxlan_if_index_ret.unwrap();
        }

        let ret = self.move_interface_to_vrf(vxlan_if_index, vrf_index).await;
        if let Err(e) = ret {
            error!(
                "Cannot put vxlan interface into vrf {}: {}",
                format!("vxlan_{}", vxlan.vid),
                e.to_string()
            );
            return Err(e);
        }

        // Create iptables so that we can forward all incoming traffic from the
        // wg interface side to the vxlan tunnel interface. In other words, the
        // vrf routing is only needed for downstream traffic. For upstream
        // traffic we want it to be routed by the VPP and pass through sase tai
        // firewall.
        let ip = std::format!("{}/{}", wg_interface_ip, wg_interface_prefix);
        self.create_fwmark_entry(wg_interface, ip, vxlan.vid as u32).await.map_or_else(
            |e| {
                if e.kind() != ErrorKind::AlreadyExists {
                    error!(
                        "Cannot create iptables fwmark entry for namespace {}: {}",
                        namespace.name,
                        e.to_string()
                    );
                    Err(e)
                } else {
                    info!(
                        "Iptables fwmark entry for namespace {} already exists, skipping creation",
                        namespace.name
                    );
                    Ok(())
                }
            },
            |_| {
                info!(
                    "Created iptables fwmark entry for namespace {} with vid {}",
                    namespace.name,
                    vxlan.vid
                );
                Ok(())
            }
        )?;

        // create the ip filter tables rule to allow traffic to pass
        let ip = std::format!("{}/{}", wg_interface_ip, wg_interface_prefix);
        self.create_filter_forward_entry(ip).await.map_or_else(
            |e| {
                if e.kind() != ErrorKind::AlreadyExists {
                    error!(
                        "Cannot create filter forward entry for namespace {}: {}",
                        namespace.name,
                        e.to_string()
                    );
                    Err(e)
                } else {
                    info!(
                        "Filter forward entry for namespace {} already exists, skipping creation",
                        namespace.name
                    );
                    Ok(())
                }
            },
            |_| {
                info!(
                    "Created filter forward entry for namespace {} with vid {}",
                    namespace.name,
                    vxlan.vid
                );
                Ok(())
            }
        )?;

        // create the ip rules to lookup a vxlan vid as table-id's routing
        // table. Note that this is different than the vrf routing table
        // which is used for downstream traffic.
        let ret = self.add_del_ip_rule(
            true,
            Some(vxlan.vid as u32),
            vxlan.vid as u32,
            100 as u32,
            None
        ).await;

        if let Err(e) = ret {
            if e.kind() != ErrorKind::AlreadyExists {
                error!("Cannot create ip rule for namespace {}: {}", namespace.name, e.to_string());
                return Err(e);
            }
            info!("IP rule for namespace {} already exists, skipping creation", namespace.name);
        } else {
            info!("Created ip rule for namespace {} with vid {}", namespace.name, vxlan.vid);
        }

        // Add route to make all upstream traffic forwarded to the vxlan tunnel
        let ret = self.create_route_entry(
            "0.0.0.0".to_string(),
            0,
            Some(vxlan.gw.clone()),
            Some(format!("vxlan_{}", vxlan.vid)),
            Some(table_id)
        ).await;

        if let Err(e) = ret {
            if e.kind() != ErrorKind::AlreadyExists {
                error!(
                    "Cannot create route entry for namespace {}: {}",
                    namespace.name,
                    e.to_string()
                );
                return Err(e);
            }
            info!("Route entry for namespace {} already exists, skipping creation", namespace.name);
        } else {
            info!("Created route entry for namespace {} with vid {}", namespace.name, vxlan.vid);
        }

        // Config vxlan underlay route
        if vxlan.underlay_if == "" {
            warn!("configuration underlay is nil");
            let err_type = ErrorKind::InvalidInput;
            let err_msg = "underlay interface is nil";
            return Err(std::io::Error::new(err_type, err_msg));
        }

        let if_name = vxlan.underlay_if.clone();
        let ret = self.create_route_entry(
            vxlan.remote,
            32,
            None,
            Some(if_name),
            Some(table_id)
        ).await;
        if let Err(e) = ret {
            if e.kind() != ErrorKind::AlreadyExists {
                error!(
                    "Cannot create underlay route entry for namespace {}: {}",
                    namespace.name,
                    e.to_string()
                );
                return Err(e);
            }
            info!(
                "Underlay route entry for namespace {} already exists, skipping creation",
                namespace.name
            );
        } else {
            info!(
                "Created underlay route entry for namespace {} with vid {}",
                namespace.name,
                vxlan.vid
            );
        }
        info!("Namespace {} created successfully", namespace.name);
        Ok(())
    }
    async fn get_namespace_stats(&self, namespace: String) -> Result<models::InterfaceStats> {
        let stats = self.get_interface_stats(namespace.as_str()).await?;

        let stats_ret = models::InterfaceStats {
            name: Some(namespace),
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
        // Check if the user has been created
        let etcd_handler: &Client = self.as_ref();

        // Check if there is an existing pk for this wg user.
        if
            let Ok(wg_user_in_db) = etcd_handler.get_user(
                wg_user.namespace.as_str(),
                wg_user.id.as_str()
            ).await
        {
            let namespace = wg_user_in_db.namespace.clone();
            let pk = wg_user_in_db.pubkey.clone();
            if pk == wg_user.pubkey {
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
                let _ = etcd_handler.delete_pk(namespace.as_str(), pk.as_str()).await;
                let _ = self.delete_wg_user(&namespace, &pk);
            }
        }

        self.create_wireguard_peer(
            &wg_user.namespace,
            &wg_user.pubkey,
            &wg_user.allowed_ips
        ).await?;
        // save it in backend database
        debug!("User [{}/{}/{}] has been created.", wg_user.name, wg_user.id, wg_user.pubkey);

        let content_json = serde_json::to_string(wg_user).map_err(|e| {
            return std::io::Error::new(ErrorKind::InvalidData, e.to_string());
        })?;

        if !skip_store_into_db {
            let _ = etcd_handler.save_user(
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
        // Check if the user has been created
        // Note we only need the wg_user id field to be valid
        let etcd_handler: &Client = self.as_ref();

        let user = etcd_handler.get_user(wg_user.namespace.as_str(), wg_user.id.as_str()).await?;

        self.delete_wg_user(&wg_user.namespace, &user.pubkey).await?;
        debug!("User [{}/{}/{}] has been deleted.", wg_user.namespace, wg_user.id, user.pubkey);
        // delete it from backend database
        let _ = etcd_handler.delete_user(wg_user.namespace.as_str(), user.id.as_str()).await?;
        etcd_handler.delete_pk(wg_user.namespace.as_str(), user.pubkey.as_str()).await
    }

    fn peer_to_wg_user_stats(
        &self,
        peer: &WgPeer,
        namespace: &str,
        id: &str,
        pubkey: String
    ) -> models::WgUserStats {
        let last_seen = peer.last_handshake_time.map_or(0, |a| a);
        debug!("last seen at {}", last_seen);

        models::WgUserStats {
            name: "".to_string(),
            device_id: "".to_string(),
            id: id.to_string(),
            pubkey: pubkey.to_owned(),
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
        let pubkey = wg_user.pubkey.clone();
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
                    error!("get user stats: user {}/{} not found", wg_user.name, wg_user.pubkey);
                    Err(Error::new(ErrorKind::Other, "User not found"))
                }
                Some(a) => {
                    info!("get user stats: user {}/{} found", wg_user.name, wg_user.pubkey);
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
                let pk = pubkey.trim_start_matches("pk:").to_string();
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
