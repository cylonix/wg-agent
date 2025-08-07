// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

use async_trait::async_trait;
use iptables::{ self };
use log::{ debug, error, info, warn };
use rtnetlink::{
    new_connection,
    Handle,
    IpVersion,
    LinkUnspec,
    LinkVrf,
    LinkVxlan,
    LinkWireguard,
    RouteMessageBuilder,
};
use netlink_packet_route::AddressFamily;
use netlink_packet_route::address::{ AddressAttribute, AddressMessage };
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::rule::RuleAttribute;
use netlink_packet_route::route::{ RouteMessage, RouteHeader };
use futures::stream::TryStreamExt;
use std::io::{ Error, ErrorKind };
use std::net::{ IpAddr, Ipv4Addr };
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use wg_api::{ models::WgNamespaceDetail, models::InterfaceStats };
use wg_rs::{
    add_wireguard_peer,
    collect_wireguard_info,
    remove_wirefguard_peer,
    set_wireguard_interface,
    ConvertToBase58,
    WgPeer,
};

const IPTABLE_TABLE: &str = "mangle";
const IPTABLE_CHAIN: &str = "PREROUTING";
const IPTABLE_FILTER_TABLE: &str = "filter";
const IPTABLE_FORWARD_CHAIN: &str = "FORWARD";
const WG_PERSISTENCE_KEEPALIVE_INTERVAL: u16 = 15;

#[derive(Debug, Clone)]
pub struct FwMark {
    pub mark: u32,
    pub mask: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct VrfParams {
    pub table: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct IpRouteEntry {
    pub destination: String,
    pub interface: Option<String>,
    pub gateway: Option<String>,
    pub table: Option<u32>,
    pub metric: Option<u32>,
}

impl IpRouteEntry {
    pub fn new(
        destination: String,
        interface: Option<String>,
        gateway: Option<String>,
        table: Option<u32>,
        metric: Option<u32>
    ) -> Option<Self> {
        Some(IpRouteEntry {
            destination,
            interface,
            gateway,
            table,
            metric,
        })
    }
}

pub struct NetworkConfClient {
    handle: Option<Handle>,
    iptable: iptables::IPTables,
}

impl NetworkConfClient {
    pub fn new() -> Self {
        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);
        NetworkConfClient {
            handle: Some(handle),
            iptable: iptables::new(false).unwrap(),
        }
    }

    pub fn new_without_handle() -> Self {
        NetworkConfClient {
            handle: None,
            iptable: iptables::new(false).unwrap(),
        }
    }

    pub async fn move_interface_to_vrf(&self, if_index: u32, vrf_index: u32) -> Result<(), Error> {
        self.handle
            .as_ref()
            .unwrap()
            .link()
            .set(LinkUnspec::new_with_index(if_index).controller(vrf_index).build())
            .execute().await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
    }

    pub async fn get_if_index_by_name(&self, name: &str) -> Result<u32, Error> {
        let mut links = self.handle
            .as_ref()
            .unwrap()
            .link()
            .get()
            .match_name(name.to_string())
            .execute();

        match links.try_next().await {
            Ok(Some(link)) => Ok(link.header.index),
            Ok(None) =>
                Err(Error::new(ErrorKind::NotFound, format!("Interface {} not found", name))),
            Err(e) => Err(Error::new(ErrorKind::Other, e.to_string())),
        }
    }

    pub async fn get_ip_by_name(&self, name: &str) -> Result<Vec<String>, Error> {
        let if_index = self.get_if_index_by_name(name).await?;

        let mut addresses = self.handle
            .as_ref()
            .unwrap()
            .address()
            .get()
            .set_link_index_filter(if_index)
            .execute();

        let mut ips = Vec::new();
        while
            let Some(addr) = addresses
                .try_next().await
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        {
            if let Some(ip_str) = self.parse_address_from_message(&addr) {
                ips.push(ip_str);
            }
        }

        Ok(ips)
    }

    pub fn create_fwmark_entry(
        &self,
        src_intf: String,
        src_ip: String,
        fwmark: u32
    ) -> std::io::Result<()> {
        let filter = format!("-i {} -s {} -j MARK --set-mark {}", src_intf, src_ip, fwmark);
        self.iptable.append_unique(IPTABLE_TABLE, IPTABLE_CHAIN, &filter).map_err(|e| {
            let err_string = e.to_string();
            err_string.find("exists").map_or_else(
                || Error::new(ErrorKind::InvalidData, e.to_string()),
                |_| Error::new(ErrorKind::AlreadyExists, err_string)
            )
        })
    }

    pub fn delete_fwmark_entry(
        &self,
        src_intf: String,
        src_ip: String,
        fwmark: u32
    ) -> std::io::Result<()> {
        let filter = format!("-i {} -s {} -j MARK --set-mark {}", src_intf, src_ip, fwmark);
        self.iptable
            .delete(IPTABLE_TABLE, IPTABLE_CHAIN, &filter)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
    }

    pub fn create_iptable_filter_forward_entry(
        &self,
        src_ip: String,
        direction: String
    ) -> std::io::Result<()> {
        let direction_symbol = if direction == "source" { "s" } else { "d" };
        let filter = format!("-{} {} -j ACCEPT", direction_symbol, src_ip);

        self.iptable
            .append_unique(IPTABLE_FILTER_TABLE, IPTABLE_FORWARD_CHAIN, &filter)
            .map_err(|e| {
                let err_string = e.to_string();
                err_string.find("exists").map_or_else(
                    || Error::new(ErrorKind::InvalidData, e.to_string()),
                    |_| Error::new(ErrorKind::AlreadyExists, err_string)
                )
            })
    }

    pub fn delete_iptable_filter_forward_entry(
        &self,
        src_ip: String,
        direction: String
    ) -> std::io::Result<()> {
        let direction_symbol = if direction == "source" { "s" } else { "d" };
        let filter = format!("-{} {} -j ACCEPT", direction_symbol, src_ip);
        self.iptable
            .delete(IPTABLE_FILTER_TABLE, IPTABLE_FORWARD_CHAIN, &filter)
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
    }

    pub async fn create_vrf_interface(&self, name: String, table_id: u32) -> std::io::Result<u32> {
        match
            self.handle
                .as_ref()
                .unwrap()
                .link()
                .add(LinkVrf::new(&name, table_id).up().build())
                .execute().await
        {
            Ok(_) => info!("Successfully created VRF interface {}", name),
            Err(e) if e.to_string().contains("exists") => {
                warn!("VRF interface {} already exists", name);
            }
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, e.to_string()));
            }
        }

        let if_index = self.get_if_index_by_name(&name).await?;
        if let Err(e) = self.set_interface_up(if_index).await {
            warn!("Failed to set vrf interface {} up (this is often expected): {}", name, e);
            // Continue anyway as this isn't critical
        }
        Ok(if_index)
    }

    async fn set_interface_up(&self, if_index: u32) -> std::io::Result<()> {
        self.handle
            .as_ref()
            .unwrap()
            .link()
            .set(LinkUnspec::new_with_index(if_index).up().build())
            .execute().await
            .map_err(|e|
                Error::new(
                    ErrorKind::Other,
                    format!("Failed to set interface {} up: {}", if_index, e.to_string())
                )
            )
    }

    pub async fn create_wg_interface(
        &self,
        link_name: String,
        ip_with_mask: String
    ) -> std::io::Result<u32> {
        match
            self.handle
                .as_ref()
                .unwrap()
                .link()
                .add(LinkWireguard::new(&link_name).up().build())
                .execute().await
        {
            Ok(_) => info!("Successfully created WireGuard interface {}", link_name),
            Err(e) if e.to_string().contains("exists") => {
                info!("WireGuard interface {} already exists", link_name);
            }
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, e.to_string()));
            }
        }

        let ret = self.get_if_index_by_name(&link_name).await;
        if let Err(e) = ret {
            error!("Cannot get WireGuard interface index for {}: {}", link_name, e);
            return Err(
                Error::new(
                    ErrorKind::NotFound,
                    format!("WireGuard interface {} not found: {}", link_name, e.to_string())
                )
            );
        }
        let if_index = ret.unwrap();
        let ret = self.configure_interface_ip(if_index, &ip_with_mask).await;
        if let Err(e) = ret {
            error!("Cannot configure WireGuard interface {} up: {}", link_name, e);
            return Err(
                Error::new(
                    ErrorKind::Other,
                    format!(
                        "Failed to configure WireGuard interface {} ip: {}",
                        link_name,
                        e.to_string()
                    )
                )
            );
        }
        if let Err(e) = self.set_interface_up(if_index).await {
            warn!("Failed to set wg interface {} up (this is often expected): {}", link_name, e);
            // Continue anyway as this isn't critical
        }
        Ok(if_index)
    }

    pub async fn create_vxlan_interface(
        &self,
        link_name: String,
        ip_with_mask: String,
        vid: u32,
        remote: String,
        dstport: u16
    ) -> std::io::Result<u32> {
        let remote_ip = Ipv4Addr::from_str(&remote).map_err(|e|
            Error::new(ErrorKind::InvalidData, e.to_string())
        )?;

        // Create VXLAN interface
        match
            self.handle
                .as_ref()
                .unwrap()
                .link()
                .add(LinkVxlan::new(&link_name, vid).remote(remote_ip).port(dstport).up().build())
                .execute().await
        {
            Ok(_) => info!("Successfully created VXLAN interface {}", link_name),
            Err(e) if e.to_string().contains("exists") => {
                info!("VXLAN interface {} already exists", link_name);
            }
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, e.to_string()));
            }
        }

        let if_index = self.get_if_index_by_name(&link_name).await?;
        self.configure_interface_ip(if_index, &ip_with_mask).await?;
        if let Err(e) = self.set_interface_up(if_index).await {
            warn!("Failed to set vxlan interface {} up (this is often expected): {}", link_name, e);
            // Continue anyway as this isn't critical
        }
        Ok(if_index)
    }

    async fn configure_interface_ip(
        &self,
        if_index: u32,
        ip_with_mask: &str
    ) -> std::io::Result<()> {
        let (addr_str, prefix_len) = self.parse_ip_with_mask(ip_with_mask)?;
        let ip_addr = IpAddr::from_str(&addr_str).map_err(|e|
            Error::new(ErrorKind::InvalidData, e.to_string())
        )?;

        self.handle
            .as_ref()
            .unwrap()
            .address()
            .add(if_index, ip_addr, prefix_len)
            .execute().await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
            .map(|v| {
                info!("Successfully added IP {} to interface {}", ip_with_mask, if_index);
                v
            })
    }

    pub fn parse_ip_with_mask(&self, ip_with_mask: &str) -> Result<(String, u8), Error> {
        let parts: Vec<&str> = ip_with_mask.trim().split('/').collect();
        if parts.len() != 2 {
            return Err(Error::new(ErrorKind::InvalidInput, "Invalid IP/mask format"));
        }

        let prefix_len = parts[1]
            .parse::<u8>()
            .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?;

        Ok((parts[0].to_string(), prefix_len))
    }

    pub async fn delete_interface(&self, link_name: String) -> std::io::Result<()> {
        debug!("Try to delete interface {}", link_name);

        let if_index = match self.get_if_index_by_name(&link_name).await {
            Ok(index) => index,
            Err(_) => {
                error!("Cannot delete the interface {}, not found", link_name);
                return Err(Error::new(ErrorKind::NotFound, "Interface not found"));
            }
        };

        self.handle
            .as_ref()
            .unwrap()
            .link()
            .del(if_index)
            .execute().await
            .map_err(|e| {
                error!("Cannot delete the interface {}, reason {}", link_name, e);
                Error::new(ErrorKind::Other, e.to_string())
            })
    }

    pub async fn delete_wg_interface(&self, link_name: String) -> std::io::Result<()> {
        self.delete_interface(link_name).await
    }

    pub async fn delete_vxlan_interface(&self, link_name: String) -> std::io::Result<()> {
        self.delete_interface(link_name).await
    }

    pub async fn delete_vrf_interface(&self, link_name: String) -> std::io::Result<()> {
        self.delete_interface(link_name).await
    }

    pub async fn get_if_stats_by_name(&self, name: &str) -> Result<InterfaceStats, Error> {
        let mut links = self.handle
            .as_ref()
            .unwrap()
            .link()
            .get()
            .match_name(name.to_string())
            .execute();

        match links.try_next().await {
            Ok(Some(link)) => {
                // Initialize all fields with default values first
                let mut stats = InterfaceStats {
                    name: Some(name.to_string()),
                    rx_packets: 0,
                    tx_packets: 0,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    rx_errors: 0,
                    tx_errors: 0,
                    rx_dropped: 0,
                    tx_dropped: 0,
                    multicast: 0,
                    collisions: 0,
                    rx_length_errors: 0,
                    rx_over_errors: 0,
                    rx_crc_errors: 0,
                    rx_frame_errors: 0,
                    rx_fifo_errors: 0,
                    rx_missed_errors: 0,
                    tx_aborted_errors: 0,
                    tx_carrier_errors: 0,
                    tx_fifo_errors: 0,
                    tx_heartbeat_errors: 0,
                    tx_window_errors: 0,
                    rx_compressed: 0,
                    tx_compressed: 0,
                    rx_nohandler: 0,
                };

                // Parse link attributes for statistics
                for attr in &link.attributes {
                    match attr {
                        LinkAttribute::Stats64(link_stats) => {
                            stats.rx_packets = link_stats.rx_packets as i64;
                            stats.tx_packets = link_stats.tx_packets as i64;
                            stats.rx_bytes = link_stats.rx_bytes as i64;
                            stats.tx_bytes = link_stats.tx_bytes as i64;
                            stats.rx_errors = link_stats.rx_errors as i64;
                            stats.tx_errors = link_stats.tx_errors as i64;
                            stats.rx_dropped = link_stats.rx_dropped as i64;
                            stats.tx_dropped = link_stats.tx_dropped as i64;
                            stats.multicast = link_stats.multicast as i64;
                            stats.collisions = link_stats.collisions as i64;
                            stats.rx_length_errors = link_stats.rx_length_errors as i64;
                            stats.rx_over_errors = link_stats.rx_over_errors as i64;
                            stats.rx_crc_errors = link_stats.rx_crc_errors as i64;
                            stats.rx_frame_errors = link_stats.rx_frame_errors as i64;
                            stats.rx_fifo_errors = link_stats.rx_fifo_errors as i64;
                            stats.rx_missed_errors = link_stats.rx_missed_errors as i64;
                            stats.tx_aborted_errors = link_stats.tx_aborted_errors as i64;
                            stats.tx_carrier_errors = link_stats.tx_carrier_errors as i64;
                            stats.tx_fifo_errors = link_stats.tx_fifo_errors as i64;
                            stats.tx_heartbeat_errors = link_stats.tx_heartbeat_errors as i64;
                            stats.tx_window_errors = link_stats.tx_window_errors as i64;
                            stats.rx_compressed = link_stats.rx_compressed as i64;
                            stats.tx_compressed = link_stats.tx_compressed as i64;
                            stats.rx_nohandler = link_stats.rx_nohandler as i64;
                            break;
                        }
                        LinkAttribute::Stats(link_stats) => {
                            // Fallback to 32-bit stats if 64-bit not available
                            stats.rx_packets = link_stats.rx_packets as i64;
                            stats.tx_packets = link_stats.tx_packets as i64;
                            stats.rx_bytes = link_stats.rx_bytes as i64;
                            stats.tx_bytes = link_stats.tx_bytes as i64;
                            stats.rx_errors = link_stats.rx_errors as i64;
                            stats.tx_errors = link_stats.tx_errors as i64;
                            stats.rx_dropped = link_stats.rx_dropped as i64;
                            stats.tx_dropped = link_stats.tx_dropped as i64;
                            stats.multicast = link_stats.multicast as i64;
                            stats.collisions = link_stats.collisions as i64;
                            stats.rx_length_errors = link_stats.rx_length_errors as i64;
                            stats.rx_over_errors = link_stats.rx_over_errors as i64;
                            stats.rx_crc_errors = link_stats.rx_crc_errors as i64;
                            stats.rx_frame_errors = link_stats.rx_frame_errors as i64;
                            stats.rx_fifo_errors = link_stats.rx_fifo_errors as i64;
                            stats.rx_missed_errors = link_stats.rx_missed_errors as i64;
                            stats.tx_aborted_errors = link_stats.tx_aborted_errors as i64;
                            stats.tx_carrier_errors = link_stats.tx_carrier_errors as i64;
                            stats.tx_fifo_errors = link_stats.tx_fifo_errors as i64;
                            stats.tx_heartbeat_errors = link_stats.tx_heartbeat_errors as i64;
                            stats.tx_window_errors = link_stats.tx_window_errors as i64;
                            stats.rx_compressed = link_stats.rx_compressed as i64;
                            stats.tx_compressed = link_stats.tx_compressed as i64;
                            stats.rx_nohandler = link_stats.rx_nohandler as i64;
                        }
                        _ => {}
                    }
                }

                Ok(stats)
            }
            Ok(None) =>
                Err(Error::new(ErrorKind::NotFound, format!("Interface {} not found", name))),
            Err(e) => Err(Error::new(ErrorKind::Other, e.to_string())),
        }
    }

    fn parse_address_from_message(&self, addr: &AddressMessage) -> Option<String> {
        // Parse netlink attributes to extract IP address and prefix length
        for attr in &addr.attributes {
            match attr {
                AddressAttribute::Address(ip_addr) => {
                    let prefix_len = addr.header.prefix_len;

                    // Check address family
                    match addr.header.family {
                        AddressFamily::Inet => {
                            if ip_addr.is_ipv4() {
                                return Some(format!("{}/{}", ip_addr.to_string(), prefix_len));
                            }
                        }
                        AddressFamily::Inet6 => {
                            if ip_addr.is_ipv6() {
                                return Some(format!("{}/{}", ip_addr.to_string(), prefix_len));
                            }
                        }
                        _ => {
                            continue;
                        }
                    }
                }
                AddressAttribute::Local(ip_addr) => {
                    // Sometimes the local address attribute is used instead
                    let prefix_len = addr.header.prefix_len;
                    if let AddressFamily::Inet = addr.header.family {
                        if ip_addr.is_ipv4() {
                            return Some(format!("{}/{}", ip_addr.to_string(), prefix_len));
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }

    pub async fn add_del_ip_rule(
        &self,
        add: bool,
        fwmark: Option<u32>,
        table: u32,
        priority: u32,
        suppress_prefixlength: Option<u32>
    ) -> std::io::Result<()> {
        let result = if add {
            let mut request = self.handle
                .as_ref()
                .unwrap()
                .rule()
                .add()
                .v4()
                .table_id(table)
                .priority(priority);

            if let Some(mark) = fwmark {
                request = request.fw_mark(mark);
            }
            if let Some(suppress) = suppress_prefixlength {
                request.message_mut().attributes.push(RuleAttribute::SuppressPrefixLen(suppress));
            }

            request.execute().await
        } else {
            // For delete, get existing rules and find the matching one
            let mut rules = self.handle.as_ref().unwrap().rule().get(IpVersion::V4).execute();

            while
                let Some(rule) = rules
                    .try_next().await
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
            {
                let mut rule_matches = true;

                // Check if rule matches our criteria
                if let Some(expected_mark) = fwmark {
                    let mut has_matching_mark = false;
                    for attr in &rule.attributes {
                        if let RuleAttribute::FwMark(mark) = attr {
                            if *mark == expected_mark {
                                has_matching_mark = true;
                                break;
                            }
                        }
                    }
                    if !has_matching_mark {
                        rule_matches = false;
                    }
                }

                if rule_matches && rule.header.table == (table as u8) {
                    // Delete this rule using the original rule message
                    return self.handle
                        .as_ref()
                        .unwrap()
                        .rule()
                        .del(rule)
                        .execute().await
                        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()));
                }
            }

            return Err(Error::new(ErrorKind::NotFound, "Rule not found"));
        };

        result.map_err(|e| {
            let err_string = e.to_string();
            if err_string.contains("exists") {
                Error::new(ErrorKind::AlreadyExists, err_string)
            } else {
                Error::new(ErrorKind::Other, err_string)
            }
        })
    }

    pub async fn delete_ip_fwmark_rule(&self, fwmark: u32) -> std::io::Result<()> {
        let mut rules = self.handle.as_ref().unwrap().rule().get(IpVersion::V4).execute();

        while
            let Some(rule) = rules
                .try_next().await
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        {
            // Check if this rule has the matching fwmark
            for attr in &rule.attributes {
                if let RuleAttribute::FwMark(mark) = attr {
                    if *mark == fwmark {
                        return self.handle
                            .as_ref()
                            .unwrap()
                            .rule()
                            .del(rule)
                            .execute().await
                            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()));
                    }
                }
            }
        }

        Err(Error::new(ErrorKind::NotFound, format!("No rule found with fwmark {}", fwmark)))
    }

    pub async fn create_route_entry(
        &self,
        dest_ip: String,
        prefix_len: u8,
        gateway: Option<String>,
        interface: Option<String>,
        table: Option<u32>
    ) -> std::io::Result<()> {
        let dest = IpAddr::from_str(&dest_ip).map_err(|e|
            Error::new(ErrorKind::InvalidInput, e.to_string())
        )?;

        // Get interface index if needed
        let if_index = if let Some(ref iface) = interface {
            Some(self.get_if_index_by_name(iface).await?)
        } else {
            None
        };

        // Create route message
        let mut builder = RouteMessageBuilder::<IpAddr>
            ::new()
            .destination_prefix(dest, prefix_len)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?;

        if let Some(table_id) = table {
            builder = builder.table_id(table_id);
        }

        if let Some(gw) = gateway {
            let gw_ip = IpAddr::from_str(&gw).map_err(|e|
                Error::new(ErrorKind::InvalidInput, e.to_string())
            )?;
            builder = builder
                .gateway(gw_ip)
                .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?;
        }

        // Add output interface if specified
        if let Some(idx) = if_index {
            builder = builder.output_interface(idx);
        }

        // Execute addition
        self.handle
            .as_ref()
            .unwrap()
            .route()
            .add(builder.build())
            .execute().await
            .map_err(|e| {
                let err_string = e.to_string();
                if err_string.contains("exists") {
                    Error::new(ErrorKind::AlreadyExists, err_string)
                } else {
                    Error::new(ErrorKind::Other, err_string)
                }
            })
    }

    pub async fn delete_route_entry(
        &self,
        dest_ip: String,
        prefix_len: u8,
        gateway: Option<String>,
        interface: Option<String>,
        table: Option<u32>
    ) -> std::io::Result<()> {
        let dest = IpAddr::from_str(&dest_ip).map_err(|e|
            Error::new(ErrorKind::InvalidInput, e.to_string())
        )?;

        // Get interface index if needed
        let if_index = if let Some(ref iface) = interface {
            Some(self.get_if_index_by_name(iface).await?)
        } else {
            None
        };

        // Create route message for deletion
        let mut builder = RouteMessageBuilder::<IpAddr>
            ::new()
            .destination_prefix(dest, prefix_len)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?;
        if let Some(table_id) = table {
            builder = builder.table_id(table_id);
        }

        if let Some(gw) = gateway {
            let gw_ip = IpAddr::from_str(&gw).map_err(|e|
                Error::new(ErrorKind::InvalidInput, e.to_string())
            )?;
            builder = builder
                .gateway(gw_ip)
                .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?;
        }

        if let Some(idx) = if_index {
            builder = builder.output_interface(idx);
        }

        // Execute deletion
        self.handle
            .as_ref()
            .unwrap()
            .route()
            .del(builder.build())
            .execute().await
            .map_err(|e| {
                let err_string = e.to_string();
                if err_string.contains("No such process") || err_string.contains("not found") {
                    Error::new(ErrorKind::NotFound, format!("Route not found: {}", err_string))
                } else {
                    Error::new(ErrorKind::Other, err_string)
                }
            })
    }

    pub async fn flush_route_table(&self, table: Option<u32>) -> std::io::Result<()> {
        let table_id = table.unwrap_or(libc::RT_TABLE_MAIN as u32);

        // Handle IPv4 routes
        let mut route_msg_v4 = RouteMessage::default();
        route_msg_v4.header = RouteHeader {
            address_family: AddressFamily::Inet,
            table: table_id as u8,
            ..Default::default()
        };

        let mut routes = self.handle.as_ref().unwrap().route().get(route_msg_v4).execute();
        let mut routes_to_delete = Vec::new();

        while
            let Some(route) = routes
                .try_next().await
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        {
            if route.header.table == (table_id as u8) {
                routes_to_delete.push(route);
            }
        }

        for route in routes_to_delete {
            let _ = self.handle.as_ref().unwrap().route().del(route).execute().await;
        }

        // Handle IPv6 routes
        let mut route_msg_v6 = RouteMessage::default();
        route_msg_v6.header = RouteHeader {
            address_family: AddressFamily::Inet6,
            table: table_id as u8,
            ..Default::default()
        };

        let mut routes_v6 = self.handle.as_ref().unwrap().route().get(route_msg_v6).execute();
        let mut routes_v6_to_delete = Vec::new();

        while
            let Some(route) = routes_v6
                .try_next().await
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
        {
            if route.header.table == (table_id as u8) {
                routes_v6_to_delete.push(route);
            }
        }

        for route in routes_v6_to_delete {
            let _ = self.handle.as_ref().unwrap().route().del(route).execute().await;
        }

        Ok(())
    }
}

#[async_trait]
pub trait NetApiHandler {
    async fn create_wg_interface(
        &self,
        namespace_name: &str,
        ip: &str,
        port: Option<i32>,
        key: &Option<String>
    ) -> Result<(), std::io::Error>;

    async fn delete_wg_interface(&self, namespace_name: &str) -> Result<(), std::io::Error>;

    async fn create_vxlan_interface(
        &self,
        ip_with_mask: String,
        vid: u32,
        remote: String,
        dstport: u16
    ) -> Result<(), std::io::Error>;

    async fn delete_vxlan_interface(&self, if_name: &str) -> Result<(), std::io::Error>;

    async fn create_vrf_interface(
        &self,
        name: String,
        table_id: u32
    ) -> Result<u32, std::io::Error>;
    async fn delete_vrf_interface(&self, _if_name: &str) -> Result<(), std::io::Error>;

    async fn create_fwmark_entry(
        &self,
        intf_name: String,
        src_ip: String,
        fwmark: u32
    ) -> std::io::Result<()>;
    async fn delete_fwmark_entry(
        &self,
        intf_name: String,
        src_ip: String,
        fwmark: u32
    ) -> std::io::Result<()>;

    async fn create_filter_forward_entry(&self, src_ip: String) -> std::io::Result<()>;
    async fn delete_filter_forward_entry(&self, src_ip: String) -> std::io::Result<()>;

    async fn create_route_entry(
        &self,
        dest_ip: String,
        prefix_len: u8,
        gateway: Option<String>,
        interface: Option<String>,
        table: Option<u32>
    ) -> std::io::Result<()>;
    async fn delete_route_entry(
        &self,
        dest_ip: String,
        prefix_len: u8,
        gateway: Option<String>,
        interface: Option<String>,
        table: Option<u32>
    ) -> std::io::Result<()>;

    async fn add_del_ip_rule(
        &self,
        add: bool,
        fwmark: Option<u32>,
        table: u32,
        priority: u32,
        suppress_prefixlength: Option<u32>
    ) -> std::io::Result<()>;
    async fn delete_ip_fwmark_rule(&self, fwmark: u32) -> std::io::Result<()>;

    async fn create_wireguard_peer(
        &self,
        name: &String,
        key: &String,
        allowed_ips: &Option<Vec<String>>
    ) -> Result<(), std::io::Error>;

    async fn delete_wg_user(
        &self,
        interface_name: &String,
        key: &String
    ) -> Result<(), std::io::Error>;

    async fn get_namespace_detail(&self, name: &str) -> Result<WgNamespaceDetail, std::io::Error>;
    async fn get_interface_stats(&self, name: &str) -> Result<InterfaceStats, std::io::Error>;

    async fn get_all_users(&self, namespace: &str) -> Result<Vec<WgPeer>, std::io::Error>;

    async fn get_interface_index(&self, name: &str) -> Result<u32, std::io::Error>;

    async fn move_interface_to_vrf(
        &self,
        if_index: u32,
        vrf_index: u32
    ) -> Result<(), std::io::Error>;
}

#[async_trait]
impl<T> NetApiHandler for T where T: AsRef<Arc<Mutex<NetworkConfClient>>> + Send + Sync {
    async fn move_interface_to_vrf(
        &self,
        if_index: u32,
        vrf_index: u32
    ) -> Result<(), std::io::Error> {
        let client = self.as_ref().lock().await;
        client.move_interface_to_vrf(if_index, vrf_index).await
    }

    async fn get_interface_index(&self, name: &str) -> Result<u32, std::io::Error> {
        let client = self.as_ref().lock().await;
        client.get_if_index_by_name(name).await
    }

    async fn create_wg_interface(
        &self,
        namespace_name: &str,
        ip: &str,
        port: Option<i32>,
        key: &Option<String>
    ) -> Result<(), std::io::Error> {
        let client = self.as_ref().lock().await;

        let if_index = client.create_wg_interface(
            String::from(namespace_name),
            String::from(ip)
        ).await?;

        // Use spawn_blocking for synchronous wg-rs operations
        let namespace_name = namespace_name.to_string();
        let key = key.clone();
        tokio::task
            ::spawn_blocking(move || {
                set_wireguard_interface(
                    &namespace_name,
                    Some(if_index),
                    key.as_ref().map(|k| k.as_str()),
                    port.map(|p| p as u16),
                    None
                )
            }).await
            .unwrap()
    }

    async fn create_vxlan_interface(
        &self,
        ip_with_mask: String,
        vid: u32,
        remote: String,
        dstport: u16
    ) -> Result<(), std::io::Error> {
        debug!(
            "Creating a new vxlan interface, name vxlan_{}, ip {}, vid {}, peer {}, dst port {}",
            vid,
            ip_with_mask,
            vid,
            remote,
            dstport
        );
        let client = self.as_ref().lock().await;

        client
            .create_vxlan_interface(
                format!("vxlan_{}", vid).to_string(),
                ip_with_mask.clone(),
                vid,
                remote.clone(),
                dstport
            ).await
            .map_err(|e| {
                warn!(
                    "Cannot create vxlan interface: ipwithmask:{}, vid {}, remote {}, dstport {}: {}",
                    ip_with_mask,
                    vid,
                    remote,
                    dstport,
                    e
                );
                e
            })
            .map(|_| ())
    }

    async fn create_fwmark_entry(
        &self,
        intf_name: String,
        src_ip: String,
        fwmark: u32
    ) -> std::io::Result<()> {
        debug!(
            "Creating the iptables entry, interface name {}, source ip {}, fwmark setting {}",
            intf_name,
            src_ip,
            fwmark
        );
        let intf_name_clone = intf_name.clone();
        let src_ip_clone = src_ip.clone();

        let client = self.as_ref().lock().await;
        client.create_fwmark_entry(intf_name_clone, src_ip_clone, fwmark)
    }

    async fn create_filter_forward_entry(&self, src_ip: String) -> std::io::Result<()> {
        debug!("Creating the iptables filter forward entry, source ip {}", src_ip);
        let src_ip_clone = src_ip.clone();
        let client = self.as_ref().lock().await;
        client.create_iptable_filter_forward_entry(src_ip_clone, "source".to_string())?;
        let src_ip_clone = src_ip.clone();
        client.create_iptable_filter_forward_entry(src_ip_clone, "destination".to_string())
    }

    async fn delete_filter_forward_entry(&self, src_ip: String) -> std::io::Result<()> {
        debug!("Delete an existing iptables forward entry, source ip {}", src_ip);
        let client = self.as_ref().lock().await;

        // Delete source rule
        let src_ip_clone = src_ip.clone();
        client.delete_iptable_filter_forward_entry(src_ip_clone, "source".to_string())?;

        // Delete destination rule
        let src_ip_clone = src_ip.clone();
        client.delete_iptable_filter_forward_entry(src_ip_clone, "destination".to_string())
    }

    async fn create_wireguard_peer(
        &self,
        name: &String,
        key: &String,
        allowed_ips: &Option<Vec<String>>
    ) -> Result<(), std::io::Error> {
        debug!("Creating wireguard peer for {}/{}", name, key);
        let client = self.as_ref().lock().await;

        let if_index = client.get_if_index_by_name(name).await?;

        // Use spawn_blocking for wg-rs operations
        let name_clone = name.clone();
        let key_clone = key.clone();
        match allowed_ips.clone() {
            None => {
                warn!("Allow ip cannot be empty.");
                Err(Error::new(ErrorKind::InvalidData, "allow ip cannot be empty"))
            }
            Some(ips) => {
                let ips_slice: Vec<&str> = ips
                    .iter()
                    .map(|a| a.as_str())
                    .collect();
                add_wireguard_peer(
                    &name_clone,
                    None,
                    Some(if_index),
                    Some(WG_PERSISTENCE_KEEPALIVE_INTERVAL),
                    ips_slice.as_slice(),
                    &key_clone
                )
            }
        }
    }

    async fn create_vrf_interface(
        &self,
        name: String,
        table_id: u32
    ) -> Result<u32, std::io::Error> {
        debug!("Creating a new vrf interface, name {}, table id {}", name, table_id);
        let ret = self.as_ref().lock().await.create_vrf_interface(name.clone(), table_id).await;
        match ret {
            Err(e) => {
                warn!("Cannot create vrf interface: name {}, table id {}: {}", name, table_id, e);
                Err(e)
            }
            Ok(v) => {
                info!("Successfully created vrf interface: name {}, table id {}", name, table_id);
                Ok(v)
            }
        }
    }

    async fn delete_fwmark_entry(
        &self,
        intf_name: String,
        src_ip: String,
        fwmark: u32
    ) -> std::io::Result<()> {
        debug!(
            "Delete an existing iptables entry, interface name {}, source ip {}, fwmark setting {}",
            intf_name,
            src_ip,
            fwmark
        );
        self.as_ref()
            .lock().await
            .delete_fwmark_entry(intf_name.clone(), src_ip.clone(), fwmark)
            .map_err(|e| {
                warn!(
                    "Cannot delete the fwmark entry, interface name {}, source ip {}, fwmark setting {}",
                    intf_name,
                    src_ip,
                    fwmark
                );
                e
            })
    }

    async fn add_del_ip_rule(
        &self,
        add: bool,
        fwmark: Option<u32>,
        table: u32,
        priority: u32,
        suppress_prefixlength: Option<u32>
    ) -> std::io::Result<()> {
        debug!(
            "add/del the ip rules entry: add {}, fwmark {:?}, table {}, priority {}",
            add,
            fwmark,
            table,
            priority
        );
        self
            .as_ref()
            .lock().await
            .add_del_ip_rule(add, fwmark, table, priority, suppress_prefixlength).await
    }

    async fn delete_ip_fwmark_rule(&self, fwmark: u32) -> std::io::Result<()> {
        debug!("Deleting the ip rules entry: fwmark {}", fwmark);
        self.as_ref().lock().await.delete_ip_fwmark_rule(fwmark).await
    }

    async fn create_route_entry(
        &self,
        dest_ip: String,
        prefix_len: u8,
        gateway: Option<String>,
        interface: Option<String>,
        table: Option<u32>
    ) -> std::io::Result<()> {
        debug!(
            "Creating an route entry, dst ip {}/{}, gateway {:?}, interface {:?}, table{:?}",
            dest_ip,
            prefix_len,
            gateway,
            interface,
            table
        );
        self.as_ref()
            .lock().await
            .create_route_entry(
                dest_ip.clone(),
                prefix_len,
                gateway.clone(),
                interface.clone(),
                table
            ).await
            .map_err(|e| {
                warn!(
                    "Cannot create route entry: {}/{}, gateway {:?}, interface{:?}, table{:?}, reason : {}",
                    dest_ip,
                    prefix_len,
                    gateway,
                    interface,
                    table,
                    e
                );
                e
            })
    }

    async fn delete_route_entry(
        &self,
        dest_ip: String,
        prefix_len: u8,
        gateway: Option<String>,
        interface: Option<String>,
        table: Option<u32>
    ) -> std::io::Result<()> {
        debug!(
            "Deleting an route entry {}/{}, gateway {:?}, interface {:?}, table{:?}",
            dest_ip,
            prefix_len,
            gateway,
            interface,
            table
        );
        self.as_ref()
            .lock().await
            .delete_route_entry(
                dest_ip.clone(),
                prefix_len,
                gateway.clone(),
                interface.clone(),
                table
            ).await
            .map_err(|e| {
                warn!(
                    "Cannot delete an route entry {}/{}, gateway {:?}, interface {:?}, table{:?}: {}",
                    dest_ip,
                    prefix_len,
                    gateway,
                    interface,
                    table,
                    e
                );
                e
            })
    }

    async fn delete_wg_interface(&self, namespace_name: &str) -> Result<(), std::io::Error> {
        debug!("Deleting an wireguard interface, interface name {}", namespace_name);
        self.as_ref()
            .lock().await
            .delete_wg_interface(String::from(namespace_name)).await
            .map_err(|e| {
                warn!(
                    "Cannot delete an wireguard interface, interface name {}, reason {}",
                    namespace_name,
                    e
                );
                e
            })
    }

    async fn delete_vxlan_interface(&self, if_name: &str) -> Result<(), std::io::Error> {
        debug!("Deleting an vxlan interface, interface name {}", if_name);
        self.as_ref()
            .lock().await
            .delete_vxlan_interface(String::from(if_name)).await
            .map_err(|e| {
                warn!("Cannot delete an vxlan interface, interface name {}, reason {}", if_name, e);
                e
            })
    }

    async fn delete_vrf_interface(&self, if_name: &str) -> Result<(), std::io::Error> {
        debug!("Deleting an vrf interface, interface name {}", if_name);
        self.as_ref()
            .lock().await
            .delete_vrf_interface(String::from(if_name)).await
            .map_err(|e| {
                warn!("Cannot delete an vrf interface, interface name {}, reason {}", if_name, e);
                e
            })
    }

    async fn delete_wg_user(
        &self,
        interface_name: &String,
        key: &String
    ) -> Result<(), std::io::Error> {
        let if_index = self.as_ref().lock().await.get_if_index_by_name(interface_name).await?;
        let interface_name = interface_name.clone();
        let key = key.clone();
        remove_wirefguard_peer(&interface_name, Some(if_index), &key)
    }

    async fn get_namespace_detail(&self, name: &str) -> Result<WgNamespaceDetail, std::io::Error> {
        let name_clone = name.to_string();
        let wg_info = collect_wireguard_info(&name_clone).unwrap();
        let pubkey = wg_info.get_base64_from_pk().unwrap_or_else(|_| "None".to_string());
        let listen_port = wg_info.listen_port.unwrap_or(0);
        let ip = self.as_ref().lock().await.get_ip_by_name(name).await?.join(",");
        debug!("{} get_namespace_detail pk: {} ip: {} port: {}", name, pubkey, ip, listen_port);
        Ok(WgNamespaceDetail::new(name.to_string(), pubkey, listen_port as i32, 0, ip))
    }

    async fn get_interface_stats(&self, name: &str) -> Result<InterfaceStats, std::io::Error> {
        self.as_ref().lock().await.get_if_stats_by_name(name).await
    }

    async fn get_all_users(&self, namespace: &str) -> Result<Vec<WgPeer>, std::io::Error> {
        let namespace_clone = namespace.to_string();
        let wgd = collect_wireguard_info(&namespace_clone).unwrap();
        Ok(wgd.get_users().unwrap_or_default().iter().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip_with_mask_valid() {
        let client = NetworkConfClient::new_without_handle();

        let result = client.parse_ip_with_mask("192.168.1.1/24");
        assert!(result.is_ok());

        let (ip, prefix) = result.unwrap();
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_parse_ip_with_mask_invalid() {
        let client = NetworkConfClient::new_without_handle();

        let result = client.parse_ip_with_mask("192.168.1.1");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_parse_ip_with_mask_invalid_prefix() {
        let client = NetworkConfClient::new_without_handle();

        let result = client.parse_ip_with_mask("192.168.1.1/abc");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_parse_ip_with_mask_edge_cases() {
        let client = NetworkConfClient::new_without_handle();

        // Test with IPv6 notation
        let result = client.parse_ip_with_mask("2001:db8::1/64");
        assert!(result.is_ok());
        let (ip, prefix) = result.unwrap();
        assert_eq!(ip, "2001:db8::1");
        assert_eq!(prefix, 64);

        // Test with zero prefix
        let result = client.parse_ip_with_mask("0.0.0.0/0");
        assert!(result.is_ok());
        let (ip, prefix) = result.unwrap();
        assert_eq!(ip, "0.0.0.0");
        assert_eq!(prefix, 0);

        // Test with maximum prefix
        let result = client.parse_ip_with_mask("192.168.1.1/32");
        assert!(result.is_ok());
        let (ip, prefix) = result.unwrap();
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(prefix, 32);
    }

    #[tokio::test]
    async fn test_network_conf_client_create_interface() {
        let client = NetworkConfClient::new();

        // Test interface creation
        let result = client.create_wg_interface(
            "test_wg0".to_string(),
            "10.0.0.1/24".to_string()
        ).await;

        // We expect this to fail in test environment without root privileges
        assert!(result.is_err());
    }

    struct MockNetApiHandler {
        client: Arc<Mutex<NetworkConfClient>>,
    }

    impl AsRef<Arc<Mutex<NetworkConfClient>>> for MockNetApiHandler {
        fn as_ref(&self) -> &Arc<Mutex<NetworkConfClient>> {
            &self.client
        }
    }

    #[tokio::test]
    async fn test_net_api_handler() {
        let client = Arc::new(Mutex::new(NetworkConfClient::new()));
        let handler = MockNetApiHandler { client };

        // Test get_interface_index
        let result = handler.get_interface_index("lo").await;
        assert!(result.is_ok()); // loopback interface should always exist
    }

    #[test]
    fn test_ip_route_entry_creation() {
        let entry = IpRouteEntry::new(
            "192.168.1.0/24".to_string(),
            Some("eth0".to_string()),
            Some("192.168.1.1".to_string()),
            Some(254),
            Some(100)
        );

        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.destination, "192.168.1.0/24");
        assert_eq!(entry.interface, Some("eth0".to_string()));
        assert_eq!(entry.gateway, Some("192.168.1.1".to_string()));
        assert_eq!(entry.table, Some(254));
        assert_eq!(entry.metric, Some(100));
    }

    #[test]
    fn test_ip_route_entry_minimal() {
        let entry = IpRouteEntry::new("0.0.0.0/0".to_string(), None, None, None, None);

        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.destination, "0.0.0.0/0");
        assert_eq!(entry.interface, None);
        assert_eq!(entry.gateway, None);
        assert_eq!(entry.table, None);
        assert_eq!(entry.metric, None);
    }

    #[test]
    fn test_fwmark_creation() {
        let fwmark = FwMark {
            mark: 100,
            mask: Some(0xff),
        };

        assert_eq!(fwmark.mark, 100);
        assert_eq!(fwmark.mask, Some(0xff));
    }

    #[test]
    fn test_fwmark_without_mask() {
        let fwmark = FwMark {
            mark: 42,
            mask: None,
        };

        assert_eq!(fwmark.mark, 42);
        assert_eq!(fwmark.mask, None);
    }

    #[test]
    fn test_vrf_params_creation() {
        let vrf_params = VrfParams {
            table: Some(254),
        };

        assert_eq!(vrf_params.table, Some(254));
    }

    #[test]
    fn test_vrf_params_default() {
        let vrf_params = VrfParams {
            table: None,
        };

        assert_eq!(vrf_params.table, None);
    }

    #[tokio::test]
    #[ignore] // Use #[ignore] for tests that require special setup
    async fn test_get_interface_index_nonexistent() {
        let client = NetworkConfClient::new();
        let result = client.get_if_index_by_name("nonexistent_interface_12345").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_loopback_interface() {
        let client = NetworkConfClient::new();

        // Test that loopback interface exists
        let result = client.get_if_index_by_name("lo").await;
        assert!(result.is_ok());

        // Test getting IP addresses for loopback
        let ip_result = client.get_ip_by_name("lo").await;
        assert!(ip_result.is_ok());
        let ips = ip_result.unwrap();
        assert!(!ips.is_empty());

        // Test getting stats for loopback
        let stats_result = client.get_if_stats_by_name("lo").await;
        assert!(stats_result.is_ok());
        let stats = stats_result.unwrap();
        assert_eq!(stats.name, Some("lo".to_string()));
    }

    #[test]
    #[ignore] // Requires network access
    fn test_real_client_parse_ip_with_mask() {
        let client = NetworkConfClient::new();

        let result = client.parse_ip_with_mask("10.0.0.1/16");
        assert!(result.is_ok());

        let (ip, prefix) = result.unwrap();
        assert_eq!(ip, "10.0.0.1");
        assert_eq!(prefix, 16);
    }

    // Test constants and static values
    #[test]
    fn test_constants() {
        assert_eq!(IPTABLE_TABLE, "mangle");
        assert_eq!(IPTABLE_CHAIN, "PREROUTING");
        assert_eq!(IPTABLE_FILTER_TABLE, "filter");
        assert_eq!(IPTABLE_FORWARD_CHAIN, "FORWARD");
        assert_eq!(WG_PERSISTENCE_KEEPALIVE_INTERVAL, 15);
    }

    // Test struct cloning
    #[test]
    fn test_struct_cloning() {
        let fwmark = FwMark {
            mark: 100,
            mask: Some(0xff),
        };

        let cloned_fwmark = fwmark.clone();
        assert_eq!(fwmark.mark, cloned_fwmark.mark);
        assert_eq!(fwmark.mask, cloned_fwmark.mask);

        let vrf_params = VrfParams {
            table: Some(254),
        };

        let cloned_vrf = vrf_params.clone();
        assert_eq!(vrf_params.table, cloned_vrf.table);
    }
}
