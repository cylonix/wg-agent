// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

use iptables::{ self };
use log::{ debug, error, info, warn };
use rtnetlink::{ new_connection, Handle, IpVersion, LinkVxlan, LinkWireguard };
use netlink_packet_route::AddressFamily;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::address::AddressMessage;
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::link::LinkFlags;
use netlink_packet_route::link::LinkMessage;
use netlink_packet_route::rule::RuleAttribute;
use netlink_packet_route::route::{
    RouteMessage,
    RouteHeader,
    RouteAttribute,
    RouteAddress,
    RouteProtocol,
    RouteScope,
    RouteType,
    RouteFlags,
};
use futures::stream::TryStreamExt;
use std::io::{ Error, ErrorKind };
use std::net::{ IpAddr, Ipv4Addr };
use std::str::FromStr;
use std::sync::{ Arc, Mutex };
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
    handle: Handle,
    iptable: iptables::IPTables,
    rt: tokio::runtime::Runtime,
}

impl NetworkConfClient {
    pub fn new() -> Self {
        let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        let (connection, handle, _) = new_connection().unwrap();

        // Spawn the connection in the background
        rt.spawn(connection);

        NetworkConfClient {
            handle,
            iptable: iptables::new(false).unwrap(),
            rt,
        }
    }

    pub fn move_interface_to_vrf(&mut self, if_index: u32, vrf_index: u32) -> Result<(), Error> {
        self.rt.block_on(async {
            // Get the current link message first
            let mut links = self.handle.link().get().match_index(if_index).execute();

            if
                let Some(mut link) = links
                    .try_next().await
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
            {
                // Modify the link to set the controller/master
                link.attributes.push(LinkAttribute::Controller(vrf_index));

                self.handle
                    .link()
                    .set(link)
                    .execute().await
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
            } else {
                Err(Error::new(ErrorKind::NotFound, "Interface not found"))
            }
        })
    }

    pub fn get_if_index_by_name(&mut self, name: &str) -> Result<u32, Error> {
        self.rt.block_on(async {
            let mut links = self.handle.link().get().match_name(name.to_string()).execute();

            match links.try_next().await {
                Ok(Some(link)) => Ok(link.header.index),
                Ok(None) =>
                    Err(Error::new(ErrorKind::NotFound, format!("Interface {} not found", name))),
                Err(e) => Err(Error::new(ErrorKind::Other, e.to_string())),
            }
        })
    }

    pub fn get_if_stats_by_name(&mut self, name: &str) -> Result<InterfaceStats, Error> {
        self.rt.block_on(async {
            let mut links = self.handle.link().get().match_name(name.to_string()).execute();

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
        })
    }

    pub fn get_ip_by_name(&mut self, name: &str) -> Result<Vec<String>, Error> {
        // Clone the name to avoid borrowing issues
        let name_clone = name.to_string();

        // Get interface index first outside the async block
        let if_index = self.get_if_index_by_name(&name_clone)?;

        self.rt.block_on(async {
            // Then get addresses for this interface
            let mut addresses = self.handle
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
                // Parse the address from the message
                if let Some(ip_str) = self.parse_address_from_message(&addr) {
                    ips.push(ip_str);
                }
            }

            Ok(ips)
        })
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

    pub fn create_vrf_interface(&mut self, name: String, _table_id: u32) -> std::io::Result<u32> {
        let name_clone = name.clone();

        self.rt.block_on(async {
            // Create LinkMessage for VRF interface
            let mut link_msg = LinkMessage::default();
            link_msg.header.interface_family = AddressFamily::Unspec;
            link_msg.attributes.push(LinkAttribute::IfName(name.clone()));

            // Create VRF interface using rtnetlink
            match self.handle.link().add(link_msg).execute().await {
                Ok(_) => {
                    info!("Successfully created VRF interface {}", name);
                }
                Err(e) if e.to_string().contains("exists") => {
                    warn!("VRF interface {} already exists", name);
                }
                Err(e) => {
                    return Err(Error::new(ErrorKind::Other, e.to_string()));
                }
            }

            Ok(())
        })?;

        // Get the interface index outside the async block
        let if_index = self.get_if_index_by_name(&name_clone)?;

        // Set interface up
        self.rt.block_on(async {
            // Get the current link message first
            let mut links = self.handle.link().get().match_index(if_index).execute();

            if
                let Some(mut link) = links
                    .try_next().await
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
            {
                // Set the interface state to up
                link.header.flags.insert(LinkFlags::Up);

                self.handle
                    .link()
                    .set(link)
                    .execute().await
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
            } else {
                Err(Error::new(ErrorKind::NotFound, "Interface not found"))
            }
        })?;

        Ok(if_index)
    }

    pub fn create_wg_interface(
        &mut self,
        link_name: String,
        ip_with_mask: String
    ) -> std::io::Result<u32> {
        let link_name_clone = link_name.clone();

        self.rt.block_on(async {
            // Use the LinkWireguard builder directly
            let create_result = self.handle
                .link()
                .add(LinkWireguard::new(&link_name_clone).build())
                .execute()
                .await;

            match create_result {
                Ok(_) => {
                    info!("Successfully created WireGuard interface {}", link_name);
                }
                Err(e) if e.to_string().contains("exists") => {
                    info!("WireGuard interface {} already exists", link_name);
                }
                Err(e) => {
                    return Err(Error::new(ErrorKind::Other, e.to_string()));
                }
            }

            Ok::<(), Error>(())
        })?;

        // Get interface index and configure it
        let if_index = self.get_if_index_by_name(&link_name_clone)?;
        self.configure_interface_ip_and_up(if_index, &ip_with_mask)?;

        Ok(if_index)
    }

    pub fn create_vxlan_interface(
        &mut self,
        link_name: String,
        ip_with_mask: String,
        vid: u32,
        remote: String,
        dstport: u16
    ) -> std::io::Result<u32> {
        let remote_ip = Ipv4Addr::from_str(&remote).map_err(|e|
            Error::new(ErrorKind::InvalidData, e.to_string())
        )?;
        let link_name_clone = link_name.clone();

        self.rt.block_on(async {
            // Use the LinkVxlan builder directly
            let create_result = self.handle
                .link()
                .add(LinkVxlan::new(&link_name_clone, vid)
                    .remote(remote_ip)
                    .port(dstport)
                    .up()
                    .build())
                .execute()
                .await;

            match create_result {
                Ok(_) => {
                    info!("Successfully created VXLAN interface {}", link_name);
                }
                Err(e) if e.to_string().contains("exists") => {
                    info!("VXLAN interface {} already exists", link_name);
                }
                Err(e) => {
                    return Err(Error::new(ErrorKind::Other, e.to_string()));
                }
            }

            Ok::<(), Error>(())
        })?;

        // Get interface index and configure it
        let if_index = self.get_if_index_by_name(&link_name_clone)?;
        self.configure_interface_ip_and_up(if_index, &ip_with_mask)?;

        Ok(if_index)
    }

    // Helper method to avoid code duplication
    fn configure_interface_ip_and_up(&mut self, if_index: u32, ip_with_mask: &str) -> std::io::Result<()> {
        // Add IP address
        let (addr_str, prefix_len) = self.parse_ip_with_mask(ip_with_mask)?;
        let ip_addr = IpAddr::from_str(&addr_str).map_err(|e|
            Error::new(ErrorKind::InvalidData, e.to_string())
        )?;

        self.rt.block_on(async {
            // Add IP address
            self.handle
                .address()
                .add(if_index, ip_addr, prefix_len)
                .execute()
                .await
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

            // Set interface up
            let mut links = self.handle
                .link()
                .get()
                .match_index(if_index)
                .execute();

            if let Some(mut link) = links
                .try_next().await
                .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
            {
                link.header.flags.insert(LinkFlags::Up);

                self.handle
                    .link()
                    .set(link)
                    .execute()
                    .await
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;
            }

            Ok::<(), Error>(())
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

    fn delete_interface(&mut self, link_name: String) -> std::io::Result<()> {
        debug!("Try to delete interface {}", link_name);

        // Get interface index outside async block
        let if_index = match self.get_if_index_by_name(&link_name) {
            Ok(index) => index,
            Err(_) => {
                error!("Cannot delete the interface {}, not found", link_name);
                return Err(Error::new(ErrorKind::NotFound, "Interface not found"));
            }
        };

        self.rt.block_on(async {
            match self.handle.link().del(if_index).execute().await {
                Ok(_) => {
                    debug!("Delete interface {} successfully.", link_name);
                    Ok(())
                }
                Err(e) => {
                    error!("Cannot delete the interface {}, reason {}", link_name, e);
                    Err(Error::new(ErrorKind::Other, e.to_string()))
                }
            }
        })
    }

    pub fn delete_wg_interface(&mut self, link_name: String) -> std::io::Result<()> {
        self.delete_interface(link_name)
    }

    pub fn delete_vxlan_interface(&mut self, link_name: String) -> std::io::Result<()> {
        self.delete_interface(link_name)
    }

    pub fn delete_vrf_interface(&mut self, link_name: String) -> std::io::Result<()> {
        self.delete_interface(link_name)
    }

    pub fn add_del_ip_rule(
        &mut self,
        add: bool,
        fwmark: Option<u32>,
        _fwmask: Option<u32>,
        table: u32,
        priority: u32,
        _flags: Option<u32>,
        _suppress_prefixlength: Option<u32>
    ) -> std::io::Result<()> {
        self.rt.block_on(async {
            let result = if add {
                let mut request = self.handle
                    .rule()
                    .add()
                    .table_id(table)
                    .priority(priority);

                // Add fwmark to rule if specified
                if let Some(mark) = fwmark {
                    request = request.fw_mark(mark);
                }

                request.execute().await
            } else {
                // For delete, get existing rules and find the matching one
                let mut rules = self.handle.rule().get(IpVersion::V4).execute();

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
        })
    }

    pub fn delete_ip_fwmark_rule(&mut self, fwmark: u32) -> std::io::Result<()> {
        self.rt.block_on(async {
            // Get all rules and find the one with matching fwmark
            let mut rules = self.handle.rule().get(IpVersion::V4).execute();

            while
                let Some(rule) = rules
                    .try_next().await
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
            {
                // Check if this rule has the matching fwmark
                let mut found_match = false;

                for attr in &rule.attributes {
                    match attr {
                        RuleAttribute::FwMark(mark) => {
                            if *mark == fwmark {
                                found_match = true;
                                break;
                            }
                        }
                        _ => {}
                    }
                }

                if found_match {
                    // Delete this rule using the original rule message
                    return self.handle
                        .rule()
                        .del(rule)
                        .execute().await
                        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()));
                }
            }

            // No rule found with matching fwmark
            Err(Error::new(ErrorKind::NotFound, format!("No rule found with fwmark {}", fwmark)))
        })
    }

    pub fn create_fwmark_entry(
        &mut self,
        src_intf: String,
        src_ip: String,
        fwmark: u32
    ) -> std::io::Result<()> {
        let filter = format!("-i {} -s {} -j MARK --set-mark {}", src_intf, src_ip, fwmark);

        self.iptable.append_unique(IPTABLE_TABLE, IPTABLE_CHAIN, &filter).map_err(|e| {
            let err_string = e.to_string();
            if err_string.contains("exists") {
                Error::new(ErrorKind::AlreadyExists, err_string)
            } else {
                Error::new(ErrorKind::InvalidData, err_string)
            }
        })
    }

    pub fn delete_fwmark_entry(
        &mut self,
        src_intf: String,
        src_ip: String,
        fwmark: u32
    ) -> std::io::Result<()> {
        let filter = format!("-i {} -s {} -j MARK --set-mark {}", src_intf, src_ip, fwmark);

        self.iptable
            .delete(IPTABLE_TABLE, IPTABLE_CHAIN, &filter)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
    }

    pub fn create_iptable_filter_forward_entry(
        &mut self,
        src_ip: String,
        direction: String
    ) -> std::io::Result<()> {
        let direction_symbol = if direction == "source" { "s" } else { "d" };
        let filter = format!("-{} {} -j ACCEPT", direction_symbol, src_ip);

        self.iptable
            .append_unique(IPTABLE_FILTER_TABLE, IPTABLE_FORWARD_CHAIN, &filter)
            .map_err(|e| {
                let err_string = e.to_string();
                if err_string.contains("exists") {
                    Error::new(ErrorKind::AlreadyExists, err_string)
                } else {
                    Error::new(ErrorKind::InvalidData, err_string)
                }
            })
    }

    pub fn delete_iptable_filter_forward_entry(
        &mut self,
        src_ip: String,
        direction: String
    ) -> std::io::Result<()> {
        let direction_symbol = if direction == "source" { "s" } else { "d" };
        let filter = format!("-{} {} -j ACCEPT", direction_symbol, src_ip);

        self.iptable
            .delete(IPTABLE_FILTER_TABLE, IPTABLE_FORWARD_CHAIN, &filter)
            .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
    }

    pub fn create_route_entry(
        &mut self,
        src_ip: String,
        gateway: Option<String>,
        interface: Option<String>,
        table: Option<u32>
    ) -> std::io::Result<()> {
        let dest_ip = IpAddr::from_str(&src_ip).map_err(|e|
            Error::new(ErrorKind::InvalidInput, e.to_string())
        )?;

        // Get interface index if needed, outside async block to avoid borrowing issues
        let if_index = if let Some(ref iface) = interface {
            Some(self.get_if_index_by_name(iface)?)
        } else {
            None
        };

        self.rt.block_on(async {
            // Create route message for addition
            let mut route_msg = RouteMessage::default();

            // Set route header with all required fields
            route_msg.header = RouteHeader {
                address_family: match dest_ip {
                    IpAddr::V4(_) => AddressFamily::Inet,
                    IpAddr::V6(_) => AddressFamily::Inet6,
                },
                destination_prefix_length: match dest_ip {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                },
                source_prefix_length: 0, // Added missing field
                tos: 0, // Added missing field
                table: table.unwrap_or(libc::RT_TABLE_MAIN as u32) as u8,
                protocol: RouteProtocol::Static,
                scope: RouteScope::Universe,
                kind: RouteType::Unicast,
                flags: RouteFlags::empty(),
            };

            // Add destination attribute
            match dest_ip {
                IpAddr::V4(ip) => {
                    route_msg.attributes.push(
                        RouteAttribute::Destination(RouteAddress::Inet(ip.into()))
                    );
                }
                IpAddr::V6(ip) => {
                    route_msg.attributes.push(
                        RouteAttribute::Destination(RouteAddress::Inet6(ip.into()))
                    );
                }
            }

            // Add gateway if specified
            if let Some(gw) = gateway {
                let gw_ip = IpAddr::from_str(&gw).map_err(|e|
                    Error::new(ErrorKind::InvalidInput, e.to_string())
                )?;

                match gw_ip {
                    IpAddr::V4(ip) => {
                        route_msg.attributes.push(
                            RouteAttribute::Gateway(RouteAddress::Inet(ip.into()))
                        );
                    }
                    IpAddr::V6(ip) => {
                        route_msg.attributes.push(
                            RouteAttribute::Gateway(RouteAddress::Inet6(ip.into()))
                        );
                    }
                }
            }

            // Add output interface if specified
            if let Some(idx) = if_index {
                route_msg.attributes.push(RouteAttribute::Oif(idx));
            }

            // Execute addition
            self.handle
                .route()
                .add(route_msg)
                .execute().await
                .map_err(|e| {
                    let err_string = e.to_string();
                    if err_string.contains("exists") {
                        Error::new(ErrorKind::AlreadyExists, err_string)
                    } else {
                        Error::new(ErrorKind::Other, err_string)
                    }
                })
        })
    }
    pub fn delete_route_entry(
        &mut self,
        src_ip: String,
        gateway: Option<String>,
        interface: Option<String>,
        table: Option<u32>
    ) -> std::io::Result<()> {
        let dest_ip = IpAddr::from_str(&src_ip).map_err(|e|
            Error::new(ErrorKind::InvalidInput, e.to_string())
        )?;

        // Get interface index if needed, outside async block to avoid borrowing issues
        let if_index = if let Some(ref iface) = interface {
            Some(self.get_if_index_by_name(iface)?)
        } else {
            None
        };

        self.rt.block_on(async {
            // Create route message for deletion
            let mut route_msg = RouteMessage::default();

            // Set route header
            route_msg.header = RouteHeader {
                address_family: match dest_ip {
                    IpAddr::V4(_) => AddressFamily::Inet,
                    IpAddr::V6(_) => AddressFamily::Inet6,
                },
                destination_prefix_length: match dest_ip {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                },
                source_prefix_length: 0,  // Added missing field
                tos: 0,                   // Added missing field
                table: table.unwrap_or(libc::RT_TABLE_MAIN as u32) as u8,
                protocol: RouteProtocol::Static,
                scope: RouteScope::Universe,
                kind: RouteType::Unicast,
                flags: RouteFlags::empty(),
            };

            // Add destination attribute
            match dest_ip {
                IpAddr::V4(ip) => {
                    route_msg.attributes.push(
                        RouteAttribute::Destination(RouteAddress::Inet(ip.into()))
                    );
                }
                IpAddr::V6(ip) => {
                    route_msg.attributes.push(
                        RouteAttribute::Destination(RouteAddress::Inet6(ip.into()))
                    );
                }
            }

            // Add gateway if specified
            if let Some(gw) = gateway {
                let gw_ip = IpAddr::from_str(&gw).map_err(|e|
                    Error::new(ErrorKind::InvalidInput, e.to_string())
                )?;

                match gw_ip {
                    IpAddr::V4(ip) => {
                        route_msg.attributes.push(
                            RouteAttribute::Gateway(RouteAddress::Inet(ip.into()))
                        );
                    }
                    IpAddr::V6(ip) => {
                        route_msg.attributes.push(
                            RouteAttribute::Gateway(RouteAddress::Inet6(ip.into()))
                        );
                    }
                }
            }

            // Add output interface if specified
            if let Some(idx) = if_index {
                route_msg.attributes.push(RouteAttribute::Oif(idx));
            }

            // Execute deletion
            self.handle
                .route()
                .del(route_msg)
                .execute().await
                .map_err(|e| {
                    let err_string = e.to_string();
                    if err_string.contains("No such process") || err_string.contains("not found") {
                        Error::new(ErrorKind::NotFound, format!("Route not found: {}", err_string))
                    } else {
                        Error::new(ErrorKind::Other, err_string)
                    }
                })
        })
    }
    pub fn flush_route_table(&mut self, table: Option<u32>) -> std::io::Result<()> {
        self.rt.block_on(async {
            let table_id = table.unwrap_or(libc::RT_TABLE_MAIN as u32);

            // Create route message to filter by table for IPv4
            let mut route_msg_v4 = RouteMessage::default();
            route_msg_v4.header = RouteHeader {
                address_family: AddressFamily::Inet,
                table: table_id as u8,
                ..Default::default()
            };

            // Get IPv4 routes from the specific table
            let mut routes = self.handle.route().get(route_msg_v4).execute();
            let mut routes_to_delete = Vec::new();

            while
                let Some(route) = routes
                    .try_next().await
                    .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?
            {
                // Collect routes from our target table
                if route.header.table == (table_id as u8) {
                    routes_to_delete.push(route);
                }
            }

            // Delete IPv4 routes
            for route in routes_to_delete {
                let _ = self.handle.route().del(route).execute().await;
            }

            // Create route message to filter by table for IPv6
            let mut route_msg_v6 = RouteMessage::default();
            route_msg_v6.header = RouteHeader {
                address_family: AddressFamily::Inet6,
                table: table_id as u8,
                ..Default::default()
            };

            // Get IPv6 routes from the specific table
            let mut routes_v6 = self.handle.route().get(route_msg_v6).execute();
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

            // Delete IPv6 routes
            for route in routes_v6_to_delete {
                let _ = self.handle.route().del(route).execute().await;
            }

            Ok(())
        })
    }
}

pub trait NetApiHandler {
    fn create_wg_interface(
        &self,
        namespace_name: &str,
        ip: &str,
        port: Option<i32>,
        key: &Option<String>
    ) -> Result<(), std::io::Error>;

    fn delete_wg_interface(&self, namespace_name: &str) -> Result<(), std::io::Error>;

    fn create_vxlan_interface(
        &self,
        ip_with_mask: String,
        vid: u32,
        remote: String,
        dstport: u16
    ) -> Result<(), std::io::Error>;

    fn delete_vxlan_interface(&self, if_name: &str) -> Result<(), std::io::Error>;

    fn create_vrf_interface(&self, name: String, table_id: u32) -> Result<u32, std::io::Error>;
    fn delete_vrf_interface(&self, _if_name: &str) -> Result<(), std::io::Error>;

    fn create_fwmark_entry(
        &self,
        intf_name: String,
        src_ip: String,
        fwmark: u32
    ) -> std::io::Result<()>;
    fn delete_fwmark_entry(
        &self,
        intf_name: String,
        src_ip: String,
        fwmark: u32
    ) -> std::io::Result<()>;

    fn create_filter_forward_entry(&self, src_ip: String) -> std::io::Result<()>;
    fn delete_filter_forward_entry(&self, src_ip: String) -> std::io::Result<()>;

    fn create_route_entry(
        &self,
        src_ip: String,
        gateway: Option<String>,
        interface: Option<String>,
        table: Option<u32>
    ) -> std::io::Result<()>;
    fn delete_route_entry(
        &self,
        src_ip: String,
        gateway: Option<String>,
        interface: Option<String>,
        table: Option<u32>
    ) -> std::io::Result<()>;

    fn add_del_ip_rule(
        &self,
        add: bool,
        fwmark: Option<u32>,
        fwmask: Option<u32>,
        table: u32,
        priority: u32,
        flags: Option<u32>,
        suppress_prefixlength: Option<u32>
    ) -> std::io::Result<()>;
    fn delete_ip_fwmark_rule(&self, fwmark: u32) -> std::io::Result<()>;

    fn create_wireguard_peer(
        &self,
        name: &String,
        key: &String,
        allowed_ips: &Option<Vec<String>>
    ) -> Result<(), std::io::Error>;

    fn delete_wg_user(&self, interface_name: &String, key: &String) -> Result<(), std::io::Error>;

    fn get_namespace_detail(&self, name: &str) -> Result<WgNamespaceDetail, std::io::Error>;
    fn get_interface_stats(&self, name: &str) -> Result<InterfaceStats, std::io::Error>;

    fn get_all_users(&self, namespace: &str) -> Result<Vec<WgPeer>, std::io::Error>;

    fn get_interface_index(&self, name: &str) -> Result<u32, std::io::Error>;

    fn move_interface_to_vrf(&self, if_index: u32, vrf_index: u32) -> Result<(), std::io::Error>;
}

impl<T> NetApiHandler for T where T: AsRef<Arc<Mutex<NetworkConfClient>>> {
    fn move_interface_to_vrf(&self, if_index: u32, vrf_index: u32) -> Result<(), std::io::Error> {
        let mut client = self.as_ref().lock().unwrap();
        client.move_interface_to_vrf(if_index, vrf_index)
    }

    fn get_interface_index(&self, name: &str) -> Result<u32, std::io::Error> {
        let mut client = self.as_ref().lock().unwrap();
        client.get_if_index_by_name(name)
    }

    fn create_wg_interface(
        &self,
        namespace_name: &str,
        ip: &str,
        port: Option<i32>,
        key: &Option<String>
    ) -> Result<(), std::io::Error> {
        let network_config_client = self.as_ref();
        network_config_client
            .lock()
            .unwrap()
            .create_wg_interface(String::from(namespace_name), String::from(ip))
            .and_then(|if_index| {
                debug!("Successfully create the wireguard interface, set key, port and sth else");
                set_wireguard_interface(
                    namespace_name,
                    Some(if_index),
                    key.as_ref().map(|k| k.as_str()),
                    port.map(|p| p as u16),
                    None
                )
            })
    }

    fn create_vxlan_interface(
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
        let network_config_client = self.as_ref();
        network_config_client
            .lock()
            .unwrap()
            .create_vxlan_interface(
                "vxlan".to_string(),
                ip_with_mask.clone(),
                vid,
                remote.clone(),
                dstport
            )
            .map_err(|e| {
                warn!(
                    "Cannot create vxlan interface: ipwithmask:{}, vid {}, remote {}, dstport {}, reason: {}",
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

    fn create_vrf_interface(&self, name: String, table_id: u32) -> Result<u32, std::io::Error> {
        debug!("Creating a new vrf interface, name {}, table id {}", name, table_id);
        let network_config_client = self.as_ref();
        network_config_client
            .lock()
            .unwrap()
            .create_vrf_interface(name.clone(), table_id)
            .map_err(|e| {
                warn!(
                    "Cannot create vrf interface: name {}, table id {}, reason: {}",
                    name,
                    table_id,
                    e
                );
                e
            })
            .map(|v| {
                debug!("Successfully create the vrf interface, return vrf id {}", v);
                v
            })
    }

    fn create_fwmark_entry(
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
        let network_config_client = self.as_ref();
        let ret = network_config_client
            .lock()
            .unwrap()
            .create_fwmark_entry(intf_name.clone(), src_ip.clone(), fwmark);

        if let Err(e) = ret {
            warn!(
                "Cannot create the fwmark: interface name{}, source ip: {}, fwmark {}, reason: {}",
                intf_name,
                src_ip,
                fwmark,
                e
            );
            Err(e)
        } else {
            Ok(())
        }
    }

    fn create_filter_forward_entry(&self, src_ip: String) -> std::io::Result<()> {
        debug!("Creating the iptables filter forward entry, source ip {}", src_ip);

        let network_config_client = self.as_ref();
        let ret = network_config_client
            .lock()
            .unwrap()
            .create_iptable_filter_forward_entry(src_ip.clone(), "source".to_string());

        if let Err(e) = ret {
            warn!("Cannot create forward accept: source ip: {}, reason: {}", src_ip, e);
            return Err(e);
        }

        let ret = network_config_client
            .lock()
            .unwrap()
            .create_iptable_filter_forward_entry(src_ip.clone(), "destination".to_string());

        if let Err(e) = ret {
            warn!("Cannot create forward accept: destination ip: {}, reason: {}", src_ip, e);
            return Err(e);
        }

        Ok(())
    }

    fn delete_filter_forward_entry(&self, src_ip: String) -> std::io::Result<()> {
        debug!("Delete an existing iptables forward entry, source ip {}", src_ip);

        let network_config_client = self.as_ref();

        let ret = network_config_client
            .lock()
            .unwrap()
            .delete_iptable_filter_forward_entry(src_ip.clone(), "source".to_string());

        if let Err(e) = ret {
            warn!("Cannot delete the forward source entry, source ip {}", src_ip);
            return Err(e);
        }

        let ret = network_config_client
            .lock()
            .unwrap()
            .delete_iptable_filter_forward_entry(src_ip.clone(), "destination".to_string());

        if let Err(e) = ret {
            warn!("Cannot delete the forward destination entry, destination ip {}", src_ip);
            return Err(e);
        }
        Ok(())
    }

    fn delete_fwmark_entry(
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
        let network_config_client = self.as_ref();
        network_config_client
            .lock()
            .unwrap()
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

    fn add_del_ip_rule(
        &self,
        add: bool,
        fwmark: Option<u32>,
        fwmask: Option<u32>,
        table: u32,
        priority: u32,
        flags: Option<u32>,
        suppress_prefixlength: Option<u32>
    ) -> std::io::Result<()> {
        debug!(
            "add/del the ip rules entry: add {}, fwmark {:?}, table {}, priority {}",
            add,
            fwmark,
            table,
            priority
        );
        let network_config_client = self.as_ref();
        network_config_client
            .lock()
            .unwrap()
            .add_del_ip_rule(add, fwmark, fwmask, table, priority, flags, suppress_prefixlength)
    }

    fn delete_ip_fwmark_rule(&self, fwmark: u32) -> std::io::Result<()> {
        debug!("Deleting the ip rules entry: fwmark {}", fwmark);
        let network_config_client = self.as_ref();
        network_config_client.lock().unwrap().delete_ip_fwmark_rule(fwmark)
    }

    fn create_route_entry(
        &self,
        src_ip: String,
        gateway: Option<String>,
        interface: Option<String>,
        table: Option<u32>
    ) -> std::io::Result<()> {
        debug!(
            "Creating an route entry, dst ip {}, gateway {:?}, interface {:?}, table{:?}",
            src_ip,
            gateway,
            interface,
            table
        );
        let network_config_client = self.as_ref();
        let ret = network_config_client
            .lock()
            .unwrap()
            .create_route_entry(src_ip.clone(), gateway.clone(), interface.clone(), table);

        ret.map_err(|e| {
            warn!(
                "Cannot create route entry: src_ip {:?}, gateway {:?}, interface{:?}, table{:?}, reason : {}",
                src_ip,
                gateway,
                interface,
                table,
                e
            );
            e
        })
    }

    fn delete_route_entry(
        &self,
        src_ip: String,
        gateway: Option<String>,
        interface: Option<String>,
        table: Option<u32>
    ) -> std::io::Result<()> {
        debug!(
            "Deleting an route entry, dst ip {}, gateway {:?}, interface {:?}, table{:?}",
            src_ip,
            gateway,
            interface,
            table
        );
        let network_config_client = self.as_ref();
        network_config_client
            .lock()
            .unwrap()
            .delete_route_entry(src_ip.clone(), gateway.clone(), interface.clone(), table)
            .map_err(|e| {
                warn!(
                    "Cannot delete an route entry, dst ip {}, gateway {:?}, interface {:?}, table{:?}, reason: {}",
                    src_ip,
                    gateway,
                    interface,
                    table,
                    e
                );
                e
            })
    }

    fn delete_wg_interface(&self, namespace_name: &str) -> Result<(), std::io::Error> {
        debug!("Deleting an wireguard interface, interface name {}", namespace_name);
        let network_config_client = self.as_ref();
        network_config_client
            .lock()
            .unwrap()
            .delete_wg_interface(String::from(namespace_name))
            .map_err(|e| {
                warn!(
                    "Cannot delete an wireguard interface, interface name {}, reason {}",
                    namespace_name,
                    e
                );
                e
            })
    }

    fn delete_vxlan_interface(&self, if_name: &str) -> Result<(), std::io::Error> {
        debug!("Deleting an vxlan interface, interface name {}", if_name);
        let network_config_client = self.as_ref();
        network_config_client
            .lock()
            .unwrap()
            .delete_vxlan_interface(String::from(if_name))
            .map_err(|e| {
                warn!("Cannot delete an vxlan interface, interface name {}, reason {}", if_name, e);
                e
            })
    }

    fn delete_vrf_interface(&self, if_name: &str) -> Result<(), std::io::Error> {
        debug!("Deleting an vrf interface, interface name {}", if_name);
        let network_config_client = self.as_ref();
        network_config_client
            .lock()
            .unwrap()
            .delete_vrf_interface(String::from(if_name))
            .map_err(|e| {
                warn!("Cannot delete an vrf interface, interface name {}, reason {}", if_name, e);
                e
            })
    }

    fn create_wireguard_peer(
        &self,
        name: &String,
        key: &String,
        allowed_ips: &Option<Vec<String>>
    ) -> Result<(), std::io::Error> {
        debug!("Creating wireguard peer for {}/{}", name, key);
        let network_config_client = self.as_ref();
        let ret = network_config_client
            .lock()
            .unwrap()
            .get_if_index_by_name(name)
            .and_then(|ifindex| {
                allowed_ips.as_ref().map_or_else(
                    || {
                        warn!("Allow ip cannot be empty.");
                        Err(
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "allow ip cannot be empty"
                            )
                        )
                    },
                    |ips| {
                        debug!("allowed ips is ok, create it in wireguard module");
                        let ips_slice: Vec<&str> = ips
                            .iter()
                            .map(|a| a.as_str())
                            .collect();
                        let wireguard_create_ret = add_wireguard_peer(
                            name.as_str(),
                            None,
                            Some(ifindex),
                            Some(WG_PERSISTENCE_KEEPALIVE_INTERVAL),
                            ips_slice.as_slice(),
                            key
                        );
                        wireguard_create_ret
                    }
                )
            });
        ret
    }

    fn delete_wg_user(&self, interface_name: &String, key: &String) -> Result<(), std::io::Error> {
        let network_config_client = self.as_ref();
        let _result = network_config_client
            .lock()
            .unwrap()
            .get_if_index_by_name(interface_name)
            .and_then(|ifindex|
                remove_wirefguard_peer(interface_name.as_str(), Some(ifindex), key)
            );
        Ok(())
    }

    fn get_namespace_detail(&self, name: &str) -> Result<WgNamespaceDetail, std::io::Error> {
        let network_config_client = self.as_ref();
        collect_wireguard_info(name).map_or_else(
            |e| { Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())) },
            |wd| {
                let pubkey = wd.get_base64_from_pk().unwrap_or_else(|_| "None".to_string());
                let listen_port = wd.listen_port.unwrap_or(0);

                let ip = network_config_client
                    .lock()
                    .map(|mut c| {
                        c.get_ip_by_name(name)
                            .unwrap_or_else(|_| vec!["0.0.0.0".to_string()])
                            .join(",")
                    })
                    .unwrap_or_else(|_| "0.0.0.0/0".to_string());

                debug!(
                    "{} get_namespace_detail pk: {} ip: {} port: {}",
                    name,
                    pubkey,
                    ip,
                    listen_port
                );
                Ok(WgNamespaceDetail::new(name.to_string(), pubkey, listen_port as i32, 0, ip)) // Fixed: convert to i32
            }
        )
    }

    fn get_interface_stats(&self, interface_name: &str) -> Result<InterfaceStats, std::io::Error> {
        let network_config_client = self.as_ref();
        network_config_client.lock().unwrap().get_if_stats_by_name(interface_name)
    }

    fn get_all_users(&self, namespace: &str) -> Result<Vec<WgPeer>, std::io::Error> {
        let wgd = collect_wireguard_info(namespace)?;
        let mut ret = Vec::new();

        if let Some(peers) = wgd.get_users() {
            for peer in peers.iter() {
                ret.push(peer.clone());
            }
        }

        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A simple mock client for pure unit tests that don't need networking
    struct MockNetworkConfClient;

    impl MockNetworkConfClient {
        fn new() -> Self {
            MockNetworkConfClient
        }

        fn parse_ip_with_mask(&self, ip_with_mask: &str) -> Result<(String, u8), Error> {
            let parts: Vec<&str> = ip_with_mask.trim().split('/').collect();
            if parts.len() != 2 {
                return Err(Error::new(ErrorKind::InvalidInput, "Invalid IP/mask format"));
            }

            let prefix_len = parts[1]
                .parse::<u8>()
                .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?;

            Ok((parts[0].to_string(), prefix_len))
        }
    }

    // Helper function to create a test client for non-networking tests
    fn create_mock_client() -> MockNetworkConfClient {
        MockNetworkConfClient::new()
    }

    #[test]
    fn test_parse_ip_with_mask_valid() {
        let client = create_mock_client();

        let result = client.parse_ip_with_mask("192.168.1.1/24");
        assert!(result.is_ok());

        let (ip, prefix) = result.unwrap();
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_parse_ip_with_mask_invalid() {
        let client = create_mock_client();

        let result = client.parse_ip_with_mask("192.168.1.1");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_parse_ip_with_mask_invalid_prefix() {
        let client = create_mock_client();

        let result = client.parse_ip_with_mask("192.168.1.1/abc");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_parse_ip_with_mask_edge_cases() {
        let client = create_mock_client();

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

        // Test invalid prefix range
        let result = client.parse_ip_with_mask("192.168.1.1/33");
        assert!(result.is_ok()); // Note: This test only checks parsing, not IP validation

        // Test empty string
        let result = client.parse_ip_with_mask("");
        assert!(result.is_err());

        // Test with whitespace
        let result = client.parse_ip_with_mask("  192.168.1.1/24  ");
        assert!(result.is_ok());
        let (ip, prefix) = result.unwrap();
        assert_eq!(ip, "192.168.1.1");
        assert_eq!(prefix, 24);
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
        let entry = IpRouteEntry::new(
            "0.0.0.0/0".to_string(),
            None,
            None,
            None,
            None
        );

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

    // Tests that require actual networking (use tokio::test and ignore by default)
    #[tokio::test]
    #[ignore] // Use #[ignore] for tests that require special setup
    async fn test_get_interface_index_nonexistent() {
        let mut client = NetworkConfClient::new();
        let result = client.get_if_index_by_name("nonexistent_interface_12345");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_loopback_interface() {
        let mut client = NetworkConfClient::new();

        // Test that loopback interface exists
        let result = client.get_if_index_by_name("lo");
        assert!(result.is_ok());

        // Test getting IP addresses for loopback
        let ip_result = client.get_ip_by_name("lo");
        assert!(ip_result.is_ok());
        let ips = ip_result.unwrap();
        assert!(!ips.is_empty());

        // Test getting stats for loopback
        let stats_result = client.get_if_stats_by_name("lo");
        assert!(stats_result.is_ok());
        let stats = stats_result.unwrap();
        assert_eq!(stats.name, Some("lo".to_string()));
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_real_client_parse_ip_with_mask() {
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