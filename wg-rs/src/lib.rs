// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

extern crate wg_sys;

use base64::{Engine as _, engine::general_purpose};
use cidr_utils::cidr::{IpCidr, Ipv4Cidr};
use log::{debug, error, info};
use rand::random;
use rtnetlink::{new_connection, Handle};
use netlink_packet_route::link::LinkMessage;
use netlink_packet_route::address::AddressMessage;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::AddressFamily;
use futures::stream::TryStreamExt;
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, SocketAddrV4, Ipv4Addr};
use std::os::raw::c_char;
use std::str::FromStr;
use std::string::String;
use std::sync::Arc;
use tokio::sync::Mutex;
use wg_sys::{
    in_addr, ipc_set_device, sockaddr_in, timespec64, wg_peer_flag_, wgallowedip,
    wgallowedip__bindgen_ty_1, wgdevice, wgdevice_flag_, wgpeer, wgpeer__bindgen_ty_1,
};

#[derive(Debug)]
pub struct WgDevices {
    devices: Vec<String>,
}

impl WgDevices {
    pub fn new() -> Self {
        let mut ret: Vec<String> = Vec::new();
        // Invoke the c bindings and get the contents
        let interface_slice = unsafe {
            let interfaces: *mut c_char = wg_sys::ipc_list_devices();
            let mut index = 0;
            loop {
                if *interfaces.offset(index) == 0 as c_char {
                    if index == 0 {
                        break;
                    }
                    // Try to read one more to see if there any strings
                    if *interfaces.offset(index + 1) == 0 as c_char {
                        break;
                    }
                }
                index += 1;
            }
            index += 1;
            // copy it to a slice
            let mut dst = Vec::with_capacity(index as usize);
            std::ptr::copy(interfaces, dst.as_mut_ptr(), index as usize);
            dst.set_len(index as usize);

            // free the interfaces
            libc::free(interfaces as *mut libc::c_void);
            dst
        };
        // now we back into the safe world
        let mut index = 0;
        let str_index = interface_slice
            .iter()
            .filter_map(|&char| {
                index += 1;
                if char == 0 {
                    return Some(index - 1);
                }
                return None;
            })
            .collect::<Vec<_>>();

        let mut start = 0;
        for i in str_index {
            let x = (start..i)
                .map(|i| interface_slice[i] as u8)
                .collect::<Vec<_>>();
            ret.push(String::from_utf8(x).unwrap());
            start = i + 1;
        }

        WgDevices { devices: ret }
    }

    pub fn get_devices(&self) -> &Vec<String> {
        &self.devices
    }
}

// Modern netlink interface manager - using Arc<Mutex<Handle>> to make it cloneable
#[derive(Clone, Debug)]
pub struct NetlinkManager {
    handle: Arc<Mutex<Handle>>,
}

impl NetlinkManager {
    pub fn new() -> Result<Self, Error> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to create tokio runtime: {}", e)))?;
        
        let (connection, handle, _) = new_connection()
            .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to create netlink connection: {}", e)))?;
        
        // Spawn the connection in the background
        rt.spawn(connection);
        
        Ok(NetlinkManager {
            handle: Arc::new(Mutex::new(handle)),
        })
    }

    pub async fn get_interface_index(&self, name: &str) -> Result<u32, Error> {
        let handle = self.handle.lock().await;
        let mut links = handle.link().get().match_name(name.to_string()).execute();
        
        match links.try_next().await {
            Ok(Some(link)) => Ok(link.header.index),
            Ok(None) => Err(Error::new(
                ErrorKind::NotFound,
                format!("Interface {} not found", name),
            )),
            Err(e) => Err(Error::new(ErrorKind::Other, e.to_string())),
        }
    }

    pub fn get_interface_index_sync(&self, name: &str) -> Result<u32, Error> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to create tokio runtime: {}", e)))?;
        
        rt.block_on(self.get_interface_index(name))
    }

    pub async fn get_interface_info(&self, name: &str) -> Result<LinkMessage, Error> {
        let handle = self.handle.lock().await;
        let mut links = handle.link().get().match_name(name.to_string()).execute();
        
        match links.try_next().await {
            Ok(Some(link)) => Ok(link),
            Ok(None) => Err(Error::new(
                ErrorKind::NotFound,
                format!("Interface {} not found", name),
            )),
            Err(e) => Err(Error::new(ErrorKind::Other, e.to_string())),
        }
    }

    pub fn interface_exists(&self, name: &str) -> bool {
        self.get_interface_index_sync(name).is_ok()
    }

    pub async fn create_wireguard_interface(&self, name: &str) -> Result<u32, Error> {
        let handle = self.handle.lock().await;
        // Try to create the wireguard interface
        let create_result = handle
            .link()
            .add()
            .name(name.to_string())
            .execute()
            .await;

        match create_result {
            Ok(_) => {
                info!("Successfully created wireguard interface {}", name);
            }
            Err(e) if e.to_string().contains("exists") => {
                debug!("Wireguard interface {} already exists", name);
            }
            Err(e) => {
                return Err(Error::new(ErrorKind::Other, e.to_string()));
            }
        }

        // Get the interface index
        drop(handle); // Release the lock before calling other methods
        self.get_interface_index(name).await
    }

    pub async fn set_interface_up(&self, name: &str) -> Result<(), Error> {
        let if_index = self.get_interface_index(name).await?;
        let handle = self.handle.lock().await;
        
        handle
            .link()
            .set(if_index)
            .up()
            .execute()
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
    }

    pub async fn set_interface_down(&self, name: &str) -> Result<(), Error> {
        let if_index = self.get_interface_index(name).await?;
        let handle = self.handle.lock().await;
        
        handle
            .link()
            .set(if_index)
            .down()
            .execute()
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
    }

    pub async fn delete_interface(&self, name: &str) -> Result<(), Error> {
        let if_index = self.get_interface_index(name).await?;
        let handle = self.handle.lock().await;
        
        handle
            .link()
            .del(if_index)
            .execute()
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
    }

    pub async fn add_ip_address(&self, name: &str, ip: IpAddr, prefix_len: u8) -> Result<(), Error> {
        let if_index = self.get_interface_index(name).await?;
        let handle = self.handle.lock().await;
        
        handle
            .address()
            .add(if_index, ip, prefix_len)
            .execute()
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
    }

    pub async fn get_ip_addresses(&self, name: &str) -> Result<Vec<String>, Error> {
        let if_index = self.get_interface_index(name).await?;
        let handle = self.handle.lock().await;
        
        let mut addresses = handle
            .address()
            .get()
            .set_link_index_filter(if_index)
            .execute();
        
        let mut ips = Vec::new();
        while let Some(addr) = addresses.try_next().await.map_err(|e| {
            Error::new(ErrorKind::Other, e.to_string())
        })? {
            // Parse the address from netlink attributes
            if let Some(ip_str) = self.parse_address_from_message(&addr) {
                ips.push(ip_str);
            }
        }
        
        Ok(ips)
    }

    fn parse_address_from_message(&self, addr: &AddressMessage) -> Option<String> {
        // Parse netlink attributes to extract IP address and prefix length
        for attr in &addr.attributes {
            match attr {
                AddressAttribute::Address(ip_addr) => {
                    // Convert AddressFamily enum to u8 for comparison
                    let family = match addr.header.family {
                        AddressFamily::Inet => 2u8,  // AF_INET
                        AddressFamily::Inet6 => 10u8, // AF_INET6
                        _ => continue,
                    };
                    
                    match family {
                        2 => { // AF_INET
                            if ip_addr.is_ipv4() {
                                let prefix_len = addr.header.prefix_len;
                                return Some(format!("{}/{}", ip_addr.to_string(), prefix_len));
                            }
                        }
                        10 => { // AF_INET6
                            if ip_addr.is_ipv6() {
                                let prefix_len = addr.header.prefix_len;
                                return Some(format!("{}/{}", ip_addr.to_string(), prefix_len));
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        None
    }
}

pub const CRYPTO_KEY_LEN: usize = 32;

pub trait CryptoCell {
    fn get_private_key(&self) -> Result<Box<Vec<u8>>, Error>;
    fn get_public_key(&self) -> Result<Box<Vec<u8>>, Error>;
}

pub trait ConvertToBase58 {
    fn get_base64_from_pk(&self) -> Result<String, Error>;
    fn get_base64_from_sk(&self) -> Result<String, Error>;
}

impl<T> ConvertToBase58 for T
where
    T: CryptoCell,
{
    fn get_base64_from_sk(&self) -> Result<String, Error> {
        match self.get_private_key() {
            Ok(buf) => {
                let ret = general_purpose::STANDARD.encode(buf.as_slice());
                Ok("sk:".to_string() + ret.as_str())
            }
            Err(e) => Err(e),
        }
    }

    fn get_base64_from_pk(&self) -> Result<String, Error> {
        match self.get_public_key() {
            Ok(buf) => {
                let ret = general_purpose::STANDARD.encode(buf.as_slice());
                Ok("pk:".to_string() + ret.as_str())
            }
            Err(e) => Err(e),
        }
    }
}

// Curve25519 key implementation
#[derive(Debug)]
pub struct Curve25519Key {
    private_key: Option<Box<Vec<u8>>>,
    public_key: Option<Box<Vec<u8>>>,
}

impl Curve25519Key {
    pub fn new() -> Self {
        // Generate the private key
        let mut buf: [u8; CRYPTO_KEY_LEN] = [0; CRYPTO_KEY_LEN];
        for i in buf.iter_mut() {
            *i = random::<u8>();
        }

        // Clamp the key
        buf[0] &= 248;
        buf[31] = (buf[31] & 127) | 64;

        Curve25519Key {
            private_key: Some(Box::new(buf.to_vec())),
            public_key: None,
        }
    }

    pub fn generate_pubkey(&mut self) -> &mut Self {
        // Generate public key from private key using unsafe code
        let secret: *const u8 = self.private_key.as_ref().unwrap().as_ptr();
        let mut buf = [0u8; CRYPTO_KEY_LEN];
        let pubkey: *mut u8 = buf.as_mut_ptr();
        unsafe {
            wg_sys::curve25519_generate_public(pubkey, secret);
        }
        self.public_key = Some(Box::new(buf.to_vec()));
        self
    }

    pub fn from(s: &str) -> Result<Self, Error> {
        let ss: &str = s.into();
        let mut splits = ss.split(":");
        let first = splits.nth(0);
        
        if first.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid base64, should prefix with pk or sk",
            ));
        }

        let first = first.unwrap();
        if first != "sk" && first != "pk" {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid base64, should prefix with pk or sk",
            ));
        }

        let last = splits.last();
        if last.is_none() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid base64, should contain the base64 data",
            ));
        }

        // Try to decode the last part
        let decode_result = general_purpose::STANDARD.decode(last.unwrap());
        if let Err(e) = decode_result {
            return Err(Error::new(ErrorKind::InvalidInput, e.to_string()));
        }

        let decode_result = decode_result.unwrap();
        if decode_result.len() != CRYPTO_KEY_LEN {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "invalid base64, the decoded length should be 32 bytes long",
            ));
        }

        let mut key;

        if first == "sk" {
            key = Curve25519Key {
                private_key: Some(Box::new(decode_result)),
                public_key: None,
            };
            key.generate_pubkey();
        } else {
            key = Curve25519Key {
                private_key: None,
                public_key: Some(Box::new(decode_result)),
            };
        }
        Ok(key)
    }
}

impl CryptoCell for Curve25519Key {
    fn get_private_key(&self) -> Result<Box<Vec<u8>>, Error> {
        match self.private_key.as_ref() {
            Some(t) => Ok(t.clone()),
            None => Err(Error::new(
                ErrorKind::NotFound,
                "not found the private key, try to regenerate it",
            )),
        }
    }

    fn get_public_key(&self) -> Result<Box<Vec<u8>>, Error> {
        match self.public_key.as_ref() {
            Some(t) => Ok(t.clone()),
            None => Err(Error::new(
                ErrorKind::NotFound,
                "not found the public key, try to regenerate it",
            )),
        }
    }
}

#[derive(Debug)]
pub struct SharedKey {
    shared_key: Option<Box<Vec<u8>>>,
}

impl SharedKey {
    pub fn new() -> Self {
        let mut buf: [u8; CRYPTO_KEY_LEN] = [0; CRYPTO_KEY_LEN];
        for i in buf.iter_mut() {
            *i = random::<u8>();
        }
        SharedKey {
            shared_key: Some(Box::new(buf.to_vec())),
        }
    }
}

impl CryptoCell for SharedKey {
    fn get_private_key(&self) -> Result<Box<Vec<u8>>, Error> {
        match self.shared_key.as_ref() {
            Some(t) => Ok(t.clone()),
            None => Err(Error::new(
                ErrorKind::NotFound,
                "not found the key, try to regenerate it",
            )),
        }
    }

    fn get_public_key(&self) -> Result<Box<Vec<u8>>, Error> {
        Err(Error::new(
            ErrorKind::NotFound,
            "this is a preshared key, no public key",
        ))
    }
}

// WgPeer implementation
#[derive(Clone)]
pub struct WgPeer {
    pub public_key: Option<Box<Vec<u8>>>,
    pub public_key_base64: Option<String>,
    pub preshared_key: Option<Box<Vec<u8>>>,
    pub endpoint: Option<libc::sockaddr_in>,
    pub last_handshake_time: Option<i64>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub persistent_keepalive_interval: Option<u16>,
    pub allowed_ips: Option<Vec<IpCidr>>,
    pub remove_me: bool,
}

impl std::fmt::Debug for WgPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "pubkey:{:?}", self.public_key_base64)?;
        writeln!(f, "preshared_key:{:?}", self.preshared_key)?;
        writeln!(f, "rx_bytes:{:?}", self.rx_bytes)?;
        writeln!(f, "tx_bytes:{:?}", self.tx_bytes)?;
        writeln!(f, "allowed_ips:{:?}", self.allowed_ips)
    }
}

impl WgPeer {
    pub fn new() -> WgPeer {
        WgPeer {
            public_key: None,
            public_key_base64: None,
            preshared_key: None,
            endpoint: None,
            last_handshake_time: None,
            rx_bytes: None,
            tx_bytes: None,
            persistent_keepalive_interval: None,
            allowed_ips: None,
            remove_me: false,
        }
    }

    pub fn set_pubkey_base64(&mut self, key: &str) -> Result<&mut Self, Error> {
        match general_purpose::STANDARD.decode(key) {
            Ok(decoded) => {
                self.public_key = Some(Box::new(decoded));
                self.public_key_base64 = Some(key.to_string());
                Ok(self)
            }
            Err(e) => Err(Error::new(ErrorKind::InvalidData, e.to_string())),
        }
    }

    pub fn set_endpoint(&mut self, peer: &str) -> Result<&mut Self, std::net::AddrParseError> {
        let socket: SocketAddrV4 = peer.parse()?;
        let ip = socket.ip().octets();

        let v4 = ((ip[0] as u32) << 24)
            | ((ip[1] as u32) << 16)
            | ((ip[2] as u32) << 8)
            | (ip[3] as u32);
        let v4 = v4.to_be();

        self.endpoint = Some(libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: socket.port().to_be(),
            sin_zero: [0u8; 8],
            sin_addr: libc::in_addr { s_addr: v4 },
        });

        Ok(self)
    }

    pub fn set_pubkey_raw<'a, T>(&mut self, key: T) -> &mut Self
    where
        T: Into<&'a [u8]>,
    {
        let bytes = Into::<&[u8]>::into(key).to_vec();
        self.public_key = Some(Box::new(bytes.clone()));
        self.public_key_base64 = Some(general_purpose::STANDARD.encode(bytes));
        self
    }

    fn set_allowed_ip(&mut self, ips: Vec<IpCidr>) -> &mut Self {
        self.allowed_ips = Some(ips);
        self
    }

    fn set_remove_me(&mut self, remove_me: bool) -> &mut Self {
        self.remove_me = remove_me;
        self
    }

    fn set_persistent_keepalive_interval(&mut self, interval: Option<u16>) -> &mut Self {
        self.persistent_keepalive_interval = interval;
        self
    }
}

impl CryptoCell for WgPeer {
    fn get_private_key(&self) -> Result<Box<Vec<u8>>, Error> {
        Err(Error::new(
            ErrorKind::NotFound,
            "this is a wgpeer object, no private key",
        ))
    }

    fn get_public_key(&self) -> Result<Box<Vec<u8>>, Error> {
        self.public_key.as_ref().map_or_else(
            || Err(Error::new(ErrorKind::NotFound, "No public key found")),
            |pubkey| Ok(pubkey.clone()),
        )
    }
}

// WgDevice implementation
#[derive(Clone, Debug)]
pub struct WgDevice {
    pub name: String,
    pub public_key: Option<Box<Vec<u8>>>,
    pub private_key: Option<Box<Vec<u8>>>,
    pub fwmark: Option<u32>,
    pub listen_port: Option<u16>,
    pub peers: Option<Box<Vec<WgPeer>>>,
    ifindex: Option<u32>,
    netlink_manager: Option<NetlinkManager>,
}

impl WgDevice {
    pub fn new(name: &str) -> Self {
        WgDevice {
            name: name.to_string(),
            public_key: None,
            private_key: None,
            fwmark: None,
            listen_port: None,
            peers: None,
            ifindex: None,
            netlink_manager: None,
        }
    }

    pub fn new_blank() -> Self {
        WgDevice {
            name: "".to_string(),
            public_key: None,
            private_key: None,
            fwmark: None,
            listen_port: None,
            peers: None,
            ifindex: None,
            netlink_manager: None,
        }
    }

    pub fn set_port(&mut self, port: u16) -> &mut Self {
        self.listen_port = Some(port);
        self
    }

    pub fn set_private(&mut self, key: &Curve25519Key) -> &mut Self {
        if let Ok(private_key) = key.get_private_key() {
            self.private_key = Some(private_key);
        }
        self
    }

    fn set_peer(&mut self, peer: &WgPeer) -> &mut Self {
        if self.peers.is_none() {
            self.peers = Some(Box::new(Vec::<WgPeer>::new()));
        }

        if let Some(ref mut peers) = self.peers {
            peers.push(peer.clone());
        }

        self
    }

    fn set_ifindex(&mut self, ifindex: Option<u32>) -> &mut Self {
        self.ifindex = ifindex;
        self
    }

    fn set_fwmark(&mut self, fwmark: Option<u32>) -> &mut Self {
        self.fwmark = fwmark;
        self
    }

    pub fn get_users(&self) -> Option<Box<Vec<WgPeer>>> {
        self.peers.as_ref().map(|peers| peers.clone())
    }

    fn get_or_create_netlink_manager(&mut self) -> Result<&mut NetlinkManager, Error> {
        if self.netlink_manager.is_none() {
            self.netlink_manager = Some(NetlinkManager::new()?);
        }
        Ok(self.netlink_manager.as_mut().unwrap())
    }

    pub fn resolve_interface_index(&mut self) -> Result<u32, Error> {
        if let Some(ifindex) = self.ifindex {
            return Ok(ifindex);
        }

        // Clone the name to avoid borrowing issues
        let name = self.name.clone();
        let netlink = self.get_or_create_netlink_manager()?;
        let ifindex = netlink.get_interface_index_sync(&name)?;
        self.ifindex = Some(ifindex);
        Ok(ifindex)
    }
}

impl CryptoCell for WgDevice {
    fn get_private_key(&self) -> Result<Box<Vec<u8>>, Error> {
        self.private_key.as_ref().map_or_else(
            || {
                Err(Error::new(
                    ErrorKind::NotFound,
                    "not found the private key, try to regenerate it",
                ))
            },
            |a| Ok(a.clone()),
        )
    }

    fn get_public_key(&self) -> Result<Box<Vec<u8>>, Error> {
        self.public_key.as_ref().map_or_else(
            || {
                Err(Error::new(
                    ErrorKind::NotFound,
                    "not found the public key, try to regenerate it",
                ))
            },
            |a| Ok(a.clone()),
        )
    }
}

// Intermediate state structs for WireGuard C API interaction
pub struct WgdeviceIntermediteState {
    wgdevice: wgdevice,
    _wgpeers: Option<Vec<WgPeerIntermediteState>>,
}

impl WgdeviceIntermediteState {
    pub fn set_wg_device(&mut self) -> Result<(), Error> {
        // Clear the replace flag
        self.wgdevice.flags &= !(wgdevice_flag_::WGDEVICE_REPLACE_PEERS as u32);

        // Invoke the IPC set device
        unsafe {
            let ret = ipc_set_device(&mut self.wgdevice as *mut wgdevice);
            if ret != 0 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "cannot configure wireguard device",
                ));
            }
        }
        Ok(())
    }

    pub fn process_peer(&mut self) -> Result<(), Error> {
        // Remove device-level flags, only process peers
        self.wgdevice.flags &= !(wgdevice_flag_::WGDEVICE_HAS_FWMARK as u32);
        self.wgdevice.flags &= !(wgdevice_flag_::WGDEVICE_HAS_LISTEN_PORT as u32);
        self.wgdevice.flags &= !(wgdevice_flag_::WGDEVICE_HAS_PRIVATE_KEY as u32);
        self.wgdevice.flags &= !(wgdevice_flag_::WGDEVICE_HAS_PUBLIC_KEY as u32);

        self.wgdevice.flags &= !(wgdevice_flag_::WGDEVICE_REPLACE_PEERS as u32);
        
        unsafe {
            let ret = ipc_set_device(&mut self.wgdevice as *mut wgdevice);
            if ret != 0 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "cannot configure wireguard peers",
                ));
            }
        }
        Ok(())
    }
}

impl Into<Option<WgdeviceIntermediteState>> for WgDevice {
    fn into(mut self) -> Option<WgdeviceIntermediteState> {
        debug!("Converting wgdevice into intermediate state.");
        let mut wgdevice = create_blank_wgdevice();

        // Set the name
        let name_bytes = self.name.as_bytes();
        let name_len = std::cmp::min(name_bytes.len(), 15); // Leave space for null terminator
        for (i, &byte) in name_bytes.iter().take(name_len).enumerate() {
            wgdevice.name[i] = byte as i8;
        }

        debug!("Set the interface index...");
        if self.ifindex.is_none() {
            // Try to resolve interface index using netlink
            match self.resolve_interface_index() {
                Ok(index) => {
                    wgdevice.ifindex = index;
                }
                Err(_) => {
                    error!("Cannot resolve interface index for {}", self.name);
                    return None;
                }
            }
        } else {
            wgdevice.ifindex = self.ifindex.unwrap();
        }

        debug!("Set the public key...");
        // Set public key
        if let Some(ref public_key) = self.public_key {
            if public_key.len() == CRYPTO_KEY_LEN {
                for (i, &byte) in public_key.iter().enumerate() {
                    wgdevice.public_key[i] = byte;
                }
                wgdevice.flags |= wgdevice_flag_::WGDEVICE_HAS_PUBLIC_KEY as u32;
            }
        }

        debug!("Set the private key if the wgdevice has...");
        // Set private key
        if let Some(ref private_key) = self.private_key {
            if private_key.len() == CRYPTO_KEY_LEN {
                for (i, &byte) in private_key.iter().enumerate() {
                    wgdevice.private_key[i] = byte;
                }
                wgdevice.flags |= wgdevice_flag_::WGDEVICE_HAS_PRIVATE_KEY as u32;
            }
        }

        debug!("Set the fwmark if the wgdevice has...");
        // Set fwmark
        if let Some(fwmark) = self.fwmark {
            wgdevice.fwmark = fwmark;
            wgdevice.flags |= wgdevice_flag_::WGDEVICE_HAS_FWMARK as u32;
        }

        debug!("Set the listening port if the wgdevice has...");
        // Set listen port
        if let Some(listen_port) = self.listen_port {
            wgdevice.listen_port = listen_port;
            wgdevice.flags |= wgdevice_flag_::WGDEVICE_HAS_LISTEN_PORT as u32;
        }

        debug!("Set the peers if the wgdevice has...");
        // Process peers
        let mut wgpeers = None;
        if let Some(ref peers) = self.peers {
            wgpeers = Some(Vec::<WgPeerIntermediteState>::new());
            for peer in peers.iter() {
                let wg_peer_state: WgPeerIntermediteState = peer.into();
                wgpeers.as_mut().unwrap().push(wg_peer_state);
            }
        }

        // Set peer pointers
        if let Some(ref mut peers) = wgpeers {
            if let Some(first_peer) = peers.first_mut() {
                wgdevice.first_peer = &mut first_peer.wgpeer as *mut wgpeer;
                wgdevice.flags |= wgdevice_flag_::WGDEVICE_REPLACE_PEERS as u32;
            }

            if let Some(last_peer) = peers.last_mut() {
                wgdevice.last_peer = &mut last_peer.wgpeer as *mut wgpeer;
            }
        }

        Some(WgdeviceIntermediteState {
            wgdevice,
            _wgpeers: wgpeers,
        })
    }
}

struct WgPeerIntermediteState {
    wgpeer: wgpeer,
    _allowed_ip_buf: Option<Box<Vec<wgallowedip>>>,
}

impl Into<WgPeerIntermediteState> for &WgPeer {
    fn into(self) -> WgPeerIntermediteState {
        debug!("Convert peer {:?} into the intermediate state.", self);
        let mut wgpeer = create_blank_wgpeer();

        // Process the remove flag
        if self.remove_me {
            wgpeer.flags |= wg_peer_flag_::WGPEER_REMOVE_ME as u32;
        }

        // Set endpoint
        if let Some(endpoint) = self.endpoint {
            wgpeer.endpoint = wgpeer__bindgen_ty_1 {
                addr4: sockaddr_in {
                    sin_family: endpoint.sin_family,
                    sin_port: endpoint.sin_port,
                    sin_addr: in_addr {
                        s_addr: endpoint.sin_addr.s_addr,
                    },
                    sin_zero: endpoint.sin_zero,
                },
            };
        }

        // Set public key
        if let Some(ref pk) = self.public_key {
            if pk.len() == CRYPTO_KEY_LEN {
                for (i, &byte) in pk.iter().enumerate() {
                    wgpeer.public_key[i] = byte;
                }
                wgpeer.flags |= wg_peer_flag_::WGPEER_HAS_PUBLIC_KEY as u32;
            }
        }

        // Set preshared key
        if let Some(ref psk) = self.preshared_key {
            if psk.len() == CRYPTO_KEY_LEN {
                for (i, &byte) in psk.iter().enumerate() {
                    wgpeer.preshared_key[i] = byte;
                }
                wgpeer.flags |= wg_peer_flag_::WGPEER_HAS_PRESHARED_KEY as u32;
            }
        }

        // Set persistent keepalive interval
        if let Some(interval) = self.persistent_keepalive_interval {
            wgpeer.persistent_keepalive_interval = interval;
            wgpeer.flags |= wg_peer_flag_::WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL as u32;
        }

        // Process allowed IPs
        let mut buf = None;
        let mut previous: *mut wgallowedip = std::ptr::null_mut();

        if let Some(ref cidrs) = self.allowed_ips {
            if !cidrs.is_empty() {
                buf = Some(Box::new(vec![
                    wgallowedip {
                        family: 0,
                        cidr: 0,
                        next_allowedip: std::ptr::null_mut(),
                        __bindgen_anon_1: wgallowedip__bindgen_ty_1 {
                            ip4: in_addr { s_addr: 0 }
                        }
                    };
                    cidrs.len()
                ]));

                if let Some(ref mut allowed_ips) = buf {
                    wgpeer.first_allowedip = allowed_ips.as_mut_ptr();
                    wgpeer.last_allowedip = unsafe { allowed_ips.as_mut_ptr().add(allowed_ips.len() - 1) };
                    wgpeer.flags |= wg_peer_flag_::WGPEER_REPLACE_ALLOWEDIPS as u32;

                    for (cidr, allowed_ip) in cidrs.iter().zip(allowed_ips.iter_mut()) {
                        match cidr {
                            IpCidr::V4(ipv4_cidr) => {
                                allowed_ip.family = 2; // AF_INET
                                allowed_ip.cidr = ipv4_cidr.network_length();
                                allowed_ip.next_allowedip = std::ptr::null_mut();
                                allowed_ip.__bindgen_anon_1 = wgallowedip__bindgen_ty_1 {
                                    ip4: in_addr {
                                        s_addr: ipv4_cidr.first_address().to_bits().to_be(),
                                    },
                                };

                                if !previous.is_null() {
                                    unsafe {
                                        (*previous).next_allowedip = allowed_ip as *mut wgallowedip;
                                    }
                                }
                                previous = allowed_ip as *mut wgallowedip;
                            }
                            _ => {
                                // Handle IPv6 if needed
                            }
                        }
                    }
                }
            }
        }

        WgPeerIntermediteState {
            wgpeer,
            _allowed_ip_buf: buf,
        }
    }
}

impl From<&wgdevice> for WgDevice {
    fn from(w: &wgdevice) -> WgDevice {
        let mut wd = WgDevice::new_blank();

        wd.name = unsafe {
            std::ffi::CStr::from_ptr(w.name.as_ptr())
                .to_str()
                .unwrap_or("")
                .to_string()
        };
        wd.public_key = Some(Box::new(w.public_key.to_vec()));
        wd.private_key = Some(Box::new(w.private_key.to_vec()));
        wd.listen_port = Some(w.listen_port);
        wd.fwmark = Some(w.fwmark);

        // Process peers
        let mut current = w.first_peer;
        while !current.is_null() {
            if wd.peers.is_none() {
                wd.peers = Some(Box::new(Vec::<WgPeer>::new()));
            }
            
            unsafe {
                wd.peers
                    .as_mut()
                    .unwrap()
                    .push(WgPeer::from(&*current));
                
                if current == w.last_peer {
                    break;
                }
                current = (*current).next_peer;
            }
        }
        wd
    }
}

impl From<&wgpeer> for WgPeer {
    fn from(w: &wgpeer) -> WgPeer {
        let mut wp = WgPeer::new();

        wp.public_key = Some(Box::new(w.public_key.to_vec()));
        wp.preshared_key = Some(Box::new(w.preshared_key.to_vec()));
        wp.last_handshake_time = Some(w.last_handshake_time.tv_sec);
        wp.rx_bytes = Some(w.rx_bytes);
        wp.tx_bytes = Some(w.tx_bytes);
        wp.persistent_keepalive_interval = Some(w.persistent_keepalive_interval);

        // Process allowed IPs
        let mut current = w.first_allowedip;
        while !current.is_null() {
            if wp.allowed_ips.is_none() {
                wp.allowed_ips = Some(Vec::<IpCidr>::new());
            }

            unsafe {
                // Create Ipv4Cidr from network address and prefix length using from_str
                let network_addr = Ipv4Addr::from(u32::from_be((*current).__bindgen_anon_1.ip4.s_addr));
                let prefix_len = (*current).cidr;
                
                if let Ok(ipv4_cidr) = Ipv4Cidr::from_str(&format!("{}/{}", network_addr, prefix_len)) {
                    wp.allowed_ips.as_mut().unwrap().push(IpCidr::V4(ipv4_cidr));
                }

                if current == w.last_allowedip {
                    break;
                }
                current = (*current).next_allowedip;
            }
        }

        wp
    }
}

// Helper functions
#[inline]
fn create_blank_wgpeer() -> wgpeer {
    wgpeer {
        flags: 0,
        public_key: [0; CRYPTO_KEY_LEN],
        preshared_key: [0; CRYPTO_KEY_LEN],
        last_handshake_time: timespec64 {
            tv_nsec: 0,
            tv_sec: 0,
        },
        rx_bytes: 0,
        tx_bytes: 0,
        persistent_keepalive_interval: 0,
        first_allowedip: std::ptr::null_mut(),
        last_allowedip: std::ptr::null_mut(),
        next_peer: std::ptr::null_mut(),
        endpoint: wgpeer__bindgen_ty_1 {
            addr4: sockaddr_in {
                sin_family: 0,
                sin_port: 0,
                sin_addr: in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            },
        },
    }
}

#[inline]
fn create_blank_wgdevice() -> wgdevice {
    wgdevice {
        name: [0 as c_char; 16usize],
        ifindex: 0,
        flags: 0,
        public_key: [0u8; 32usize],
        private_key: [0u8; 32usize],
        fwmark: 0u32,
        listen_port: 0u16,
        first_peer: std::ptr::null_mut(),
        last_peer: std::ptr::null_mut(),
    }
}

// Public API functions
pub fn set_wireguard_interface(
    name: &str,
    if_index: Option<u32>,
    key_str: Option<&str>,
    port: Option<u16>,
    fwmark: Option<u32>,
) -> Result<(), Error> {
    let mut wd = WgDevice::new(name);
    debug!("Setting wireguard interface...");
    
    let key = if let Some(ks) = key_str {
        let ks_base64 = if ks.starts_with("sk:") {
            &ks[3..]
        } else {
            ks
        };
        debug!("Set wg interface sk: {}", ks_base64);
        match general_purpose::STANDARD.decode(ks_base64) {
            Ok(decoded) => Curve25519Key {
                private_key: Some(Box::new(decoded)),
                public_key: None,
            },
            Err(e) => {
                return Err(Error::new(ErrorKind::InvalidData, e.to_string()));
            }
        }
    } else {
        Curve25519Key::new()
    };

    let listen_port = port.unwrap_or(52180);

    wd.set_port(listen_port)
        .set_private(&key)
        .set_fwmark(fwmark)
        .set_ifindex(if_index);

    let wgdi: Option<WgdeviceIntermediteState> = wd.into();
    wgdi.unwrap().set_wg_device()
}

pub fn collect_wireguard_info(name: &str) -> Result<WgDevice, Error> {
    let wgd;
    unsafe {
        let mut device: *mut wgdevice = std::ptr::null_mut();
        let cs = std::ffi::CString::new(name).unwrap();
        let ptr = cs.into_raw();

        let ret = wg_sys::ipc_get_device(&mut device as *mut *mut wgdevice, ptr);
        if ret == 0 {
            wgd = (&*device).into();
            wg_sys::ipc_free_device(device);
        } else {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Cannot get wg device: {}", name),
            ));
        }
    }
    Ok(wgd)
}

pub fn add_wireguard_peer<'a, T>(
    name: &'a str,
    endpoint: Option<String>,
    ifindex: Option<u32>,
    persistent_keepalive_interval: Option<u16>,
    allowed_ip: T,
    key: &'a str,
) -> Result<(), Error>
where
    T: Into<&'a [&'a str]>,
{
    debug!("Add wireguard user {} to interface {}", key, name);
    let mut wd = WgDevice::new(name);
    let mut wp = WgPeer::new();
    
    wp.set_pubkey_base64(key)?;

    let allowed_ips = Into::<&[&str]>::into(allowed_ip)
        .iter()
        .filter_map(|&a| Ipv4Cidr::from_str(a).ok())
        .map(|a| IpCidr::V4(a))
        .collect::<Vec<_>>();
    
    wp.set_allowed_ip(allowed_ips)
        .set_persistent_keepalive_interval(persistent_keepalive_interval);

    if let Some(endpoint) = endpoint {
        wp.set_endpoint(&endpoint).map_err(|e| {
            error!("Cannot set the endpoint to wg, reason: {}", e);
            Error::new(ErrorKind::InvalidInput, e.to_string())
        })?;
    }

    wd.set_peer(&wp).set_ifindex(ifindex);

    let wgdi: Option<WgdeviceIntermediteState> = wd.into();
    wgdi.unwrap().process_peer()
}

pub fn remove_wirefguard_peer<'a>(
    name: &'a str,
    ifindex: Option<u32>,
    key: &'a str,
) -> Result<(), Error> {
    let mut wd = WgDevice::new(name);
    let mut wp = WgPeer::new();
    
    wp.set_pubkey_base64(key)?;
    wp.set_remove_me(true);

    wd.set_peer(&wp).set_ifindex(ifindex);
    let wgdi: Option<WgdeviceIntermediteState> = wd.into();
    wgdi.unwrap().process_peer()
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_wg_info() {
        let wgd = collect_wireguard_info("wg0");
        println!("{:?}", wgd);
    }

    #[test]
    fn test_set_wgdevice() {
        let mut wgd = WgDevice::new("wg123");
        let key = Curve25519Key::new();
        wgd.listen_port = Some(51280);
        wgd.private_key = Some(key.get_private_key().unwrap());
        let wgdi: Option<WgdeviceIntermediteState> = wgd.into();
        println!("================");
        wgdi.unwrap().set_wg_device().unwrap();
    }

    #[test]
    fn test_base64_curve25519() {
        let mut key = Curve25519Key::new();
        println!("key: {}", key.get_base64_from_sk().unwrap());
        key.generate_pubkey();
        println!("key: {}", key.get_base64_from_pk().unwrap());

        let sk = Curve25519Key::from("sk:+HSbINLH2Hn41FfWa+JlqW/nRB2JtzNvc2UrvHmu7mw=").unwrap();
        println!("sk: {}", sk.get_base64_from_sk().unwrap());
        println!("sk: {}", sk.get_base64_from_pk().unwrap());
        assert_eq!(
            sk.get_base64_from_sk().unwrap(),
            "sk:+HSbINLH2Hn41FfWa+JlqW/nRB2JtzNvc2UrvHmu7mw="
        );
        assert_eq!(
            sk.get_base64_from_pk().unwrap(),
            "pk:Mx5ViJGrI5w2xaXa28RI8o/lrGAzLn63TMOFE1/UHiw="
        );
    }

    #[test]
    fn generate_private_key() {
        let key = Curve25519Key::new();
        println!("{:?}", key);
        assert_ne!(
            key.get_private_key().unwrap().to_vec(),
            vec![0u8; CRYPTO_KEY_LEN]
        );
    }

    #[test]
    fn generate_public_key() {
        let mut key = Curve25519Key::new();
        println!("{:?}", key);
        assert_ne!(
            key.generate_pubkey().get_public_key().unwrap().to_vec(),
            vec![0u8; CRYPTO_KEY_LEN]
        );
    }

    #[test]
    fn test_netlink_manager() {
        let manager = NetlinkManager::new().unwrap();
        println!("NetlinkManager created successfully");
        
        // Test interface existence check
        let exists = manager.interface_exists("lo");
        println!("Interface 'lo' exists: {}", exists);
        assert!(exists);
    }
}