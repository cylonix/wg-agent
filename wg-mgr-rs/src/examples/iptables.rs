// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

use wg_mgr_rs::wg_network_conf_srv;

const INTERFACE: &str = "lo";
const MARK: u32 = 12345;
const IP: &str = "10.0.0.0/24";

fn main() {
    let mut iproute = wg_network_conf_srv::NetworkConfClient::new();

    let _ = iproute
        .create_fwmark_entry(INTERFACE.to_string(), IP.to_string(), MARK)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => {}
            _ => panic!("Cannot create ip table entries"),
        });

    iproute
        .delete_fwmark_entry(INTERFACE.to_string(), IP.to_string(), MARK)
        .expect("Cannot delete the iptable entry");
}
