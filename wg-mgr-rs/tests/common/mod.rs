use std::sync::{Arc, Mutex};
use wg_mgr_rs::wg_network_conf_srv::NetworkConfClient;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn setup_test_client() -> NetworkConfClient {
    NetworkConfClient::new()
}

pub fn create_test_interface_name() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("test-{}", timestamp)
}

pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[macro_export]
macro_rules! skip_if_not_root {
    () => {
        if !crate::common::is_root() {
            println!("Skipping test: requires root privileges");
            return;
        }
    };
}

// Test utilities for async tests
pub async fn cleanup_test_interface(client: &mut NetworkConfClient, name: &str) {
    let _ = client.delete_wg_interface(name.to_string());
    let _ = client.delete_vxlan_interface(name.to_string());
    let _ = client.delete_vrf_interface(name);
}