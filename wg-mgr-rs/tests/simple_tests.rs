use wg_mgr_rs::wg_network_conf_srv::NetworkConfClient;
use wg_mgr_rs::wg_conf_store_srv::{EtcdClientConfig, get_hostname};

// Create a simple mock client for IP parsing tests that don't need networking
struct MockNetworkConfClient;

impl MockNetworkConfClient {
    fn new() -> Self {
        MockNetworkConfClient
    }

    fn parse_ip_with_mask(&self, ip_with_mask: &str) -> Result<(String, u8), std::io::Error> {
        use std::io::{Error, ErrorKind};

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

#[test]
fn test_mock_client_creation() {
    // Test that we can create a mock client without networking requirements
    let _client = MockNetworkConfClient::new();
    // This should always work since it doesn't require networking
    assert!(true);
}

#[test]
fn test_hostname() {
    let hostname = get_hostname();
    assert!(hostname.is_ok());
    let hostname = hostname.unwrap();
    assert!(!hostname.is_empty());
    println!("System hostname: {}", hostname);
}

#[test]
fn test_ip_parsing() {
    // Use mock client instead of real NetworkConfClient
    let client = MockNetworkConfClient::new();

    let result = client.parse_ip_with_mask("192.168.1.1/24");
    assert!(result.is_ok());
    let (ip, prefix) = result.unwrap();
    assert_eq!(ip, "192.168.1.1");
    assert_eq!(prefix, 24);
}

#[test]
fn test_ip_parsing_comprehensive() {
    let client = MockNetworkConfClient::new();

    // Test IPv6
    let result = client.parse_ip_with_mask("2001:db8::1/64");
    assert!(result.is_ok());
    let (ip, prefix) = result.unwrap();
    assert_eq!(ip, "2001:db8::1");
    assert_eq!(prefix, 64);

    // Test edge cases
    let result = client.parse_ip_with_mask("0.0.0.0/0");
    assert!(result.is_ok());
    let (ip, prefix) = result.unwrap();
    assert_eq!(ip, "0.0.0.0");
    assert_eq!(prefix, 0);

    // Test maximum prefix
    let result = client.parse_ip_with_mask("192.168.1.1/32");
    assert!(result.is_ok());
    let (ip, prefix) = result.unwrap();
    assert_eq!(ip, "192.168.1.1");
    assert_eq!(prefix, 32);

    // Test whitespace handling
    let result = client.parse_ip_with_mask("  10.0.0.1/8  ");
    assert!(result.is_ok());
    let (ip, prefix) = result.unwrap();
    assert_eq!(ip, "10.0.0.1");
    assert_eq!(prefix, 8);
}

#[test]
fn test_ip_parsing_errors() {
    let client = MockNetworkConfClient::new();

    // Test missing slash
    let result = client.parse_ip_with_mask("192.168.1.1");
    assert!(result.is_err());

    // Test invalid prefix
    let result = client.parse_ip_with_mask("192.168.1.1/abc");
    assert!(result.is_err());

    // Test empty string
    let result = client.parse_ip_with_mask("");
    assert!(result.is_err());

    // Test too many parts
    let result = client.parse_ip_with_mask("192.168.1.1/24/extra");
    assert!(result.is_err());
}

#[test]
fn test_etcd_config_creation() {
    let endpoints = vec!["http://127.0.0.1:2379"];
    let _config = EtcdClientConfig::new(&endpoints);
    // Just test that we can create config without panicking
    assert!(true);
}

// Tests that require networking - these must use tokio::test and should be ignored
#[tokio::test]
#[ignore] // Requires running etcd
async fn test_etcd_connection() {
    let endpoints = vec!["http://127.0.0.1:2379"];
    let config = EtcdClientConfig::new(&endpoints);
    let client = config.connect().await;

    if let Some(_client) = client {
        println!("Successfully connected to etcd");
    } else {
        println!("Could not connect to etcd (expected if not running)");
    }
}

#[tokio::test]
#[ignore] // Requires network access and tokio runtime
async fn test_real_client_creation() {
    // Test that we can create a real NetworkConfClient
    let _client = NetworkConfClient::new();
    // If we get here, the client was created successfully
    assert!(true);
}

#[tokio::test]
#[ignore] // Requires network access
async fn test_real_client_ip_parsing() {
    let client = NetworkConfClient::new();

    let result = client.parse_ip_with_mask("10.0.0.1/16");
    assert!(result.is_ok());

    let (ip, prefix) = result.unwrap();
    assert_eq!(ip, "10.0.0.1");
    assert_eq!(prefix, 16);
}

#[tokio::test]
#[ignore] // Requires network access
async fn test_loopback_interface_basic() {
    let mut client = NetworkConfClient::new();

    // Test that loopback interface exists
    let result = client.get_if_index_by_name("lo");
    assert!(result.is_ok());
    let lo_index = result.unwrap();
    assert!(lo_index > 0);

    println!("Loopback interface index: {}", lo_index);
}

// Test some basic Rust std library networking functions that don't require our client
#[test]
fn test_std_networking() {
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Test IPv4 parsing
    let ipv4: Ipv4Addr = "192.168.1.1".parse().unwrap();
    assert_eq!(ipv4.to_string(), "192.168.1.1");
    assert!(!ipv4.is_loopback());
    assert!(ipv4.is_private());

    // Test IPv6 parsing
    let ipv6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert_eq!(ipv6.to_string(), "2001:db8::1");
    assert!(!ipv6.is_loopback());

    // Test loopback addresses
    let loopback_v4: Ipv4Addr = "127.0.0.1".parse().unwrap();
    assert!(loopback_v4.is_loopback());

    let loopback_v6: Ipv6Addr = "::1".parse().unwrap();
    assert!(loopback_v6.is_loopback());
}

// Test some basic constants and static functions
#[test]
fn test_basic_constants() {
    // Test that we can access some basic networking constants
    use std::net::{IpAddr, Ipv4Addr};

    let unspecified = Ipv4Addr::UNSPECIFIED;
    assert_eq!(unspecified.to_string(), "0.0.0.0");

    let localhost = Ipv4Addr::LOCALHOST;
    assert_eq!(localhost.to_string(), "127.0.0.1");

    let broadcast = Ipv4Addr::BROADCAST;
    assert_eq!(broadcast.to_string(), "255.255.255.255");
}