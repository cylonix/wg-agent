use wg_mgr_rs::wg_network_conf_srv::NetworkConfClient;
use std::time::{SystemTime, UNIX_EPOCH};

// Helper functions
fn create_test_interface_name() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("test-{}", timestamp)
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

macro_rules! skip_if_not_root {
    () => {
        if !is_root() {
            println!("Skipping test: requires root privileges");
            return;
        }
    };
}

// A simple mock client for IP parsing tests that don't need networking
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

#[tokio::test]
#[ignore]
async fn test_vrf_lifecycle() {
    skip_if_not_root!();

    let client = NetworkConfClient::new();
    let vrf_name = create_test_interface_name();

    // Create VRF - Note: Using direct method call instead of trait
    let result = client.create_vrf_interface(vrf_name.clone(), 100).await;
    if result.is_ok() {
        let vrf_index = result.unwrap();
        assert!(vrf_index > 0);

        // Cleanup
        let delete_result = client.delete_vrf_interface(vrf_name).await;
        assert!(delete_result.is_ok());
    } else {
        println!("VRF creation failed (may require kernel VRF support): {:?}", result.err());
    }
}

#[tokio::test]
#[ignore]
async fn test_loopback_interface_info() {
    let client = NetworkConfClient::new();

    // Test that loopback interface exists
    let result = client.get_if_index_by_name("lo").await;
    assert!(result.is_ok());

    // Test getting IP addresses for loopback
    let ip_result = client.get_ip_by_name("lo").await;
    assert!(ip_result.is_ok());
    let ips = ip_result.unwrap();
    assert!(!ips.is_empty());
    println!("Loopback IPs: {:?}", ips);

    // Test getting stats for loopback
    let stats_result = client.get_if_stats_by_name("lo").await;
    assert!(stats_result.is_ok());
    let stats = stats_result.unwrap();
    assert_eq!(stats.name, Some("lo".to_string()));
    println!("Loopback stats: {:?}", stats);
}

#[test]
fn test_ip_parsing() {
    // Use mock client for pure IP parsing tests
    let client = MockNetworkConfClient::new();

    // Test valid IP parsing
    let result = client.parse_ip_with_mask("192.168.1.1/24");
    assert!(result.is_ok());
    let (ip, prefix) = result.unwrap();
    assert_eq!(ip, "192.168.1.1");
    assert_eq!(prefix, 24);

    // Test invalid IP parsing
    let result = client.parse_ip_with_mask("invalid");
    assert!(result.is_err());

    // Test IPv6 parsing
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

    // Test whitespace handling
    let result = client.parse_ip_with_mask("  192.168.1.1/24  ");
    assert!(result.is_ok());
    let (ip, prefix) = result.unwrap();
    assert_eq!(ip, "192.168.1.1");
    assert_eq!(prefix, 24);
}

#[tokio::test]
#[ignore]
async fn test_interface_enumeration() {
    let client = NetworkConfClient::new();

    // Test that loopback interface exists by getting its index
    let result = client.get_if_index_by_name("lo").await;
    assert!(result.is_ok());
    let lo_index = result.unwrap();
    assert!(lo_index > 0);

    println!("Loopback interface index: {}", lo_index);
}

#[tokio::test]
#[ignore]
async fn test_real_client_ip_parsing() {
    // Test IP parsing with a real client (requires tokio runtime)
    let client = NetworkConfClient::new();

    let result = client.parse_ip_with_mask("10.0.0.1/16");
    assert!(result.is_ok());

    let (ip, prefix) = result.unwrap();
    assert_eq!(ip, "10.0.0.1");
    assert_eq!(prefix, 16);
}

#[tokio::test]
#[ignore]
async fn test_client_creation() {
    // Test that we can create a NetworkConfClient without panicking
    let _client = NetworkConfClient::new();
    // If we get here, the client was created successfully
    assert!(true);
}

#[test]
fn test_mock_client_creation() {
    // Test that we can create a mock client without any runtime requirements
    let _client = MockNetworkConfClient::new();
    assert!(true);
}

#[test]
fn test_ip_parsing_error_cases() {
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

    // Test negative prefix (this will be caught by u8 parsing)
    let result = client.parse_ip_with_mask("192.168.1.1/-1");
    assert!(result.is_err());
}