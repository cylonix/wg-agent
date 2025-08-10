use wg_mgr_rs::wg_network_conf_srv::NetworkConfClient;
use wg_mgr_rs::wg_conf_store_srv::EtcdClientConfig;

#[tokio::test]
#[ignore] // Requires proper test environment setup
async fn test_full_interface_lifecycle() {
    let client = NetworkConfClient::new();

    // Test creating a test interface (requires root)
    let result = client.create_wg_interface(
        "test-wg0",
        "10.0.0.1/24"
    ).await;

    if result.is_ok() {
        let _if_index = result.unwrap();

        // Test getting interface details
        let ip_result = client.get_ip_by_name("test-wg0").await;
        assert!(ip_result.is_ok());

        let stats_result = client.get_if_stats_by_name("test-wg0").await;
        assert!(stats_result.is_ok());

        // Cleanup
        let delete_result = client.delete_wg_interface("test-wg0").await;
        assert!(delete_result.is_ok());
    }
}

#[tokio::test]
#[ignore] // Requires running etcd
async fn test_etcd_integration() {
    let endpoints = vec!["http://127.0.0.1:2379"];
    let config = EtcdClientConfig::new(&endpoints);
    let client = config.connect().await;

    assert!(client.is_some());
}

#[tokio::test]
#[ignore] // Requires root privileges
async fn test_vxlan_interface_lifecycle() {
    let client = NetworkConfClient::new();

    // Test creating a VXLAN interface
    let result = client.create_vxlan_interface(
        "test-vxlan0",
        "10.0.1.1/24",
        100, // VID
        "239.1.1.1", // Multicast group
        4789 // Default VXLAN port
    ).await;

    if result.is_ok() {
        let _if_index = result.unwrap();

        // Test getting interface details
        let ip_result = client.get_ip_by_name("test-vxlan0").await;
        assert!(ip_result.is_ok());

        // Cleanup
        let delete_result = client.delete_vxlan_interface("test-vxlan0").await;
        assert!(delete_result.is_ok());
    }
}

#[test]
fn test_hostname_retrieval() {
    use wg_mgr_rs::wg_conf_store_srv::get_hostname;

    let hostname = get_hostname();
    assert!(hostname.is_ok());
    let hostname = hostname.unwrap();
    assert!(!hostname.is_empty());
    println!("System hostname: {}", hostname);
}