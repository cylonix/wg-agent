use wg_rs::{add_wireguard_peer, remove_wirefguard_peer, set_wireguard_interface};

fn main() {
    let name = "wg0";
    let key = "v5rrqGUYEHpQd0ujsENkmYgsPA1NWwfahhqcgEuKvAs=";
    let private_key = "qDkNecFS9MxOgEjVaMiTf11+a/QSh+zsxuheO2V0yWQ=";

    // create the wgdevice
    set_wireguard_interface(name, None, Some(private_key), Some(51111), None).unwrap();
    add_wireguard_peer(
        name,
        None,
        None,
        None,
        vec!["10.0.1.0/24", "10.2.0.0/24"].as_slice(),
        key,
    )
    .unwrap();

    remove_wirefguard_peer(name, None, key).unwrap();
}
