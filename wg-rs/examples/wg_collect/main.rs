use wg_rs::collect_wireguard_info;

fn main() {
    let d = collect_wireguard_info("wg0");
    println!("{:?}", d);
}
