use std::fs;
use std::path::Path;
const WGTOOL_PATH: &str = "./wireguard-tools/src";
const WGTOOL_INLCUDE_PATH: &str = "./wireguard-tools/src/uapi/linux";

fn main() {
    // Search all the files in target directory
    let path = Path::new(WGTOOL_PATH);
    let entries = fs::read_dir(path)
        .expect("Cannot read the c file from wg tool dir")
        .filter_map(|res| {
            let de = res.unwrap();
            let s = std::string::String::from(de.path().to_str().unwrap());
            if s.ends_with(".c") && !s.ends_with("wg.c") {
                return Some(de);
            }
            return None;
        })
        .collect::<Vec<_>>();

    let mut ccb = cc::Build::new();
    for entry in entries.iter() {
        //println!("{:?}", entry.path().into_os_string());
        ccb.file(entry.path());
    }

    // Prepare the incldue file
    ccb.include(WGTOOL_INLCUDE_PATH)
        .define("RUNSTATEDIR", "\"/var/run\"")
        .define("_GNU_SOURCE", None)
        .opt_level(3)
        .warnings(true)
        .compile("wg");

    println!("rustc-link-lib=wg");
}
