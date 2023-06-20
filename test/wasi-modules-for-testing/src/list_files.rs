use std::fs;

fn main() {
    let root_files = fs::read_dir("/").expect("Could not list files in /");
    for file in root_files {
        let name = file.expect("Could not list path").path();
        println!("found file: {}", name.to_str().unwrap());
    }

    let dev_files = fs::read_dir("/dev").expect("Could not list files in /dev");
    for file in dev_files {
        let name = file.expect("Could not list path").path();
        println!("found file: {}", name.to_str().unwrap());
    }

    let sys_files = fs::read_dir("/sys").expect("Could not list files in /sys");
    for file in sys_files {
        let name = file.expect("Could not list path").path();
        println!("found file: {}", name.to_str().unwrap());
    }

    let run_files = fs::read_dir("/run").expect("Could not list files in /run");
    for file in run_files {
        let name = file.expect("Could not list path").path();
        println!("found file: {}", name.to_str().unwrap());
    }

    let proc_files = fs::read_dir("/proc").expect("Could not list files in /proc");
    for file in proc_files {
        let name = file.expect("Could not list path").path();
        println!("found file: {}", name.to_str().unwrap());
    }
}
