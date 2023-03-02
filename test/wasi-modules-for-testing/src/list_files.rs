use std::fs;

fn main() {
    let root_files = fs::read_dir("/").expect("Could not list files in /");

    for file in root_files {
        let name = file.expect("Could not list path").file_name();
        println!("found file: {:?}", name);
        if name == "dev" {
            // There is directory dev in / which is unexpected
            panic!("/dev found");
        }
    }

    match fs::metadata("/dev/zero") {
        Ok(metadata) => {
            // This is the error case, since there should not be
            // /dev access
            println!("/dev/zero metadata:\n{:?}", metadata);
        }
        Err(_) => {
            // This is the success case
            println!("/dev/zero not found")
        }
    }
}
