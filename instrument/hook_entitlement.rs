use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

fn edit_got(mut kext_bytes: Vec<u8>, ori_sym: &[u8], new_sym: &[u8], addrs: Vec<usize>) -> Vec<u8> {
    if ori_sym.len() != new_sym.len() {
        eprintln!("Original and new symbols must be of the same length.");
        std::process::exit(1);
    }
    
    for &addr in &addrs {
        if kext_bytes[addr..addr + ori_sym.len()] != *ori_sym {
            eprintln!(
                "Mismatch at address {:x}: expected {:?}, found {:?}",
                addr,
                &ori_sym,
                &kext_bytes[addr..addr + ori_sym.len()]
            );
            std::process::exit(1);
        }
        
        kext_bytes.splice(addr..addr + ori_sym.len(), new_sym.iter().cloned());
    }

    println!("Successfully edited GOT from {:?} to {:?}", ori_sym, new_sym);
    kext_bytes
}

fn type_check(kext_bytes: &[u8]) -> bool {
    kext_bytes.starts_with(b"\xcf\xfa\xed\xfe") && &kext_bytes[4..8] == b"\x0c\x00\x00\x01"
}

fn edit_entitle(mut kext_bytes: Vec<u8>) -> Vec<u8> {
    let sym1 = b"__ZN12IOUserClient21copyClientEntitlementEP4taskPKc";
    let addr0 = kext_bytes.windows(sym1.len()).position(|window| window == sym1);
    let addr1 = kext_bytes.windows(sym1.len()).rposition(|window| window == sym1);
    
    if let Some(addr0) = addr0 {
        println!("{:?} found", sym1);
        kext_bytes = edit_got(kext_bytes, sym1, b"__ZN12IOFuzzClient21copyClientEntitlementEP4taskPKc", vec![addr0, addr1.unwrap()]);
    } else {
        println!("{:?} not found, no patch needed", sym1);
    }

    let sym2 = b"__ZN24AppleMobileFileIntegrity16copyEntitlementsEP4proc";
    let addr0 = kext_bytes.windows(sym2.len()).position(|window| window == sym2);
    let addr1 = kext_bytes.windows(sym2.len()).rposition(|window| window == sym2);

    if let Some(addr0) = addr0 {
        println!("{:?} found", sym2);
        kext_bytes = edit_got(kext_bytes, sym2, b"__ZN12IOFuzzClient25AMFIcopyClientEntitlementEP4taskPKc", vec![addr0, addr1.unwrap()]);
    } else {
        println!("{:?} not found, no patch needed", sym2);
    }

    kext_bytes
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <input_universal_binary> <arg>", args[0]);
        std::process::exit(1);
    }

    let input_universal_binary = &args[1];
    let arg = &args[2];

    // Execute lipo command to extract arm64e architecture
    let output = Command::new("lipo")
        .args(&["-extract", "arm64e", "-output", arg, input_universal_binary])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .expect("Failed to execute lipo command");

    if !output.status.success() {
        eprintln!("Error running lipo command: {:?}", output.status);
      //  std::process::exit(1);
    }

    // Open the extracted file 'arg'
    let mut file = File::open(&arg)?;
    let mut kext_bytes = Vec::new();
    file.read_to_end(&mut kext_bytes)?;

    if !type_check(&kext_bytes) {
        eprintln!("Mach-O file only");
        std::process::exit(1);
    }

    kext_bytes = edit_entitle(kext_bytes);

    let mut file = File::create(arg)?;
    file.write_all(&kext_bytes)?;
    fs::set_permissions(arg, fs::Permissions::from_mode(0o755))?;

    println!("Edited kext saved in {}", arg);

    Ok(())
}
