//! Convert hash160 hex file (40 hex per hash) to binary (20 bytes per hash).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <hex_file> <output.bin>", args[0]);
        std::process::exit(1);
    }
    let hex_path = std::path::Path::new(&args[1]);
    let out_path = std::path::Path::new(&args[2]);
    let hashes = keyhunt_pvk::hash160::read_hash160_hex(hex_path)?;
    keyhunt_pvk::hash160::write_hash160_binary(out_path, &hashes)?;
    eprintln!("Written {} hashes to {}", hashes.len(), out_path.display());
    Ok(())
}
