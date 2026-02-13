//! Decrypt results.enc (same format/key as keyhunt write).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "results.enc".to_string());
    let lines = keyhunt_pvk::results::read_encrypted_results(&path)?;
    for line in lines {
        println!("{}", line);
    }
    Ok(())
}
