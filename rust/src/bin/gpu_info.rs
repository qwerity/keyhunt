//! Print CUDA GPU info (uses cudarc, no keyhunt CUDA lib).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    use cudarc::driver::CudaDevice;
    let mut count = 0usize;
    let mut list = Vec::new();
    while let Ok(dev) = CudaDevice::new(count) {
        let name = dev.name().unwrap_or_else(|_| "?".to_string());
        list.push((count, name));
        count += 1;
    }
    println!("CUDA devices: {}", count);
    for (i, name) in list {
        println!("  [{}] {}", i, name);
    }
    Ok(())
}
