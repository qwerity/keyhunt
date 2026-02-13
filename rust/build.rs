// When building with --features cuda, link keyhunt CUDA libs.
// Build the CUDA lib first: from project root:
//   cmake -B build -DCMAKE_CUDA_ARCHITECTURES=86
//   cmake --build build --target keyhunt_cuda_capi
// Then: KEYHUNT_CUDA_LIB_DIR=../build/cuda cargo build --features cuda
// Для cudart_static задайте CUDA_PATH (или CUDA_HOME) или запускайте скрипт — он выставит из nvcc.

#[cfg(target_os = "linux")]
fn detect_cuda_from_nvcc() -> Result<String, std::env::VarError> {
    use std::process::Command;
    let out = Command::new("which").arg("nvcc").output().ok();
    let path = out.and_then(|o| String::from_utf8(o.stdout).ok());
    let path = match path.as_deref() {
        Some(p) if !p.trim().is_empty() => p.trim().to_string(),
        _ => return Err(std::env::VarError::NotPresent),
    };
    let bin = std::path::Path::new(&path).canonicalize().map_err(|_| std::env::VarError::NotPresent)?;
    let root = bin.parent().and_then(|p| p.parent()).ok_or(std::env::VarError::NotPresent)?;
    Ok(root.display().to_string())
}

#[cfg(not(target_os = "linux"))]
fn detect_cuda_from_nvcc() -> Result<String, std::env::VarError> {
    Err(std::env::VarError::NotPresent)
}

fn main() {
    if std::env::var("CARGO_FEATURE_CUDA").is_ok() {
        let lib_dir = std::env::var("KEYHUNT_CUDA_LIB_DIR").unwrap_or_else(|_| "../build/cuda".into());
        println!("cargo:rustc-link-search=native={}", lib_dir);
        // На случай если CMake кладёт .a в build/ а не build/cuda/
        if let Ok(root) = std::env::var("KEYHUNT_CUDA_LIB_DIR") {
            if root.ends_with("/cuda") {
                if let Some(parent) = std::path::Path::new(&root).parent() {
                    println!("cargo:rustc-link-search=native={}", parent.display());
                }
            }
        }

        // CUDA Toolkit: находим libcudart_static.a и добавляем его каталог в link-search
        #[cfg(target_os = "linux")]
        {
            let candidates = std::env::var("CUDA_PATH")
                .or_else(|_| std::env::var("CUDA_HOME"))
                .or_else(|_| detect_cuda_from_nvcc())
                .into_iter()
                .chain(["/usr/local/cuda".into(), "/opt/cuda".into()]);
            let mut found = false;
            for root in candidates {
                for subdir in [
                    "targets/x86_64-linux/lib",
                    "targets/x86_64-linux-gnu/lib",
                    "lib64",
                    "lib64/stubs",
                    "lib",
                ] {
                    let path = std::path::Path::new(&root).join(subdir).join("libcudart_static.a");
                    if path.exists() {
                        let dir = path.parent().unwrap();
                        println!("cargo:rustc-link-search=native={}", dir.display());
                        println!("cargo:warning=Using cudart_static from {}", dir.display());
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
                }
            }
            if !found {
                eprintln!("cargo:warning=libcudart_static.a not found. Set CUDA_PATH to CUDA root (e.g. /usr/local/cuda).");
            }
        }

        // Порядок: зависимости первыми (линкер подтягивает символы по мере обхода)
        println!("cargo:rustc-link-lib=static=cudart_static");
        println!("cargo:rustc-link-lib=static=ecc_cuda");
        println!("cargo:rustc-link-lib=static=keyhunt_cuda_capi");
        #[cfg(target_os = "linux")]
        {
            println!("cargo:rustc-link-lib=stdc++");
            println!("cargo:rustc-link-lib=pthread");
            println!("cargo:rustc-link-lib=dl");
        }
        #[cfg(target_os = "windows")]
        println!("cargo:rustc-link-lib=libcmt");
    }
}
