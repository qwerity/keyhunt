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

        // CUDA Toolkit: линкер ищет libcudart_static.a (Linux)
        #[cfg(target_os = "linux")]
        {
            let cuda_root = std::env::var("CUDA_PATH")
                .or_else(|_| std::env::var("CUDA_HOME"))
                .or_else(|_| detect_cuda_from_nvcc());
            if let Ok(root) = cuda_root {
                for subdir in ["lib64", "lib64/stubs", "lib"] {
                    let lib = std::path::Path::new(&root).join(subdir);
                    if lib.exists() {
                        println!("cargo:rustc-link-search=native={}", lib.display());
                    }
                }
                if !std::path::Path::new(&root).join("lib64").exists()
                    && !std::path::Path::new(&root).join("lib").exists()
                {
                    eprintln!("cargo:warning=CUDA root {} has no lib64/ or lib/", root);
                }
            } else {
                // фиксированные пути без CUDA_PATH
                for path in ["/usr/local/cuda/lib64", "/opt/cuda/lib64", "/usr/lib/x86_64-linux-gnu"] {
                    if std::path::Path::new(path).exists() {
                        println!("cargo:rustc-link-search=native={}", path);
                    }
                }
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
