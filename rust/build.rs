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
    println!("cargo:rerun-if-env-changed=KEYHUNT_CUDA_LIB_DIR");
    println!("cargo:rerun-if-env-changed=KEYHUNT_UTIL_LIB_DIR");
    if std::env::var("CARGO_FEATURE_CUDA").is_ok() {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
        let lib_dir_raw = std::env::var("KEYHUNT_CUDA_LIB_DIR").unwrap_or_else(|_| "../build/cuda".into());
        // Абсолютный путь — как есть; относительный — относительно корня крейта (rust/)
        let lib_dir = if std::path::Path::new(&lib_dir_raw).is_absolute() {
            std::path::PathBuf::from(lib_dir_raw)
        } else {
            std::path::Path::new(&manifest_dir).join(&lib_dir_raw)
        };
        let lib_dir = lib_dir.canonicalize().unwrap_or_else(|_| lib_dir.clone());
        let lib_dir_str = lib_dir.display().to_string();
        // Re-run when CUDA libs change so we pick .so vs .a correctly (e.g. after building keyhunt_cuda_capi).
        if std::path::Path::new(&lib_dir_str).exists() {
            println!("cargo:rerun-if-changed={}", lib_dir_str);
        }
        println!("cargo:rustc-link-search=native={}", lib_dir_str);
        // На случай если CMake кладёт .a в build/ а не build/cuda/
        if let Ok(root) = std::env::var("KEYHUNT_CUDA_LIB_DIR") {
            if root.ends_with("/cuda") {
                if let Some(parent) = std::path::Path::new(&root).parent() {
                    let parent_abs = std::path::Path::new(&manifest_dir).join(parent);
                    if parent_abs.exists() {
                        println!("cargo:rustc-link-search=native={}", parent_abs.canonicalize().unwrap_or(parent_abs).display());
                    }
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

        // ecc_cuda: предпочтительно .so (device link делается nvcc при сборке .so), иначе .a с --whole-archive
        println!("cargo:rustc-link-lib=static=cudart_static");
        #[cfg(target_os = "linux")]
        {
            let ecc_so = lib_dir.join("libecc_cuda.so");
            let ecc_a = lib_dir.join("libecc_cuda.a");
            if ecc_so.exists() {
                // Динамическая линковка: символы __fatbinwrap_* / __cudaRegisterLinkedBinary_* уже в .so
                println!("cargo:rustc-link-search=native={}", lib_dir.display());
                // rpath: искать libecc_cuda.so рядом с бинарником ($ORIGIN) — чтобы на удалённой машине не задавать LD_LIBRARY_PATH
                println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN");
                println!("cargo:rustc-link-lib=dylib=ecc_cuda");
            } else if let Ok(canon) = ecc_a.canonicalize() {
                println!("cargo:rustc-link-arg=-Wl,--whole-archive");
                println!("cargo:rustc-link-arg=-Wl,{}", canon.display());
                println!("cargo:rustc-link-arg=-Wl,--no-whole-archive");
            } else {
                panic!(
                    "CUDA: не найден libecc_cuda.so или libecc_cuda.a в {}. Соберите CUDA: ./scripts/build_rust_with_cuda.sh или cmake -B build && cmake --build build --target keyhunt_cuda_capi",
                    lib_dir.display()
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        println!("cargo:rustc-link-lib=static=ecc_cuda");
        println!("cargo:rustc-link-lib=static=keyhunt_cuda_capi");

        // ecc_cuda (ecc.cu) использует util/secp256k1.h → secp256k1::G(), doublePoint, addPoints из util.
        // Линкуем наш libutil.a по полному пути, иначе -lutil подхватывает системный libutil (login_tty и т.д.).
        let util_dir = std::env::var("KEYHUNT_UTIL_LIB_DIR").unwrap_or_else(|_| {
            std::path::Path::new(&lib_dir)
                .parent()
                .map(|p| p.join("util"))
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "../build/util".into())
        });
        let util_path = std::path::Path::new(&util_dir).join("libutil.a");
        if util_path.exists() {
            if let Ok(canon) = util_path.canonicalize() {
                println!("cargo:rustc-link-arg=-Wl,{}", canon.display());
            } else {
                println!("cargo:rustc-link-search=native={}", util_dir);
                println!("cargo:rustc-link-lib=static=util");
            }
        } else {
            println!("cargo:rustc-link-search=native={}", util_dir);
            println!("cargo:rustc-link-lib=static=util");
        }

        #[cfg(target_os = "linux")]
        {
            // Пути к wallycore и secp256k1 (CMake: external/wallycore/lib; secp256k1 — система или external)
            let project_root = std::env::var("KEYHUNT_PROJECT_ROOT").unwrap_or_else(|_| {
                std::path::Path::new(&lib_dir)
                    .parent()
                    .and_then(|p| p.parent())
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "..".into())
            });
            let wally_lib = std::path::Path::new(&project_root).join("external/wallycore/lib");
            if wally_lib.exists() {
                println!("cargo:rustc-link-search=native={}", wally_lib.display());
            }
            // secp256k1 часто в системе (libsecp256k1-dev) или в build
            for secp_path in [
                format!("{}/external/secp256k1/.libs", project_root),
                format!("{}/build/_deps/secp256k1-build", project_root),
                "/usr/lib/x86_64-linux-gnu".to_string(),
            ] {
                if std::path::Path::new(&secp_path).exists() {
                    println!("cargo:rustc-link-search=native={}", secp_path);
                    break;
                }
            }
            println!("cargo:rustc-link-lib=stdc++");
            println!("cargo:rustc-link-lib=pthread");
            println!("cargo:rustc-link-lib=dl");
            println!("cargo:rustc-link-lib=boost_log");
            println!("cargo:rustc-link-lib=boost_log_setup");
            println!("cargo:rustc-link-lib=boost_iostreams");
            println!("cargo:rustc-link-lib=ssl");
            println!("cargo:rustc-link-lib=crypto");
            println!("cargo:rustc-link-lib=wallycore");
            println!("cargo:rustc-link-lib=secp256k1");
        }
        #[cfg(target_os = "windows")]
        println!("cargo:rustc-link-lib=libcmt");
    }
}
