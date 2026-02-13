// When building with --features cuda, link keyhunt CUDA libs.
// Build the CUDA lib first: from project root:
//   cmake -B build -DCMAKE_CUDA_ARCHITECTURES=86
//   cmake --build build --target keyhunt_cuda_capi
// Then: KEYHUNT_CUDA_LIB_DIR=../build/cuda cargo build --features cuda

fn main() {
    if std::env::var("CARGO_FEATURE_CUDA").is_ok() {
        let lib_dir = std::env::var("KEYHUNT_CUDA_LIB_DIR").unwrap_or_else(|_| "../build/cuda".into());
        println!("cargo:rustc-link-search=native={}", lib_dir);

        // CUDA Toolkit path: cudart_static and driver libs (Linux)
        #[cfg(target_os = "linux")]
        {
            let cuda_root = std::env::var("CUDA_PATH")
                .or_else(|_| std::env::var("CUDA_HOME"))
                .unwrap_or_else(|_| "/usr/local/cuda".to_string());
            let cuda_lib = std::path::Path::new(&cuda_root).join("lib64");
            if cuda_lib.exists() {
                println!("cargo:rustc-link-search=native={}", cuda_lib.display());
            }
        }

        println!("cargo:rustc-link-lib=static=keyhunt_cuda_capi");
        println!("cargo:rustc-link-lib=static=ecc_cuda");
        println!("cargo:rustc-link-lib=cudart_static");
        #[cfg(target_os = "linux")]
        {
            println!("cargo:rustc-link-lib=stdc++");
            // cudart_static may pull in pthread/dl
            println!("cargo:rustc-link-lib=pthread");
            println!("cargo:rustc-link-lib=dl");
        }
        #[cfg(target_os = "windows")]
        println!("cargo:rustc-link-lib=libcmt");
    }
}
