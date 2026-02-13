// When building with --features cuda, link keyhunt CUDA libs.
// Build the CUDA lib first: from project root:
//   cmake -B build -DCMAKE_CUDA_ARCHITECTURES=86
//   cmake --build build --target keyhunt_cuda_capi
// Then: KEYHUNT_CUDA_LIB_DIR=../build cargo build --features cuda

fn main() {
    if std::env::var("CARGO_FEATURE_CUDA").is_ok() {
        let lib_dir = std::env::var("KEYHUNT_CUDA_LIB_DIR").unwrap_or_else(|_| "../build".into());
        println!("cargo:rustc-link-search=native={}", lib_dir);
        println!("cargo:rustc-link-lib=static=keyhunt_cuda_capi");
        println!("cargo:rustc-link-lib=static=ecc_cuda");
        println!("cargo:rustc-link-lib=cudart_static");
        #[cfg(target_os = "linux")]
        println!("cargo:rustc-link-lib=stdc++");
        #[cfg(target_os = "windows")]
        println!("cargo:rustc-link-lib=libcmt");
    }
}
