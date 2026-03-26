fn main() {
    println!("cargo:rustc-check-cfg=cfg(sync_crypto)");
    println!("cargo:rustc-check-cfg=cfg(async_crypto)");
    println!(
        "cargo:rustc-check-cfg=cfg(crypto_backend, values(\"crypto_openssl\", \"crypto_pure_rust\", \"crypto_webcrypto\"))"
    );

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let has_openssl = std::env::var_os("CARGO_FEATURE_CRYPTO_OPENSSL").is_some();
    let has_pure_rust = std::env::var_os("CARGO_FEATURE_CRYPTO_PURE_RUST").is_some();
    let has_webcrypto = std::env::var_os("CARGO_FEATURE_CRYPTO_WEBCRYPTO").is_some();

    if has_webcrypto && target_arch != "wasm32" {
      panic!("`crypto_webcrypto` is only supported on wasm32 targets.");
    }

    let crypto_backend = if has_openssl {
        "crypto_openssl"
    } else if has_webcrypto {
        "crypto_webcrypto"
    } else if has_pure_rust {
        "crypto_pure_rust"
    } else {
        panic!("At least one crypto backend must be enabled")
    };

    let backend_map= std::collections::BTreeMap::from([
        ("crypto_openssl", (true, true)),
        ("crypto_pure_rust", (true, true)),
        ("crypto_webcrypto", (false, true)),
    ]);

    let (sync_crypto, async_crypto) = backend_map.get(crypto_backend).unwrap();

    if *sync_crypto {
        println!("cargo:rustc-cfg=sync_crypto");
    }
    if *async_crypto {
        println!("cargo:rustc-cfg=async_crypto");
    }

    println!("cargo:rustc-cfg=crypto_backend=\"{crypto_backend}\"");
}
