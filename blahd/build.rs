fn main() {
    // No rerun on file changes.
    println!("cargo::rerun-if-changed=build.rs");

    println!("cargo::rerun-if-env-changed=CFG_RELEASE");
    if std::env::var_os("CFG_RELEASE").is_none() {
        let vers = std::env::var("CARGO_PKG_VERSION").expect("cargo should set it");
        println!("cargo::rustc-env=CFG_RELEASE={vers}");
    }

    println!("cargo::rerun-if-env-changed=CFG_SRC_URL");
    if let Some(url) = std::env::var_os("CFG_SRC_URL") {
        url.to_str()
            .expect("CFG_SRC_URL is not in UTF-8")
            .parse::<url::Url>()
            .expect("CFG_SRC_URL is not a valid URL");
    } else {
        println!("cargo::warning=CFG_SRC_URL is not set");
    }
}
