use std::env;
use std::process::Command;

fn main() {
    // Print cargo directives
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=src/");
    
    // Check if we're building for wasm target
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("wasm32") {
        // Additional steps for wasm target
        println!("cargo:rustc-cfg=feature=\"wasm\"");
        
        // Remove native features to avoid compilation errors
        println!("cargo:rustc-cfg=feature=\"not(native)\"");
    } else {
        // Additional steps for native target
        println!("cargo:rustc-cfg=feature=\"native\"");
        
        // Remove wasm features to avoid compilation errors
        println!("cargo:rustc-cfg=feature=\"not(wasm)\"");
    }
} 
