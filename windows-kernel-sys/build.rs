use bindgen::callbacks::*;
use std::path::PathBuf;
use windows_kernel_build::get_km_dir;
use windows_kernel_build::DirectoryType;

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
        Some(match name {
            "TRUE" | "FALSE" => IntKind::UChar,
            _ => return None,
        })
    }
}

fn generate_base() {
    println!("cargo:rerun-if-changed=src/wrapper.h");

    let include_dir = windows_kernel_build::get_km_dir(DirectoryType::Include).unwrap();
    let out_path = PathBuf::from(
        std::env::var_os("OUT_DIR").expect("the environment variable OUT_DIR is undefined"),
    );

    bindgen::Builder::default()
        .header("src/wrapper.h")
        .use_core()
        .derive_debug(false)
        .layout_tests(false)
        .ctypes_prefix("cty")
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .clang_arg(format!("-I{}", include_dir.to_str().unwrap()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .parse_callbacks(Box::new(Callbacks))
        .ignore_functions()
        .generate()
        .unwrap()
        .write_to_file(out_path.join("base.rs"))
        .unwrap();
}

#[cfg(feature = "auxklib")]
fn generate_auxlib() {
    println!("cargo:rerun-if-changed=src/wrapper_auxklib.h");
    
    println!("cargo:rustc-link-lib=aux_klib");
    
    
        let include_dir = windows_kernel_build::get_km_dir(DirectoryType::Include).unwrap();
        let out_path = PathBuf::from(
            std::env::var_os("OUT_DIR").expect("the environment variable OUT_DIR is undefined"),
        );
        bindgen::Builder::default()
            .header("src/wrapper_auxklib.h")
            .use_core()
            .derive_debug(false)
            .layout_tests(false)
            .ctypes_prefix("cty")
            .default_enum_style(bindgen::EnumVariation::ModuleConsts)
            .clang_arg(format!("-I{}", include_dir.to_str().unwrap()))
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .allowlist_function("AuxKlibInitialize")
            .allowlist_function("AuxKlibQueryModuleInformation")
            .allowlist_recursively(false)
            .generate()
            .unwrap()
            .write_to_file(out_path.join("auxklib.rs"))
            .unwrap();
}

#[cfg(not(feature = "auxklib"))]
fn generate_auxlib() {
    // Empty implementation when the "auxklib" feature is not enabled.
}

#[cfg(feature = "intrin")]
fn generate_intrin() {
    println!("cargo:rerun-if-changed=src/wrapper_intrin.c");

    let include_dir = windows_kernel_build::get_km_dir(DirectoryType::Include).unwrap();

    cc::Build::new()
        .flag("/kernel")
        .include(include_dir)
        .file("src/wrapper_intrin.c")
        .compile("wrapper_intrin");
}

#[cfg(not(feature = "intrin"))]
fn generate_intrin() {}

#[cfg(feature = "ntoskrnl")]
fn generate_ntoskrnl() {
    println!("cargo:rerun-if-changed=src/wrapper.h");
    println!("cargo:rerun-if-changed=src/wrapper.c");
    println!("cargo:rustc-link-lib=ntoskrnl");
    println!("cargo:rustc-link-lib=bufferoverflowfastfailk");
    

    let include_dir = windows_kernel_build::get_km_dir(DirectoryType::Include).unwrap();
    let out_path = PathBuf::from(
        std::env::var_os("OUT_DIR").expect("the environment variable OUT_DIR is undefined"),
    );

    bindgen::Builder::default()
        .header("src/wrapper.h")
        .use_core()
        .derive_debug(false)
        .layout_tests(false)
        .ctypes_prefix("cty")
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .clang_arg(format!("-I{}", include_dir.to_str().unwrap()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .blocklist_type(".*")
        .allowlist_function(".*")
        .allowlist_recursively(false)
        .generate()
        .unwrap()
        .write_to_file(out_path.join("ntoskrnl.rs"))
        .unwrap();

    cc::Build::new()
        .flag("/kernel")
        .include(include_dir)
        .file("src/wrapper.c")
        .compile("wrapper_ntoskrnl");

        
}

#[cfg(not(feature = "ntoskrnl"))]
fn generate_ntoskrnl() {}

#[cfg(feature = "netio")]
fn generate_netio() {
    println!("cargo:rerun-if-changed=src/wrapper_netio.h");
    println!("cargo:rustc-link-lib=netio");

    let include_dir = windows_kernel_build::get_km_dir(DirectoryType::Include).unwrap();
    let out_path = PathBuf::from(
        std::env::var_os("OUT_DIR").expect("the environment variable OUT_DIR is undefined"),
    );

    bindgen::Builder::default()
        .header("src/wrapper.h")
        .use_core()
        .derive_debug(false)
        .layout_tests(false)
        .ctypes_prefix("cty")
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .clang_arg(format!("-I{}", include_dir.to_str().unwrap()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .blocklist_type(".*")
        .allowlist_function(".*")
        .allowlist_recursively(false)
        .generate()
        .unwrap()
        .write_to_file(out_path.join("netio.rs"))
        .unwrap();
}

#[cfg(not(feature = "netio"))]
fn generate_netio() {}

fn main() {
    let dir = get_km_dir(DirectoryType::Library).unwrap();

    // Append the architecture based on our target.
    let target = std::env::var("TARGET").unwrap();

    let arch = if target.contains("x86_64") {
        "x64"
    } else if target.contains("i686") {
        "x86"
    } else {
        panic!("The target {} is currently not supported.", target);
    };

    let dir = dir.join(arch);
    // println!("cargo:rustc-link-search=C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.22621.0\\km\\x64");
    println!("cargo:rustc-link-search=native={}", dir.to_str().unwrap());
    println!("cargo:rerun-if-changed=build.rs");

    generate_base();
    generate_intrin();
    generate_ntoskrnl();
    generate_netio();
    generate_auxlib();
}
