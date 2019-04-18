use std::fs;
use std::process::Command;

fn fail_on_empty_directory(name: &str) {
    if fs::read_dir(name).unwrap().count() == 0 {
        println!(
            "The `{}` directory is empty, did you forget to pull the submodules?",
            name
        );
        println!("Try `git submodule update --init --recursive`");
        panic!();
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=mcl/");
    println!("cargo:rerun-if-changed=bls/");

    fail_on_empty_directory("mcl");
    fail_on_empty_directory("bls");

    println!("cargo:rustc-link-lib=static=bls384_256");
    println!("cargo:rustc-link-lib=static=mcl");
    println!("cargo:rustc-link-lib=static=mclshe256");
    println!("cargo:rustc-link-lib=static=mclbn384_256");
    println!("cargo:rustc-link-search=bls/lib");
    println!("cargo:rustc-link-search=mcl/lib");

    // makefile is using a special env variable
    Command::new("make")
        .current_dir("bls")
        .arg("all")
        .arg("MCL_USE_GMP=0")
        .arg("MCL_USE_OPENSSL=0")
        .status()
        .expect("failed to make!");
}
