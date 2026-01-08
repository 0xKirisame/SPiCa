use std::process::Command;
use std::path::PathBuf;
use clap::Parser;
use anyhow::Context;

#[derive(Parser)]
struct Options {
    #[clap(subcommand)]
    command: CommandOpts,
}

#[derive(Parser)]
enum CommandOpts {
    /// Build the eBPF program
    BuildEbpf {
        /// Build for release (optimized)
        #[clap(long)]
        release: bool,
    },
}

fn main() -> Result<(), anyhow::Error> {
    let opts = Options::parse();

    match opts.command {
        CommandOpts::BuildEbpf { release } => {
            // 1. Define the target (BPF Bytecode)
            let target = "bpfel-unknown-none";
            
            // 2. Construct the cargo command
            let mut args = vec![
                "build",
                "--package", "spica-ebpf",
                "--target", target,
                "-Z", "build-std=core", // Required for no_std builds
            ];

            if release {
                args.push("--release");
            }

            // 3. Execute
            let status = Command::new("cargo")
                .args(&args)
                .status()
                .context("Failed to run cargo build for eBPF")?;

            if !status.success() {
                anyhow::bail!("eBPF build failed");
            }
            
            println!("✨ eBPF Kernel Probe compiled successfully!");
            Ok(())
        }
    }
}
