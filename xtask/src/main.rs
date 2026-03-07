use clap::{Parser, Subcommand};
use std::process::Command;

#[derive(Parser)]
#[command(name = "xtask", about = "Build helper for neko-firewall")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the eBPF program
    BuildEbpf {
        /// Build in release mode
        #[arg(long, default_value_t = true)]
        release: bool,
    },
    /// Build everything (eBPF + userspace)
    Build {
        /// Build in release mode
        #[arg(long, default_value_t = true)]
        release: bool,
    },
    /// Build and run the firewall
    Run {
        /// Interface to attach to
        #[arg(short, long, default_value = "lo")]
        iface: String,
        /// Extra arguments passed to neko-firewall
        #[arg(last = true)]
        args: Vec<String>,
    },
}

fn build_ebpf(release: bool) {
    let mut cmd = Command::new("cargo");
    cmd.current_dir("neko-ebpf");
    cmd.env_remove("RUSTUP_TOOLCHAIN");
    cmd.args([
        "+nightly",
        "build",
        "--target=bpfel-unknown-none",
        "-Z",
        "build-std=core",
        "--target-dir=../target",
    ]);
    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .expect("Failed to execute cargo build for eBPF");

    if !status.success() {
        eprintln!("eBPF build failed");
        std::process::exit(1);
    }

    println!("eBPF program built successfully");
}

fn build_userspace(release: bool) {
    let mut cmd = Command::new("cargo");
    cmd.args(["build", "--package", "neko-firewall"]);
    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .expect("Failed to execute cargo build for userspace");

    if !status.success() {
        eprintln!("Userspace build failed");
        std::process::exit(1);
    }

    println!("Userspace program built successfully");
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::BuildEbpf { release } => {
            build_ebpf(release);
        }
        Commands::Build { release } => {
            build_ebpf(release);
            build_userspace(release);
        }
        Commands::Run { iface, args } => {
            build_ebpf(true);
            build_userspace(true);

            let mut cmd = Command::new("sudo");
            cmd.args([
                "target/release/neko-firewall",
                "run",
                "-i",
                &iface,
            ]);
            cmd.args(&args);

            let status = cmd
                .status()
                .expect("Failed to run neko-firewall");

            if !status.success() {
                std::process::exit(1);
            }
        }
    }
}
