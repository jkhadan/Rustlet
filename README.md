# Rustlet: Your Own Container Runtime in Rust

[![Rust](https://img.shields.io/badge/rust-1.88+-blue.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](https://opensource.org/licenses/Apache-2.0)

Rustlet is an educational, open-source project aimed at building a functional, albeit simplified, container runtime from scratch using the Rust programming language. Inspired by the core principles of Docker and OCI (Open Container Initiative) runtimes like `runc`, Rustlet aims to showcase how containers work at a low level, leveraging Linux namespaces, cgroups, and union filesystems directly.

**This project is for learning purposes and is not intended for production use.**

## 🚀 What is Rustlet (Wide Angle)?

Imagine you want to understand exactly what happens when you type `docker run ubuntu echo hello`. Docker does a lot of complex work behind the scenes to:

1.  **Fetch an Image:** Download a filesystem and metadata for "ubuntu" from a registry.
2.  **Prepare a Filesystem:** Create a isolated filesystem view for the container, often using layered filesystems.
3.  **Isolate Resources:** Use Linux kernel features like **namespaces** to give the container its own view of PIDs, network, mounts, users, etc.
4.  **Limit Resources:** Use **cgroups** to control how much CPU, memory, and I/O the container can consume.
5.  **Run the Application:** Execute the `echo hello` command within this isolated and resource-controlled environment.

**Rustlet aims to replicate these core functionalities.** By building Rustlet, you'll gain a deep understanding of:

*   **Linux System Calls:** Directly interacting with the kernel for process isolation and resource management.
*   **Rust's Async Capabilities:** Managing multiple container operations concurrently.
*   **Container Technologies:** The underlying mechanisms that make containerization possible.
*   **OCI Standards:** How container images and runtimes are specified.

## 🛠️ Getting Started for New Rust Developers

Rustle leverages the Rust ecosystem and standard Linux tools.

### Prerequisites

*   **Rust Toolchain:** You need to have Rust and Cargo installed. If you don't, follow the official installation guide: [https://www.rust-lang.org/tools/install](https://www.rust-lang.org/tools/install)
*   **Linux Environment:** Rustlet is designed for Linux systems due to its heavy reliance on Linux-specific kernel features (namespaces, cgroups, OverlayFS).
*   **Root Privileges:** Running containers typically requires root privileges to manipulate namespaces and cgroups.
*   **Standard Linux Tools:** Familiarity with tools like `mount`, `chroot`, `tar`, and `iptables` (though Rustlet will abstract these) is helpful.

### 1. Cloning the Repository

First, clone this project to your local machine:

```bash
git clone <your-repository-url> # Replace with your actual Git repository URL
cd my-container-runtime # Or the name of your project directory
```



### 2. Building Rustlet

Rust uses `cargo`, its build system and package manager, to compile and manage your project. For development, `cargo` offers several convenient commands.

#### Building for Development (`cargo build`)

This command compiles your project's code, checking for errors and creating an executable. By default, it builds in "debug mode," which includes extra checks and is slower than a release build but excellent for finding bugs.

```bash
cargo build
```

After running this, the compiled executable will be located at:
`./target/debug/rustlet`

You can then run it (remembering you'll need `sudo` for full functionality):

```bash
sudo ./target/debug/rustlet <command> [arguments...]
# Example: sudo ./target/debug/rustlet run --image ubuntu echo hello
```

#### Building for Release (`cargo build --release`)

When you're ready to optimize your code for performance or distribute it, you use the `--release` flag. This performs extensive optimizations, making the executable faster and smaller.

```bash
cargo build --release
```

The optimized executable will be placed here:
`./target/release/rustlet`

Run it using:

```bash
sudo ./target/release/rustlet <command> [arguments...]
# Example: sudo ./target/release/rustlet run --image ubuntu echo hello
```

#### Running Directly with `cargo run` (Build & Run)

This is often the **most convenient command for day-to-day development**. `cargo run` first builds your project (if it detects changes) and then immediately runs the resulting executable.

```bash
cargo run
```

If your `src/main.rs` has a simple `println!("Hello, world!");` and no arguments are passed, this will just print "Hello, world!".

To pass arguments to your Rustlet executable when using `cargo run`, use `--` after `cargo run`:

```bash
cargo run -- <command> [arguments...]
# Example: cargo run -- run --image ubuntu echo hello
```

**Important Note on `sudo` with `cargo run`:**
You **cannot** directly use `sudo cargo run` because `sudo` would execute `cargo` itself as root, not the resulting executable. If your Rust code needs root privileges (which Rustlet's will), you'll run `cargo run` normally and then execute the resulting binary with `sudo`:

1.  Run `cargo run` (or `cargo run -- ...` for arguments).
2.  Once it's built and running, you can stop it (usually with Ctrl+C) and then re-run the executable with `sudo` if needed for further testing with root privileges.

**For testing root-required functionality:**
It's often best to build with `cargo build --release` and then explicitly run the release binary with `sudo`:

```bash
sudo ./target/release/rustlet run --image ubuntu echo hello
```

This separation helps you manage when root privileges are actually required.



### 3. Running a Basic Container (Conceptual Example)

Rustlet will have several commands, similar to Docker. A common starting point is a `run` command.

**Note:** This is a conceptual example, as the actual implementation of image pulling, filesystem setup, and resource management needs to be built.

Let's assume a very basic `run` command that expects an image name and a command to execute:

```bash
sudo ./target/release/rustlet run --image ubuntu echo "Hello from Rustlet!"
```

**For the initial development phase, you might have a simpler command to test basic isolation:**

```bash
# Example: Testing PID and Mount Namespaces
# Create a simple 'spec.json' (you'll define this later)
# echo '{ "process": { "command": ["/bin/sh"], "args": ["-sh"], "cwd": "/" } }' > container.json

# Then run it (this is illustrative, actual cmd might be different)
sudo ./target/release/rustlet create --config container.json my_container_1
# And then start the container
# sudo ./target/release/rustlet start my_container_1
```

**Important:** The `sudo` is crucial because manipulating namespaces and cgroups requires elevated privileges.

## 📚 Project Structure

```
my-container-runtime/
├── Cargo.toml          # Project manifest (dependencies, metadata)
├── README.md           # This file!
└── src/                # Source code
    ├── main.rs         # Entry point of the executable, CLI argument parsing
    ├── runtime/        # Core container runtime logic (OCI spec, process management)
    │   ├── mod.rs
    │   ├── spec.rs     # Parsing OCI `config.json` and `spec.json`
    │   ├── process.rs  # Setting up namespaces, cgroups, execing the process
    │   └── filesystem.rs # Mounting rootfs, overlayfs
    ├── image/          # Image handling (pulling from registries, unpacking layers)
    │   ├── mod.rs
    │   ├── client.rs   # OCI registry interaction
    │   └── unpack.rs   # Logic for unpacking tar.gz layers
    ├── network/        # Network configuration for containers
    │   ├── mod.rs
    │   └── bridge.rs   # Setting up virtual network interfaces
    ├── cgroups/        # Management of Linux Control Groups (cgroups)
    │   ├── mod.rs
    │   └── manager.rs  # Defining limits, assigning processes
    ├── utils/          # Common utilities, error types, helpers
    │   ├── mod.rs
    │   └── error.rs    # Custom error definitions
    ├── cli/            # CLI command parsing and structure
    │   ├── mod.rs
    │   └── commands.rs # Defines subcommands like 'run', 'create', 'start'
    └── config.rs       # Global configuration, paths, etc. (optional)
```

## 🚀 Commands (Planned)

Rustlet will aim to support a subset of common container commands:

*   `rustlet run <image> [command...]`: Creates and runs a new container from an image.
*   `rustlet create <image>`: Creates a new container from an image but does not start it.
*   `rustlet start <container-id>`: Starts a created but stopped container.
*   `rustlet stop <container-id>`: Stops a running container.
*   `rustlet ps`: Lists running containers.
*   `rustlet pull <image>`: Downloads an image from an OCI registry.
*   `rustlet logs <container-id>`: Fetches the logs of a container.

## 📚 Learning Rust While Building

This project is an excellent way to learn Rust:

*   **`Cargo.toml` Dependency Management:** You'll learn to add and manage libraries (crates) using Cargo. Essential crates for this project include:
    *   `nix`: For low-level POSIX system calls (namespaces, fork, mount, etc.).
    *   `tokio` or `async-std`: For asynchronous programming, crucial for managing multiple containers and I/O operations.
    *   `serde` & `serde_json`: For handling OCI configuration files (JSON).
    *   `clap`: For building a robust command-line interface.
    *   `tar`: For unpacking OCI image layers.
    *   `thiserror` & `anyhow`: For powerful error handling.
    *   `oci-distribution`: For interacting with container registries.

*   **Error Handling:** Rust forces you to think about errors from the start. Using `Result` and crates like `thiserror` will become second nature.
*   **Ownership and Borrowing:** You'll constantly be interacting with Rust's memory safety features.
*   **Modules and Organization:** Keeping your codebase clean and maintainable using Rust's module system.
*   **Async/Await:** Mastering Rust's concurrency model is key for a responsive container runtime.

## 🤔 How This Project Works (Under the Hood)

1.  **Command Parsing:** The `cli` module uses `clap` to parse user commands and arguments.
2.  **Image Handling:** If a `run` or `create` command is used, the `image` module is responsible for fetching the specified image from an OCI registry (like Docker Hub) and unpacking its layers using `tar`.
3.  **Filesystem Setup:** A temporary directory is prepared and layered using **OverlayFS** (via the `mount` syscall, accessed through `nix`) to create the container's root filesystem.
4.  **Namespace Creation:** The `runtime::process` module uses `nix::sched::unshare` to create new namespaces for the container's PID, network, mounts, user, UTS, and IPC.
5.  **Cgroup Setup:** The `cgroups` module interacts with the Linux cgroups filesystem to create resource control groups and assign CPU/memory limits. The container process will be placed into these groups.
6.  **Process Execution:** A new process is forked. The child process reaps the benefits of the new namespaces and cgroups. Crucially, it uses `execvp` (via `nix`) to replace itself with the command specified for the container (e.g., `/bin/sh` or `/usr/bin/echo`).
7.  **Networking:** The `network` module sets up a virtual network interface (like a `tun/tap` device) and configures bridging and NAT rules (often via `iptables` or `nftables`) to allow the container to communicate with the host and the outside world.

## 🔗 Contributing

We welcome contributions! Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file (which you'll want to create!) for details on how to contribute, our code of conduct, and development guidelines.

## 📜 License

This project is licensed under the MIT License and Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
