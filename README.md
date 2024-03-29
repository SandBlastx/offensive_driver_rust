
---

# Offensive Driver Project



## Overview

The **Offensive Driver Project** is an initiative aimed at exploring and developing Windows driver with diverse offensive security capabilities. The project comprises a kernel-level driver and a user-space client named `user.exe`. The driver is coded in Rust and adheres to the secure framework for kernel driver development introduced by [Codentium](https://github.com/StephanvanSchaik/windows-kernel-rs). It incorporates techniques and knowledge from the [ZeroPoint Security Offensive Driver course](https://training.zeropointsecurity.co.uk/)."

This README provides an introduction to the project and guidelines for building, using it.

## Features

The user-space client `user.exe` is equipped with various features, including:

- **Process Callback Enumeration**: Enumerate process callbacks in the target process.
- **Process Callback Removal**: Remove specific process callbacks from the target process.
- **Process Unprotection**: Unprotect target process.
- **Process Token Privilege**: Elevate privileges in the target process to full control.
- **Driver Signature Enforcement**: TODO.
- **Add Callback**:TODO.

## Getting Started

### Prerequisites

- **Windows Environment**: This project is designed for the Windows operating system.
- **Rust**: Ensure you have Rust installed. You can download it from [Rust's official website](https://www.rust-lang.org/).

### Build and Run

1. Clone the repository to your local machine:

    ```bash
    git clone https://github.com/SandBlastx/offensive_driver_rust.git
    ```
2. Adjust the build variable in the make file driver\Makefile.toml

3. Build the driver and the user-space client:

    ```bash
    cd driver
    cargo make sign
    ```

4. Load the driver onto your target system (More information in the "Driver Installation" section).

5. Run the `user.exe` client:

    ```bash
    target/release/user.exe --help
    ```

6. Explore the various features of the client by running specific commands.

### Driver Installation

The installation of the offensive driver on a target system is beyond the scope of this README. Consult the ZeroPoint Security Offensive Driver course for more information on how to install and use the driver effectively.

## Usage

- Detailed usage instructions for the user-space client are available by running `user.exe --help`. Each feature is explained along with the associated command-line options.

- **Driver Interaction**: The client interacts with the driver loaded on the target system. The driver provides the necessary functionality to execute client commands.



## Acknowledgments

- Thanks to [Codentium](https://codentium.com/guides/windows-dev/) for it's guides on kernel drivers for Microsoft Windows in Rust.
- Knowledge drawn from the [ZeroPoint Security Offensive Driver course](https://training.zeropointsecurity.co.uk/).
- [memn0ps](https://memn0ps.github.io/) for it's specific technique to dynamically retrieve the "signature_level_offset" of a process.

---




