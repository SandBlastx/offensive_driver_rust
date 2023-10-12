#![no_std]

use windows_kernel_rs::callback::{Callback, CallbackInformation, CallbackOperation};
use windows_kernel_rs::device::{
    Completion, Device, DeviceDoFlags, DeviceFlags, DeviceOperations, DeviceType, RequestError,
};
use windows_kernel_rs::process::Process;
use windows_kernel_rs::request::IoControlRequest;
use windows_kernel_rs::token::Token;
use windows_kernel_rs::{kernel_module, println, UserPtr};
use windows_kernel_rs::{
    Access, Driver, Error, KernelModule, RequiredAccess, SymbolicLink, BOOLEAN, HANDLE, PEPROCESS,
    PIMAGE_INFO, PPS_CREATE_NOTIFY_INFO, PUNICODE_STRING,
};

struct Target {
    process: Option<Process>,
    token: Option<Token>,
    callback: Option<Callback>,
}

const IOCTL_SET_TARGET: u32 = 0x803;
const IOCTL_UNPROTECT_TARGET: u32 = 0x804;
const IOCTL_PRIVILEGE_TARGET: u32 = 0x805;
const IOCTL_ENUM_PROCESS_CALLBACK: u32 = 0x806;
const IOCTL_RM_PROCESS_CALLBACK: u32 = 0x807;



impl Target {
    fn set_process(&mut self, request: &IoControlRequest) -> Result<u32, Error> {
        let user_ptr: UserPtr = request.user_ptr();
        match user_ptr.read() {
            Ok(id) => {
                let res_id = Process::by_id(id);
                match res_id {
                    Ok(process) => {
                        self.process = Some(process);
                        let res_token = Token::by_eprocess(self.process.as_ref().unwrap());
                        match res_token {
                            Ok(token) => self.token = Some(token),
                            Err(err) => println!("[!] Unable to set Target token: {:?}", err),
                        }
                        println!("[*] Setting callbacks");
                        self.callback = Some(Callback::new());
                        println!("[*] Target set: {}", self.process.as_ref().unwrap().id());

                        Ok(core::mem::size_of::<u32>() as u32)
                    }
                    Err(err) => {
                        println!("[!] Unable to set Target : {:?}", err);
                        Err(Error::UNSUCCESSFUL)
                    }
                }
            }
            Err(_) => {
                println!("[!] Unable to read Target");
                Err(Error::UNSUCCESSFUL)
            }
        }
    }

    fn unprotecing_process(&self) -> Result<u32, Error> {
        match self.process.as_ref() {
            Some(p) => {
                p.unprotecting();
                Ok(0)
            }
            None => {
                println!("[!] Target process not set ");
                Err(Error::UNSUCCESSFUL)
            }
        }
    }

    fn enable_privilege(&self) -> Result<u32, Error> {
        return match self.token.as_ref() {
            Some(t) => t.enable_privileges(),
            None => {
                println!("[!] Target token not set ");
                Err(Error::UNSUCCESSFUL)
            }
        };
    }

    fn enum_process_callback(&self, request: &IoControlRequest) -> Result<u32, Error> {
        let mut user_ptr: UserPtr = request.user_ptr();
        let len_array = user_ptr.as_slice().len() / core::mem::size_of::<CallbackInformation>();
        if len_array != 64 {
            println!(
                "[!] Wrong size for Callbackinformation array {:}",
                len_array
            )
        }
        unsafe {
            let array_call_back_info = core::slice::from_raw_parts_mut(
                user_ptr.as_mut_slice().as_mut_ptr() as *mut CallbackInformation,
                64,
            );

            match self.callback.as_ref() {
                Some(_) => {
                    Callback::enum_process_callback(array_call_back_info)?;

                    Ok((core::mem::size_of::<CallbackInformation>() * 64) as u32)
                }
                None => {
                    println!("[!] Target callback not set ");
                    Err(Error::UNSUCCESSFUL)
                }
            }
        }
    }

    fn rm_process_callback(&self, request: &IoControlRequest) -> Result<u32, Error> {
        match self.callback.as_ref() {
            Some(_) => {
               
                let user_ptr = request.user_ptr();
                let index = user_ptr.read()?;
                Callback::rm_process_callback(index)?;
                Ok(core::mem::size_of::<u32>() as u32)
            }
            None => {
                println!("[!] Target callback not set ");
                Err(Error::UNSUCCESSFUL)
            }
        }
    }
}

impl DeviceOperations for Target {
    fn ioctl(
        &mut self,
        _device: &Device,
        request: IoControlRequest,
    ) -> Result<Completion, RequestError> {
        let result = match request.function() {
            // (_, IOCTL_PRINT_TARGET) => self.print_id(&request),
            // (RequiredAccess::READ_DATA, IOCTL_READ_TARGET) => self.read_id(&request),
            // (RequiredAccess::WRITE_DATA, IOCTL_WRITE_TARGET) => self.write_id(&request),
            (RequiredAccess::WRITE_DATA, IOCTL_SET_TARGET) => self.set_process(&request),
            (RequiredAccess::ANY_ACCESS, IOCTL_UNPROTECT_TARGET) => self.unprotecing_process(),
            (RequiredAccess::ANY_ACCESS, IOCTL_PRIVILEGE_TARGET) => self.enable_privilege(),
            (_, IOCTL_ENUM_PROCESS_CALLBACK) => self.enum_process_callback(&request),
            (_, IOCTL_RM_PROCESS_CALLBACK) => self.rm_process_callback(&request),
            _ => Err(Error::INVALID_PARAMETER),
        };

        match result {
            Ok(size) => Ok(Completion::Complete(size, request.into())),
            Err(e) => Err(RequestError(e, request.into())),
        }
    }
}

impl CallbackOperation for Target {
    unsafe extern "C" fn process_notify(
        Process: PEPROCESS,
        ProcessId: HANDLE,
        CreateInfo: PPS_CREATE_NOTIFY_INFO,
    ) {
        if CreateInfo.is_null() {
            println!("[+] Callback struct unintiated ");
        }

        if (*CreateInfo)
            .__bindgen_anon_1
            .__bindgen_anon_1
            .FileOpenNameAvailable()
            != 0
        {
            println!(
                "[+] Process Created: {:?} {:?}",
                (*CreateInfo).ImageFileName,
                ProcessId
            );
        }
    }

    unsafe extern "C" fn thread_notify(ProcessId: HANDLE, ThreadId: HANDLE, Create: BOOLEAN) {}

    unsafe extern "C" fn image_notify(
        FullImageName: PUNICODE_STRING,
        ProcessId: HANDLE,
        ImageInfo: PIMAGE_INFO,
    ) {
    }
}
struct Module {
    _device: Device,
    _symbolic_link: SymbolicLink,
    // _callback: Callback,
}

impl KernelModule for Module {
    fn init(mut driver: Driver, _: &str) -> Result<Self, Error> {
        println!("[*]Creating device");
        let device = driver.create_device(
            "\\Device\\PKkS_driver",
            DeviceType::Unknown,
            DeviceFlags::SECURE_OPEN,
            DeviceDoFlags::DO_BUFFERED_IO,
            Access::NonExclusive,
            Target {
                process: None,
                token: None,
                callback: None,
            },
        )?;
        let symbolic_link = SymbolicLink::new("\\??\\PKkS_driver", "\\Device\\PKkS_driver")?;

        //callback.add(CallbackType::ProcessNotify(Some(Target::process_notify)));
        // let result = callback.init();

        Ok(Module {
            _device: device,
            _symbolic_link: symbolic_link,
            // _callback: callback,
        })
    }

    fn cleanup(&mut self, _driver: Driver) {
        println!("Cleaning driver ! ");
    }
}

kernel_module!(Module);
