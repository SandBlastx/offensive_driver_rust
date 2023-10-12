use core::ffi::c_void;

use crate::error::{Error, IntoResult};
use crate::println;
use crate::string::create_unicode_string;

use alloc::vec::Vec;
use widestring::U16CString;
use windows_kernel_sys::base::_POOL_TYPE as POOL_TYPE;
use windows_kernel_sys::base::{
    BOOLEAN, HANDLE, PCREATE_PROCESS_NOTIFY_ROUTINE_EX, PCREATE_THREAD_NOTIFY_ROUTINE, PEPROCESS,
    PIMAGE_INFO, PLOAD_IMAGE_NOTIFY_ROUTINE, PPS_CREATE_NOTIFY_INFO, PUNICODE_STRING,
};
use windows_kernel_sys::ntoskrnl::MmGetSystemRoutineAddress;

use windows_kernel_sys::auxklib::{
    AuxKlibInitialize, AuxKlibQueryModuleInformation, AuxModuleExtendedInfo,
};
use windows_kernel_sys::ntoskrnl::{
    strlen, ExAllocatePool, MmIsAddressValid, PsRemoveCreateThreadNotifyRoutine,
    PsRemoveLoadImageNotifyRoutine, PsSetCreateProcessNotifyRoutineEx,
    PsSetCreateThreadNotifyRoutine, PsSetLoadImageNotifyRoutine,
};

#[derive(Copy, Clone, Debug)]
pub enum CallbackType {
    ProcessNotify(PCREATE_PROCESS_NOTIFY_ROUTINE_EX),
    ThreadNotify(PCREATE_THREAD_NOTIFY_ROUTINE),
    ImageNotify(PLOAD_IMAGE_NOTIFY_ROUTINE),
}

pub struct Callback {
    callback: Vec<CallbackType>,
}

#[derive(Copy, Clone, Debug)]
pub struct CallbackInformation {
    pub module_name: [u8; 256],
    pub pointer: u64,
}

impl Default for CallbackInformation {
    fn default() -> Self {
        Self {
            module_name: [0; 256],
            pointer: 0,
        }
    }
}
pub type PcallbackInformation = *mut CallbackInformation;

unsafe impl Send for Callback {}
unsafe impl Sync for Callback {}

impl Callback {
    pub fn new() -> Self {
        Self {
            callback: Vec::new(),
        }
    }

    pub fn add(&mut self, func: CallbackType) {
        self.callback.push(func);
    }
    
    pub fn init(&mut self) {
        for c in self.callback.iter() {
            match c {
                CallbackType::ProcessNotify(p) => unsafe {
                    match PsSetCreateProcessNotifyRoutineEx(*p, 1).into_result() {
                        Ok(_) => println!("[*] Process callback loaded."),
                        Err(e) => println!("[!] Process callback error loading {:?}", e),
                    }
                },
                CallbackType::ThreadNotify(t) => unsafe {
                    match PsSetCreateThreadNotifyRoutine(*t).into_result() {
                        Ok(_) => println!("[*] Thread callback loaded."),
                        Err(e) => println!("[!] Thread callback error loading {:?}", e),
                    }
                },
                CallbackType::ImageNotify(i) => unsafe {
                    match PsSetLoadImageNotifyRoutine(*i).into_result() {
                        Ok(_) => println!("[*] Image callback loaded."),
                        Err(e) => println!("[!] Image callback error loading {:?}", e),
                    }
                },
            }
        }
    }

    pub fn find_psp_set_create_process_notify() -> Result<&'static mut [u64], Error> {
        println!("[*] Find PspSetcreateProcessNotify ...");
        const OPCODE_CALL: u8 = 0xE8;
        const OPCODE_JMP: u8 = 0xE9;

        let function_name = U16CString::from_str("PsSetCreateProcessNotifyRoutine").unwrap();
        let mut function_name = create_unicode_string(function_name.as_slice());

        let ps_set_create_process_notify = unsafe { MmGetSystemRoutineAddress(&mut function_name) };
        if ps_set_create_process_notify.is_null() {
            println!("[!] Failed to find PsSetCreateProcessNotifyRoutine");
        }
        println!(
            "[+] PsSetCreateProcessNotifyRoutine found @ {:?}",
            ps_set_create_process_notify
        );

        let mut psp_set_create_process_notify: *const u8 = core::ptr::null();

        let ps_set_create_process_notify_slice =
            unsafe { core::slice::from_raw_parts(ps_set_create_process_notify as *const u8, 0x14) };

        if let Some(index_1) = ps_set_create_process_notify_slice
            .iter()
            .position(|&a| a == OPCODE_CALL || a == OPCODE_JMP)
        {
            println!("[+] CALL/JMP found at offset {}", index_1);

            let offset = u32::from_le_bytes(
                ps_set_create_process_notify_slice[index_1 + 1..index_1 + 5]
                    .try_into()
                    .unwrap(),
            );

            psp_set_create_process_notify =
                (unsafe { ps_set_create_process_notify.offset(index_1 as _) } as u64
                    + offset as u64
                    + 5) as _;

            if psp_set_create_process_notify.is_null() {
                println!("[+] Failed to find PspSetCreateProcessNotifyRoutine");
                return Err(Error::INVALID_HANDLE);
            }

            println!(
                "[+] PspSetCreateProcessNotifyRoutine found @ {:?}",
                psp_set_create_process_notify
            );

            let psp_set_create_process_notify_slice: &[u8] =
                unsafe { core::slice::from_raw_parts(psp_set_create_process_notify, 0x70) };
            //https://github.com/memN0ps/rootkit-rs/blob/master/driver/src/process/mod.rs
            let needle = [0x4c, 0x8D]; //lea r13,

            if let Some(y) = psp_set_create_process_notify_slice
                .windows(needle.len())
                .position(|x| *x == needle)
            {
                let position = y + 3; // 3 byte after lea r13, is the offset
                let offset_slice = &psp_set_create_process_notify_slice[position..position + 4]; //u32::from_le_bytes takes 4 slices
                let offset = u32::from_le_bytes(offset_slice.try_into().unwrap());
                let new_base = unsafe { psp_set_create_process_notify.cast::<u8>().offset(0x62) }; // +0x62 is lea r13,[nt!PspCreateProcessNotifyRoutine (<address>)]
                let new_offset = offset + 0x7; // offset + 6: because i is a the start of lea and not the end
                let psp_set_create_process_notify_array =
                    unsafe { new_base.cast::<u8>().offset(new_offset as isize) };

                let slice: &mut [u64] = unsafe {
                    core::slice::from_raw_parts_mut(
                        psp_set_create_process_notify_array as *mut u64,
                        64,
                    )
                };

                return Ok(slice);
            }
            println!(
                "[!] Unable to find the instruction LEA containing PspCreateProcessNotifyRoutine"
            );
            return Err(Error::INVALID_HANDLE);
        }

        println!("[!] Unable to find the instruction CALL containing PsCreateProcessNotifyRoutine");
        return Err(Error::INVALID_HANDLE);
    }

    pub fn rm_process_callback(index: u8) -> Result<(), Error> {
        println!("[*] Rm {}", index);
        let psp_array = Callback::find_psp_set_create_process_notify()?;

        psp_array[index as usize] = 0;

        Ok(())
    }

    pub fn search_loaded_modules(
        modules: &mut Vec<AuxModuleExtendedInfo>,
        callbacks_info: *mut CallbackInformation,
    ) {
        for m in modules {
            let start_address = m.basic_info.image_base as u64;
            let image_size = m.image_size;

            let end_address = start_address + image_size as u64;
            let raw_pointer =
                unsafe { *(((*callbacks_info).pointer & 0xfffffffffffffff8) as *mut u64) };
            if raw_pointer > start_address && raw_pointer < end_address {
                let module_name_dst = unsafe { (*callbacks_info).module_name.as_mut() };

                let module_name_src = unsafe {
                    m.full_path_name
                        .as_mut_ptr()
                        .offset(m.file_name_offset as _)
                };

                let name_len = unsafe { strlen(module_name_src as *const i8) };

                unsafe {
                    core::ptr::copy_nonoverlapping(
                        module_name_src,
                        module_name_dst.as_mut_ptr(),
                        name_len as _,
                    )
                };
                break;
            }
        }
    }

    fn get_module_array() -> Result<Vec<AuxModuleExtendedInfo>, Error> {
        let mut sz_buffer = 0;

        // Initialize the auxiliary library
        let status = unsafe { AuxKlibInitialize() };
        if status != 0 {
            println!("[!] AuxKlibInitialize failed {:#x}", status);
            return Err(Error::INVALID_HANDLE);
        }

        // Run once to get the required buffer size
        let status = unsafe {
            AuxKlibQueryModuleInformation(
                &mut sz_buffer,
                core::mem::size_of::<AuxModuleExtendedInfo>() as u32,
                core::ptr::null_mut(),
            )
        };
        if status != 0 {
            println!("[!] AuxKlibQueryModuleInformation failed (0x{:#x})", status);
            return Err(Error::INVALID_HANDLE);
        }

        let nb = sz_buffer / core::mem::size_of::<AuxModuleExtendedInfo>() as u32;
        // Allocate memory
        let mut buffer: Vec<AuxModuleExtendedInfo> = Vec::with_capacity(nb as usize);
        unsafe { buffer.set_len(nb as _) };

        let status = unsafe {
            AuxKlibQueryModuleInformation(
                &mut sz_buffer,
                core::mem::size_of::<AuxModuleExtendedInfo>() as u32,
                buffer.as_mut_ptr() as _,
            )
        };
        if status != 0 {
            println!("[!] AuxKlibQueryModuleInformation failed (0x{:#x})", status);
            return Err(Error::INVALID_HANDLE);
        }

        return Ok(buffer);
    }

    pub fn enum_process_callback(callback_array: &mut [CallbackInformation]) -> Result<u32, Error> {
        let psp_array = Callback::find_psp_set_create_process_notify()?;

        let mut module_array = Callback::get_module_array()?;

        for i in 0..64 {
            callback_array[i].pointer = psp_array[i];

            if callback_array[i].pointer > 0 {
                Callback::search_loaded_modules(&mut module_array, &mut callback_array[i]);
                if let Ok(name) = core::str::from_utf8(&callback_array[i].module_name) {
                    println!("{:x} from {}", callback_array[i].pointer, name);
                } else {
                    println!("{:x} with invalid module name", callback_array[i].pointer);
                }
            }
        }

        return Ok(1);
    }
}

pub trait CallbackOperation {
    unsafe extern "C" fn process_notify(
        Process: PEPROCESS,
        ProcessId: HANDLE,
        CreateInfo: PPS_CREATE_NOTIFY_INFO,
    ) {
    }

    unsafe extern "C" fn thread_notify(ProcessId: HANDLE, ThreadId: HANDLE, Create: BOOLEAN) {}

    unsafe extern "C" fn image_notify(
        FullImageName: PUNICODE_STRING,
        ProcessId: HANDLE,
        ImageInfo: PIMAGE_INFO,
    ) {
    }
}

impl Drop for Callback {
    fn drop(&mut self) {
        for c in self.callback.iter() {
            {
                match c {
                    CallbackType::ProcessNotify(f) => unsafe {
                        match PsSetCreateProcessNotifyRoutineEx(*f, 0).into_result() {
                            Ok(_) => println!("[*] Process callback unloaded."),
                            Err(e) => println!("[!] Process callback error unloading {:?}", e),
                        }
                    },
                    CallbackType::ThreadNotify(f) => unsafe {
                        match PsRemoveCreateThreadNotifyRoutine(*f).into_result() {
                            Ok(_) => println!("[*] Thread callback unloaded."),
                            Err(e) => println!("[!] Thread callback error unloading {:?}", e),
                        };
                    },
                    CallbackType::ImageNotify(f) => unsafe {
                        match PsRemoveLoadImageNotifyRoutine(*f).into_result() {
                            Ok(_) => println!("[*] Image callback unloaded."),
                            Err(e) => println!("[!] Image callback error unloading {:?}", e),
                        };
                    },
                }
            }
        }
    }
}
