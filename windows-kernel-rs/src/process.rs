use crate::error::{Error, IntoResult};
use crate::println;
use crate::string::create_unicode_string;
use bitflags::bitflags;
use widestring::U16CString;
use windows_kernel_sys::base::{
    CLIENT_ID, HANDLE, KAPC_STATE, OBJECT_ATTRIBUTES, PEPROCESS, PPROCESS_PROTECTION_INFO,
};
use windows_kernel_sys::ntoskrnl::MmGetSystemRoutineAddress;
use windows_kernel_sys::ntoskrnl::{KeStackAttachProcess, KeUnstackDetachProcess};
use windows_kernel_sys::ntoskrnl::{ObDereferenceObject, ObReferenceObject};
use windows_kernel_sys::ntoskrnl::{PsGetCurrentProcess, PsLookupProcessByProcessId};
use windows_kernel_sys::ntoskrnl::{ZwClose, ZwOpenProcess};
pub type ProcessId = usize;

#[derive(Clone, Debug)]
pub struct Process {
    pub process: PEPROCESS,
}


unsafe impl Send for Process {}
unsafe impl Sync for Process {}

impl Process {
    pub fn as_ptr(&self) -> PEPROCESS {
        self.process
    }

    pub fn current() -> Self {
        let process = unsafe { PsGetCurrentProcess() };

        unsafe {
            ObReferenceObject(process as _);
        }

        Self { process }
    }

    pub fn by_id(process_id: ProcessId) -> Result<Self, Error> {
        let mut process = core::ptr::null_mut();

        unsafe { PsLookupProcessByProcessId(process_id as _, &mut process) }.into_result()?;

        Ok(Self { process })
    }

    pub fn id(&self) -> ProcessId {
        let handle = unsafe { windows_kernel_sys::ntoskrnl::PsGetProcessId(self.process) };

        handle as _
    }

    pub fn attach(&self) -> ProcessAttachment {
        unsafe { ProcessAttachment::attach(self.process) }
    }

    pub fn signature_level_offset() -> isize {
        // Convert the name to UTF-16 and then create a UNICODE_STRING.
        let function_name = U16CString::from_str("PsGetProcessSignatureLevel").unwrap();
        let mut function_name = create_unicode_string(function_name.as_slice());

        let base_address = unsafe { MmGetSystemRoutineAddress(&mut function_name) };
        let function_bytes: &[u8] = unsafe { core::slice::from_raw_parts(base_address as *const u8, 20) };

        let slice = &function_bytes[15..17];
        let signature_level_offset = u16::from_le_bytes(slice.try_into().unwrap());

        println!("[-] EPROCESS_sign_offset : {}", signature_level_offset);

        return signature_level_offset as isize;
    }

    pub fn unprotecting(&self)  {

        let signature_level_offset = Process::signature_level_offset();

        let ps_protection = unsafe {
            self.as_ptr().cast::<u8>().offset(signature_level_offset) as PPROCESS_PROTECTION_INFO
        };

        unsafe {
            (*ps_protection).SignatureLevel = 0;
            (*ps_protection).SectionSignatureLevel = 0;
            (*ps_protection).Protection.set_Signer(0);
            (*ps_protection).Protection.set_Type(0);
            (*ps_protection).Protection.set_Audit(0);
        }

        println!("[-] Unprotecting process id: {}", self.id());
        
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            ObDereferenceObject(self.process as _);
        }
    }
}

pub struct ProcessAttachment {
    process: PEPROCESS,
    state: KAPC_STATE,
}

impl ProcessAttachment {
    pub unsafe fn attach(process: PEPROCESS) -> Self {
        let mut state: KAPC_STATE = core::mem::zeroed();

        ObReferenceObject(process as _);
        KeStackAttachProcess(process, &mut state);

        Self { process, state }
    }
}

impl Drop for ProcessAttachment {
    fn drop(&mut self) {
        unsafe {
            KeUnstackDetachProcess(&mut self.state);
            ObDereferenceObject(self.process as _);
        }
    }
}

bitflags! {
    pub struct ProcessAccess: u32 {
        const ALL_ACCESS = windows_kernel_sys::base::PROCESS_ALL_ACCESS;
    }
}

pub struct ZwProcess {
    pub(crate) handle: HANDLE,
}

impl ZwProcess {
    pub fn open(id: ProcessId, access: ProcessAccess) -> Result<Self, Error> {
        let mut attrs: OBJECT_ATTRIBUTES = unsafe { core::mem::zeroed() };
        attrs.Length = core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;

        let mut client_id = CLIENT_ID {
            UniqueProcess: id as _,
            UniqueThread: core::ptr::null_mut(),
        };

        let mut handle = core::ptr::null_mut();

        unsafe { ZwOpenProcess(&mut handle, access.bits(), &mut attrs, &mut client_id) }
            .into_result()?;

        Ok(Self { handle })
    }
}

impl Drop for ZwProcess {
    fn drop(&mut self) {
        unsafe {
            ZwClose(self.handle);
        }
    }
}
