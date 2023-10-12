
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]


use crate::base::*;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuxModuleBasicInfo {
    pub image_base: *mut c_void,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuxModuleExtendedInfo {
    pub basic_info: AuxModuleBasicInfo,
    pub image_size: u32,
    pub file_name_offset: u16,
    pub full_path_name: [u8; 256],
}



include!(concat!(env!("OUT_DIR"), "/auxklib.rs"));