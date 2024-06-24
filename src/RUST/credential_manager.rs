use windows::core::PCWSTR;
use windows::Win32::Security::Credentials::{
    CredDeleteW, CredReadW, CredWriteW, CREDENTIALW, CRED_TYPE_GENERIC, CRED_PERSIST_LOCAL_MACHINE,
};
use windows::Win32::Foundation::{GetLastError, ERROR_SUCCESS};
use std::ptr::null_mut;
use std::ffi::c_void;
use std::mem::size_of;
use std::slice;
use std::ptr;

pub struct CredentialManager;

impl CredentialManager {
    pub fn add_credential(target: &str, username: &str, password: &str) -> Result<(), String> {
        let target_w: Vec<u16> = target.encode_utf16().chain(Some(0)).collect();
        let username_w: Vec<u16> = username.encode_utf16().chain(Some(0)).collect();
        let password_w: Vec<u16> = password.encode_utf16().collect();
        
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: PCWSTR(target_w.as_ptr()),
            CredentialBlobSize: (password_w.len() * size_of::<u16>()) as u32,
            CredentialBlob: password_w.as_ptr() as *mut c_void,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            UserName: PCWSTR(username_w.as_ptr()),
            ..Default::default()
        };

        unsafe {
            if CredWriteW(&credential, 0).as_bool() {
                Ok(())
            } else {
                Err(format!("Failed to write credential: {}", GetLastError().0))
            }
        }
    }

    pub fn read_credential(target: &str) -> Result<(String, String), String> {
        let target_w: Vec<u16> = target.encode_utf16().chain(Some(0)).collect();
        let mut pcred: *mut CREDENTIALW = null_mut();
        
        unsafe {
            if CredReadW(PCWSTR(target_w.as_ptr()), CRED_TYPE_GENERIC, 0, &mut pcred).as_bool() {
                let cred = *pcred;
                let username = to_string(cred.UserName);
                let password = to_wide_string(cred.CredentialBlob as *const u16, cred.CredentialBlobSize as usize / 2);
                Ok((username, password))
            } else {
                Err(format!("Failed to read credential: {}", GetLastError().0))
            }
        }
    }

    pub fn delete_credential(target: &str) -> Result<(), String> {
        let target_w: Vec<u16> = target.encode_utf16().chain(Some(0)).collect();

        unsafe {
            if CredDeleteW(PCWSTR(target_w.as_ptr()), CRED_TYPE_GENERIC, 0).as_bool() {
                Ok(())
            } else {
                Err(format!("Failed to delete credential: {}", GetLastError().0))
            }
        }
    }

    pub fn validate_credential(target: &str, username: &str, password: &str) -> Result<bool, String> {
        match Self::read_credential(target) {
            Ok((stored_username, stored_password)) => {
                Ok(stored_username == username && stored_password == password)
            },
            Err(e) => Err(e),
        }
    }
}

fn to_string(pwstr: PCWSTR) -> String {
    let len = unsafe { (0..).take_while(|&i| *pwstr.0.offset(i) != 0).count() };
    let slice = unsafe { slice::from_raw_parts(pwstr.0, len) };
    String::from_utf16_lossy(slice)
}

fn to_wide_string(ptr: *const u16, len: usize) -> String {
    let slice = unsafe { slice::from_raw_parts(ptr, len) };
    String::from_utf16_lossy(slice)
}
