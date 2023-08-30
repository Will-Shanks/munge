use munge_sys;
use std::ffi::{self,CString, CStr};
use std::ptr;
use libc;

fn get_err(err: munge_sys::munge_err) -> String {
    //err_msg should not be freed per munge api docs
    let err_msg = unsafe{munge_sys::munge_strerror(err)};
    let msg = unsafe{CStr::from_ptr(err_msg)}.to_str().unwrap().to_string();
    msg
}

pub fn munge(msg: &str) -> Result<String, String> {
    let mut cred: *mut ffi::c_char = ptr::null_mut();
    let len: ffi::c_int = msg.len().try_into().unwrap();
    let buf: *const ffi::c_void = CString::new(msg).unwrap().into_raw() as *const ffi::c_void;
    let err = unsafe{munge_sys::munge_encode(&mut cred, ptr::null_mut(), buf, len)};
    if err != 0 {
        Err(get_err(err))
    }else {
        let resp = Ok(unsafe{CStr::from_ptr(cred as *const i8)}.to_str().unwrap().to_string());
        unsafe{libc::free(cred as *mut ffi::c_void)};
        resp
    }
}

#[derive(Debug)]
pub struct Message {
    pub msg: String,
    pub uid: u32,
    pub gid: u32,
}

pub fn unmunge(encoded_msg: String) -> Result<Message, String> {
    let cred: *mut ffi::c_char = CString::new(encoded_msg).unwrap().into_raw();
    let mut dmsg: *mut ffi::c_void = ptr::null_mut();
    let mut len: ffi::c_int = 0;
    let mut uid: munge_sys::uid_t = 0;
    let mut gid: munge_sys::gid_t = 0;

    let err = unsafe{munge_sys::munge_decode(cred, ptr::null_mut(), &mut dmsg, &mut len, &mut uid, &mut gid)};
    if err != 0 {
        Err(get_err(err))
    } else {
        let resp = unsafe{CStr::from_ptr(dmsg as *const i8)}.to_str().unwrap().to_string();
        unsafe{libc::free(dmsg)};
        Ok(Message{msg: resp, uid, gid})
    }
}

/**
fn main() {
    let msg = "test message";
    let encoded_msg = munge(msg).unwrap();
    println!("{}", encoded_msg);
    let decoded_msg = unmunge(encoded_msg).unwrap();
    println!("{:?}", decoded_msg);
}
**/
