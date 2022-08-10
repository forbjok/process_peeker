use std::ffi::OsString;
use std::os::windows::prelude::OsStringExt;

/// Convert a Win32 API-compatible string to a Rust OsString.
pub fn wstring_to_osstring(wstring: &[u16]) -> OsString {
    match wstring.iter().position(|&x| x == 0) {
        Some(pos) => OsString::from_wide(&wstring[..pos]),
        None => OsString::from_wide(wstring),
    }
}

/// Convert a Win32 API-compatible string to a Rust string.
pub fn wstring_to_string(wstring: &[u16]) -> String {
    wstring_to_osstring(wstring).to_string_lossy().into_owned()
}
