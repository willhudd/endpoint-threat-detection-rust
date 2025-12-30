use windows::{
    core::{w, PCWSTR},
    Win32::{
        Security::{
            AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
            SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
            TOKEN_QUERY,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

pub fn enable_required_privileges() -> bool {
    unsafe {
        enable_privilege(w!("SeDebugPrivilege")) &&
        enable_privilege(w!("SeSystemProfilePrivilege")) &&
        enable_privilege(w!("SeSecurityPrivilege"))
    }
}

unsafe fn enable_privilege(privilege_name: PCWSTR) -> bool {
    let mut token_handle = unsafe { std::mem::zeroed() };

    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        )
    }
    .is_err()
    {
        return false;
    }

    let mut luid = unsafe { std::mem::zeroed() };
    if unsafe {
        LookupPrivilegeValueW(PCWSTR::null(), privilege_name, &mut luid)
    }
    .is_err()
    {
        return false;
    }

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    unsafe {
        AdjustTokenPrivileges(token_handle, false, Some(&tp), 0, None, None)
    }
    .is_ok()
}