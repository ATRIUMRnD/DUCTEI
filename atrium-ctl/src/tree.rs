// Copyright (C) 2026 xingxerx
// Licensed under the Apache License 2.0. See the LICENSE file in the repository root.

//! Process-tree ownership for managed rooms.
//!
//! Windows: each room gets a Job Object with KILL_ON_JOB_CLOSE. The child is
//! assigned right after spawn; everything it starts afterwards joins the job
//! automatically. Dropping the `Tree` (room stopped, or atrium itself exiting
//! or crashing, since the OS closes the handle) kills the whole tree.
//! Elsewhere: `kill_tree` falls back to signalling the process group.

use std::process::Child;

pub struct Tree {
    #[cfg(windows)]
    job: windows_sys::Win32::Foundation::HANDLE,
}

// The job handle is owned exclusively by this struct.
unsafe impl Send for Tree {}

impl Tree {
    /// Create a kill-on-close job and put `child` in it.
    pub fn adopt(child: &Child) -> Result<Self, String> {
        #[cfg(windows)]
        unsafe {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::JobObjects::*;
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() { return Err(format!("CreateJobObjectW: {}", std::io::Error::last_os_error())); }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32);
            if ok == 0 { let e = std::io::Error::last_os_error(); CloseHandle(job); return Err(format!("SetInformationJobObject: {e}")); }
            if AssignProcessToJobObject(job, child.as_raw_handle() as _) == 0 {
                let e = std::io::Error::last_os_error(); CloseHandle(job);
                return Err(format!("AssignProcessToJobObject: {e}"));
            }
            Ok(Self { job })
        }
        #[cfg(not(windows))]
        { let _ = child; Ok(Self {}) }
    }

    /// Kill every process in the tree now.
    pub fn kill(&self) {
        #[cfg(windows)]
        unsafe { windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job, 1); }
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            // KILL_ON_JOB_CLOSE: closing the last handle kills the tree.
            windows_sys::Win32::Foundation::CloseHandle(self.job);
        }
    }
}

/// Belt and braces for anything that escaped the job (spawned before adopt):
/// `taskkill /T /F` on the root PID.
pub fn kill_tree_by_pid(pid: u32) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill").args(["/T", "/F", "/PID", &pid.to_string()])
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    }
    #[cfg(not(windows))]
    {
        let _ = std::process::Command::new("kill").args(["-9", &format!("-{pid}")]).status();
    }
}
