use std::os::fd::{FromRawFd, OwnedFd};

use libc::{c_long, syscall};
use linux_raw_sys::{general::__NR_io_uring_setup, io_uring::io_uring_params};

pub(crate) unsafe fn io_uring_setup(entries: u32, params: &mut io_uring_params) -> OwnedFd {
    let result = syscall(
        __NR_io_uring_setup as c_long,
        entries as c_long,
        params as *mut io_uring_params,
    );

    OwnedFd::from_raw_fd(result as i32)
}
