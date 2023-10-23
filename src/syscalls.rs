use libc::{c_long, syscall};
use linux_raw_sys::general::__NR_io_uring_setup;
use linux_raw_sys::io_uring::io_uring_params;

pub(crate) unsafe fn io_uring_setup(entries: u32, params: &mut io_uring_params) {
    syscall(
        __NR_io_uring_setup as c_long,
        entries as c_long,
        params as *mut io_uring_params,
    );
}
