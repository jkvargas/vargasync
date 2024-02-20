use bitflags::bitflags;
use libc::{c_long, syscall};
use linux_raw_sys::{
    general::{__NR_io_uring_enter, __NR_io_uring_setup, sigset_t},
    io_uring::{
        io_uring_params, IORING_ENTER_EXT_ARG, IORING_ENTER_GETEVENTS,
        IORING_ENTER_REGISTERED_RING, IORING_ENTER_SQ_WAIT, IORING_ENTER_SQ_WAKEUP,
    },
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(crate) type NumberOfIOsSuccessfullyConsumed = i64;

bitflags! {
    pub struct IoUringEnterFlags : u32 {
        const IoRingEnterGetEvents = IORING_ENTER_GETEVENTS;
        const IoRingEnterSqWakeup = IORING_ENTER_SQ_WAKEUP;
        const IoRingEnterSqWait = IORING_ENTER_SQ_WAIT;
        const IoRingEnterExtArg = IORING_ENTER_EXT_ARG;
        const IoRingEnterRegisteredRing = IORING_ENTER_REGISTERED_RING;
    }
}

pub(crate) unsafe fn io_uring_setup(entries: u32, params: &mut io_uring_params) -> OwnedFd {
    let result = syscall(
        __NR_io_uring_setup as c_long,
        entries as c_long,
        params as *mut io_uring_params,
    );

    OwnedFd::from_raw_fd(result as i32)
}

pub(crate) unsafe fn io_uring_enter(
    ring_fd: &OwnedFd,
    submit: u32,
    min_complete: u32,
    flags: IoUringEnterFlags,
    sigset: *mut sigset_t,
    sz: u32,
) -> NumberOfIOsSuccessfullyConsumed {
    syscall(
        __NR_io_uring_enter as c_long,
        ring_fd.as_raw_fd(),
        submit,
        min_complete,
        flags.bits(),
        sigset,
        sz,
    )
}
