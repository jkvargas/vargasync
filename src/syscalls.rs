use bitflags::bitflags;
use libc::{c_long, syscall};
use linux_raw_sys::{
    general::{__NR_io_uring_enter, __NR_io_uring_setup, sigset_t},
    io_uring::{
        io_uring_params, IORING_ENTER_EXT_ARG, IORING_ENTER_GETEVENTS,
        IORING_ENTER_REGISTERED_RING, IORING_ENTER_SQ_WAIT, IORING_ENTER_SQ_WAKEUP,
    },
    io_uring::{
        IORING_REGISTER_BUFFERS, IORING_REGISTER_BUFFERS2, IORING_REGISTER_BUFFERS_UPDATE,
        IORING_REGISTER_ENABLE_RINGS, IORING_REGISTER_EVENTFD, IORING_REGISTER_EVENTFD_ASYNC,
        IORING_REGISTER_FILES, IORING_REGISTER_FILES2, IORING_REGISTER_FILES_UPDATE,
        IORING_REGISTER_FILES_UPDATE2, IORING_REGISTER_FILE_ALLOC_RANGE, IORING_REGISTER_IOWQ_AFF,
        IORING_REGISTER_IOWQ_MAX_WORKERS, IORING_REGISTER_LAST, IORING_REGISTER_PBUF_RING,
        IORING_REGISTER_PERSONALITY, IORING_REGISTER_PROBE, IORING_REGISTER_RESTRICTIONS,
        IORING_REGISTER_RING_FDS, IORING_REGISTER_SYNC_CANCEL, IORING_REGISTER_USE_REGISTERED_RING,
        IORING_UNREGISTER_BUFFERS, IORING_UNREGISTER_EVENTFD, IORING_UNREGISTER_FILES,
        IORING_UNREGISTER_IOWQ_AFF, IORING_UNREGISTER_PBUF_RING, IORING_UNREGISTER_PERSONALITY,
        IORING_UNREGISTER_RING_FDS,
    },
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

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

bitflags! {
    pub struct IoUringOpCode: u32 {
        const IoRingRegisterBuffers = IORING_REGISTER_BUFFERS as u32;
        const IoRingUnregisterBuffers = IORING_UNREGISTER_BUFFERS as u32;
        const IoRingRegisterFiles = IORING_REGISTER_FILES as u32;
        const IoRingUnregisterFiles = IORING_UNREGISTER_FILES as u32;
        const IoRingRegisterEventFd = IORING_REGISTER_EVENTFD as u32;
        const IoRingUnregisterEventFd = IORING_UNREGISTER_EVENTFD as u32;
        const IoRingRegisterFilesUpdate = IORING_REGISTER_FILES_UPDATE as u32;
        const IoRingRegisterEventFdAsync = IORING_REGISTER_EVENTFD_ASYNC as u32;
        const IoRingRegisterProbe = IORING_REGISTER_PROBE as u32;
        const IoRingRegisterPeronality = IORING_REGISTER_PERSONALITY as u32;
        const IoRingUnregisterPersonality = IORING_UNREGISTER_PERSONALITY as u32;
        const IoRingRegisterRestrictions = IORING_REGISTER_RESTRICTIONS as u32;
        const IoRingRegisterEnableRings = IORING_REGISTER_ENABLE_RINGS as u32;
        const IoRingRegisterFiles2 = IORING_REGISTER_FILES2 as u32;
        const IoRingRegisterFilesUpdate2 = IORING_REGISTER_FILES_UPDATE2 as u32;
        const IoRingRegisterBuffers2 = IORING_REGISTER_BUFFERS2 as u32;
        const IoRingRegisterBuffersUpdate = IORING_REGISTER_BUFFERS_UPDATE as u32;
        const IoRingRegisterIowqAff = IORING_REGISTER_IOWQ_AFF as u32;
        const IoRingUnregisterIowqAff = IORING_UNREGISTER_IOWQ_AFF as u32;
        const IoRingRegisterIowqMaxWorkers = IORING_REGISTER_IOWQ_MAX_WORKERS as u32;
        const IoRingRegisterRingFds = IORING_REGISTER_RING_FDS as u32;
        const IoRingUnregisterRingFds = IORING_UNREGISTER_RING_FDS as u32;
        const IoRingRegisterPbufRing = IORING_REGISTER_PBUF_RING as u32;
        const IoRingUnregisterPbufRing = IORING_UNREGISTER_PBUF_RING as u32;
        const IoRingRegisterSyncCancel = IORING_REGISTER_SYNC_CANCEL as u32;
        const IoRingRegisterFileAllocRange = IORING_REGISTER_FILE_ALLOC_RANGE as u32;
        const IoRingRegisterLast = IORING_REGISTER_LAST as u32;
        const IoRingRegisterUseRegisteredRing = IORING_REGISTER_USE_REGISTERED_RING as u32;
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

pub(crate) unsafe fn io_uring_register(
    ring_fd: &OwnedFd,
    opcode: IoUringOpCode,
    raw_fd: RawFd,
    nr_args: u32,
) {
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
