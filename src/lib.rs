mod arch;
mod syscalls;

use anyhow::{anyhow, Result};
use bitflags::bitflags;
use linux_raw_sys::io_uring::{
    io_uring_params, IORING_SETUP_ATTACH_WQ, IORING_SETUP_CLAMP, IORING_SETUP_COOP_TASKRUN,
    IORING_SETUP_CQE32, IORING_SETUP_CQSIZE, IORING_SETUP_DEFER_TASKRUN, IORING_SETUP_IOPOLL,
    IORING_SETUP_NO_MMAP, IORING_SETUP_REGISTERED_FD_ONLY, IORING_SETUP_R_DISABLED,
    IORING_SETUP_SINGLE_ISSUER, IORING_SETUP_SQE128, IORING_SETUP_SQPOLL, IORING_SETUP_SQ_AFF,
    IORING_SETUP_SUBMIT_ALL, IORING_SETUP_TASKRUN_FLAG,
};
use std::error::Error;
use std::fmt::Display;
use std::sync::atomic::AtomicU32;
use syscalls::io_uring_setup;

bitflags! {
    pub struct IoUringSetupFlags: u32 {
        const IoPoll = IORING_SETUP_IOPOLL;	/* io_context is polled */
        const SqPool = IORING_SETUP_SQPOLL;	/* SQ poll thread */
        const SqAff = IORING_SETUP_SQ_AFF;	/* sq_thread_cpu is valid */
        const CqSize = IORING_SETUP_CQSIZE;	/* app defines CQ size */
        const Clamp = IORING_SETUP_CLAMP;	/* clamp SQ/CQ ring sizes */
        const AttachWq = IORING_SETUP_ATTACH_WQ;	/* attach to existing wq */
        const RDisabled = IORING_SETUP_R_DISABLED;	/* start with ring disabled */
        const SubmitAll = IORING_SETUP_SUBMIT_ALL;	/* continue submit on error */
        /*
         * Cooperative task running. When requests complete, they often require
         * forcing the submitter to transition to the kernel to complete. If this
         * flag is set, work will be done when the task transitions anyway, rather
         * than force an inter-processor interrupt reschedule. This avoids interrupting
         * a task running in userspace, and saves an IPI.
         */
        const CoopTaskRun = IORING_SETUP_COOP_TASKRUN;
        /*
         * If COOP_TASKRUN is set, get notified if task work is available for
         * running and a kernel transition would be needed to run it. This sets
         * IORING_SQ_TASKRUN in the sq ring flags. Not valid with COOP_TASKRUN.
         */
        const TaskRunFlag = IORING_SETUP_TASKRUN_FLAG;
        const Sqe128 = IORING_SETUP_SQE128; /* SQEs are 128 byte */
        const Cqe32 = IORING_SETUP_CQE32; /* CQEs are 32 byte */
        /*
         * Only one task is allowed to submit requests
         */
        const SingleIssuer = IORING_SETUP_SINGLE_ISSUER;

        /*
         * Defer running task work to get events.
         * Rather than running bits of task work whenever the task transitions
         * try to do it just before it is needed.
         */
        const DeferTaskRun = IORING_SETUP_DEFER_TASKRUN;

        /*
         * Application provides ring memory
         */
        const NoMmap = IORING_SETUP_NO_MMAP;

        /*
         * Register the ring fd in itself for use with
         * IORING_REGISTER_USE_REGISTERED_RING; return a registered fd index rather
         * than an fd.
         */
        const RegisteredFdOnly = IORING_SETUP_REGISTERED_FD_ONLY;
    }
}

#[derive(Debug)]
pub enum IoUringError {
    InvalidArgument,
}

impl Display for IoUringError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            IoUringError::InvalidArgument => write!(f, "Invalid Argument"),
        }
    }
}

impl Error for IoUringError {
    fn description(&self) -> &str {
        match *self {
            IoUringError::InvalidArgument => "Invalid Argument",
        }
    }
}

// pub struct IoUringParams {
//     pub sq_entries: u32,
//     pub cq_entries: u32,
//     pub flags: u32,
//     pub sq_thread_cpu: u32,
//     pub sq_thread_idle: u32,
//     pub features: u32,
//     pub wq_fd: u32,
//     pub resv: [u32; 3usize],
//     pub sq_off: io_sqring_offsets,
//     pub cq_off: io_cqring_offsets,
// }
//
// impl Into<io_uring_params> for IoUringParams {
//     fn into(self) -> io_uring_params {
//         io_uring_params {
//             flags: self.flags,
//             cq_entries
//         }
//     }
// }

pub struct IoUring {
    head: *const AtomicU32,
    tail: *const AtomicU32,
    mask: u32,
    entries: u32,
    flags: u32,
    // sqes: *mut QE,
}

impl IoUring {
    pub fn initialize(entries: u32, mut params: io_uring_params) -> Result<IoUring> {
        let flags = IoUringSetupFlags::from_bits(params.flags).ok_or(anyhow!("error"))?;

        if flags.contains(IoUringSetupFlags::RegisteredFdOnly)
            && !(flags.contains(IoUringSetupFlags::NoMmap))
        {
            return Err(anyhow!(IoUringError::InvalidArgument));
        }

        unsafe {
            io_uring_setup(entries, &mut params);
        }

        Err(anyhow!("Pal"))
    }
}

#[cfg(test)]
mod when_initializing_io_uring {
    use linux_raw_sys::io_uring::{io_cqring_offsets, io_sqring_offsets, io_uring_params};

    use crate::IoUring;

    #[test]
    pub fn io_uring_setup_does_not_throw() {
        let params = io_uring_params {
            sq_entries: 0,
            cq_entries: 0,
            flags: 0,
            sq_thread_cpu: 0,
            sq_thread_idle: 0,
            features: 0,
            wq_fd: 0,
            resv: [0, 0, 0],
            sq_off: io_sqring_offsets {
                head: 0,
                tail: 0,
                ring_mask: 0,
                ring_entries: 0,
                flags: 0,
                dropped: 0,
                array: 0,
                resv1: 0,
                user_addr: 0,
            },
            cq_off: io_cqring_offsets {
                head: 0,
                tail: 0,
                ring_mask: 0,
                ring_entries: 0,
                overflow: 0,
                cqes: 0,
                flags: 0,
                resv1: 0,
                user_addr: 0,
            },
        };
        let io_uring = IoUring::initialize(1, params);
    }
}
