mod arch;
mod mmap;
mod syscalls;

use anyhow::{anyhow, Result};
use bitflags::bitflags;
use libc::off_t;
use linux_raw_sys::io_uring::{
    io_cqring_offsets, io_sqring_offsets, io_uring_cqe, io_uring_params, io_uring_sqe,
    IORING_FEAT_CQE_SKIP, IORING_FEAT_CUR_PERSONALITY, IORING_FEAT_EXT_ARG, IORING_FEAT_FAST_POLL,
    IORING_FEAT_LINKED_FILE, IORING_FEAT_NATIVE_WORKERS, IORING_FEAT_NODROP,
    IORING_FEAT_POLL_32BITS, IORING_FEAT_REG_REG_RING, IORING_FEAT_RSRC_TAGS,
    IORING_FEAT_RW_CUR_POS, IORING_FEAT_SINGLE_MMAP, IORING_FEAT_SQPOLL_NONFIXED,
    IORING_FEAT_SUBMIT_STABLE, IORING_OFF_CQ_RING, IORING_OFF_SQES, IORING_OFF_SQ_RING,
    IORING_SETUP_ATTACH_WQ, IORING_SETUP_CLAMP, IORING_SETUP_COOP_TASKRUN, IORING_SETUP_CQE32,
    IORING_SETUP_CQSIZE, IORING_SETUP_DEFER_TASKRUN, IORING_SETUP_IOPOLL, IORING_SETUP_NO_MMAP,
    IORING_SETUP_REGISTERED_FD_ONLY, IORING_SETUP_R_DISABLED, IORING_SETUP_SINGLE_ISSUER,
    IORING_SETUP_SQE128, IORING_SETUP_SQPOLL, IORING_SETUP_SQ_AFF, IORING_SETUP_SUBMIT_ALL,
    IORING_SETUP_TASKRUN_FLAG,
};
use mmap::MMap;
use std::error::Error;
use std::fmt::Display;
use std::mem::size_of;
use std::os::fd::OwnedFd;
use std::sync::atomic::AtomicU32;
use syscalls::io_uring_setup;

bitflags! {
    pub struct IoUringFeatures : u32 {
        const SingleMmap = IORING_FEAT_SINGLE_MMAP;
        const NoDrop = IORING_FEAT_NODROP;
        const SubmitStable = IORING_FEAT_SUBMIT_STABLE;
        const RwCurPos = IORING_FEAT_RW_CUR_POS;
        const CurPersonality = IORING_FEAT_CUR_PERSONALITY;
        const FastPoll = IORING_FEAT_FAST_POLL;
        const Poll32Bits = IORING_FEAT_POLL_32BITS;
        const SqPollNonFixed = IORING_FEAT_SQPOLL_NONFIXED;
        const ExtArg = IORING_FEAT_EXT_ARG;
        const NativeWorkers = IORING_FEAT_NATIVE_WORKERS;
        const RsRcTags = IORING_FEAT_RSRC_TAGS;
        const CqeSkip = IORING_FEAT_CQE_SKIP;
        const LinkedFile = IORING_FEAT_LINKED_FILE;
        const RegRegRing = IORING_FEAT_REG_REG_RING;
    }
}

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

pub struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3usize],
    pub sq_off: IoSqRingOffsets,
    pub cq_off: IoCqRingOffsets,
}

impl Into<io_cqring_offsets> for IoCqRingOffsets {
    fn into(self) -> io_cqring_offsets {
        todo!()
    }
}

pub struct IoCqRingOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

impl Into<io_sqring_offsets> for IoSqRingOffsets {
    fn into(self) -> io_sqring_offsets {
        todo!()
    }
}

pub struct IoSqRingOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

impl Into<io_uring_params> for IoUringParams {
    fn into(self) -> io_uring_params {
        io_uring_params {
            flags: self.flags,
            cq_entries: self.cq_entries,
            sq_entries: self.sq_entries,
            sq_thread_cpu: self.sq_thread_cpu,
            sq_thread_idle: self.sq_thread_idle,
            features: self.features,
            wq_fd: self.wq_fd,
            resv: self.resv,
            sq_off: self.sq_off.into(),
            cq_off: self.cq_off.into(),
        }
    }
}

pub struct IoUringQueue<'a, TRing> {
    pub(crate) head: *const AtomicU32,
    pub(crate) tail: *const AtomicU32,
    pub(crate) mask: u32,
    pub(crate) entries: u32,
    pub(crate) flags: u32,
    pub(crate) ring: Option<MMap<'a, TRing>>,
    pub(crate) qes: MMap<'a, TRing>,
}

pub struct IoUring<'a> {
    pub(crate) send_queue: IoUringQueue<'a, io_uring_sqe>,
    pub(crate) complete_queue: IoUringQueue<'a, io_uring_cqe>,
    pub(crate) flags: u32,
    pub(crate) ring_file_descriptor: OwnedFd,
}

impl<'a> IoUring<'a> {
    pub fn initialize(entries: u32, params: IoUringParams) -> Result<IoUring<'a>> {
        let flags = IoUringSetupFlags::from_bits(params.flags).ok_or(anyhow!("error"))?;

        if flags.contains(IoUringSetupFlags::RegisteredFdOnly)
            && !(flags.contains(IoUringSetupFlags::NoMmap))
        {
            return Err(anyhow!(IoUringError::InvalidArgument));
        }

        let fd = unsafe {
            io_uring_setup(entries, &mut params.into());
        };

        if !flags.contains(IoUringSetupFlags::NoMmap) {}

        let io_uring = IoUring {
            send_queue: todo!(),
            complete_queue: todo!(),
            flags: todo!(),
            ring_file_descriptor: todo!(),
        };

        Ok(io_uring)
    }

    /*
     * For users that want to specify sq_thread_cpu or sq_thread_idle, this
     * interface is a convenient helper for mmap()ing the rings.
     * Returns -errno on error, or zero on success.  On success, 'ring'
     * contains the necessary information to read/write to the rings.
     */
    fn io_uring_queue_mmap(
        &mut self,
        file_descriptor: &OwnedFd,
        setup_flags: &IoUringSetupFlags,
        io_uring_params: &IoUringParams,
    ) -> Result<()> {
        let mut size = size_of::<io_uring_cqe>();
        if setup_flags.contains(IoUringSetupFlags::Cqe32) {
            size += size_of::<io_uring_cqe>();
        }

        let mut send_size =
            io_uring_params.sq_off.array + io_uring_params.sq_entries * size_of::<u32>() as u32;
        let mut complete_size =
            io_uring_params.cq_off.cqes + io_uring_params.cq_entries * size as u32;

        let features =
            IoUringFeatures::from_bits(io_uring_params.features).ok_or(anyhow!("error"))?;

        if features.contains(IoUringFeatures::SingleMmap) {
            if complete_size > send_size {
                send_size = complete_size;
            }
            complete_size = send_size;
        }

        self.send_queue.ring = Some(MMap::new(
            file_descriptor,
            IORING_OFF_SQ_RING as off_t,
            send_size as usize,
        )?);

        if features.contains(IoUringFeatures::SingleMmap) {
            self.complete_queue.ring = None;
        } else {
            self.complete_queue.ring = Some(MMap::new(
                file_descriptor,
                IORING_OFF_CQ_RING as off_t,
                complete_size as usize,
            )?);
        }

        size = size_of::<io_uring_sqe>();
        if setup_flags.contains(IoUringSetupFlags::Sqe128) {
            size += 64;
        }

        self.send_queue.qes = MMap::new(
            file_descriptor,
            IORING_OFF_SQES as off_t,
            size * io_uring_params.sq_entries as usize,
        )?;

        Ok(())
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
