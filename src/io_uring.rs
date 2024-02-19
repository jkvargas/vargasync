use crate::{mmap::MMap, syscalls::io_uring_setup};
use anyhow::{anyhow, Result};
use bitflags::bitflags;
use libc::{c_void, off_t};
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
use std::{error::Error, fmt::Display, mem::size_of, os::fd::OwnedFd, ptr::NonNull};

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

impl Into<io_cqring_offsets> for &IoCqRingOffsets {
    fn into(self) -> io_cqring_offsets {
        io_cqring_offsets {
            head: self.head,
            tail: self.tail,
            ring_mask: self.ring_mask,
            ring_entries: self.ring_entries,
            overflow: self.overflow,
            cqes: self.cqes,
            flags: self.flags,
            resv1: self.resv1,
            user_addr: self.user_addr,
        }
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

impl Into<io_sqring_offsets> for &IoSqRingOffsets {
    fn into(self) -> io_sqring_offsets {
        io_sqring_offsets {
            head: self.head,
            tail: self.tail,
            ring_mask: self.ring_mask,
            ring_entries: self.ring_entries,
            flags: self.flags,
            dropped: self.dropped,
            array: self.array,
            resv1: self.resv1,
            user_addr: self.user_addr,
        }
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

impl Into<io_uring_params> for &IoUringParams {
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
            sq_off: (&self.sq_off).into(),
            cq_off: (&self.cq_off).into(),
        }
    }
}

pub struct IoUringCompleteQueue<'a> {
    pub(crate) head: NonNull<c_void>,
    pub(crate) tail: NonNull<c_void>,
    pub(crate) mask: NonNull<c_void>,
    pub(crate) entries: NonNull<c_void>,
    pub(crate) flags: NonNull<c_void>,
    pub(crate) ring: IoUringQueueOwnership<'a>,
    pub(crate) cqes: NonNull<c_void>,
}

pub struct IoUringSendQueue<'a> {
    pub(crate) head: NonNull<c_void>,
    pub(crate) tail: NonNull<c_void>,
    pub(crate) mask: NonNull<c_void>,
    pub(crate) entries: NonNull<c_void>,
    pub(crate) flags: NonNull<c_void>,
    pub(crate) ring: MMap<'a>,
    pub(crate) sqes: MMap<'a>,
}

pub(crate) enum IoUringQueueOwnership<'a> {
    Owns(MMap<'a>),
    Refers(&'a MMap<'a>),
}

pub(crate) fn setup_cq_ring<'a>(
    map: IoUringQueueOwnership<'a>,
    params: &io_uring_params,
) -> Result<IoUringCompleteQueue<'a>> {
    let (head, tail, mask, entries, flags, cqes) = match &map {
        IoUringQueueOwnership::Owns(ring) => {
            (ring
                .add_offset(params.cq_off.head as usize)
                .ok_or(anyhow!("could not set the head for send_io_uring"))?,
             ring
                .add_offset(params.cq_off.tail as usize)
                .ok_or(anyhow!("could not set head pro completion queue"))?,
            ring
                .add_offset(params.cq_off.ring_mask as usize)
                .ok_or(anyhow!("could not set ring mask"))?,
             ring
                .add_offset(params.cq_off.ring_entries as usize)
                .ok_or(anyhow!("could not set entries"))?,
            ring
                .add_offset(params.cq_off.flags as usize)
                .ok_or(anyhow!("could not set flags"))?,
            ring
                .add_offset(params.cq_off.cqes as usize)
                .ok_or(anyhow!("could not set cqes"))?)
        },
        IoUringQueueOwnership::Refers(ring) => {
            ((*ring)
                 .add_offset(params.cq_off.head as usize)
                 .ok_or(anyhow!("could not set the head for send_io_uring"))?,
             (*ring)
                 .add_offset(params.cq_off.tail as usize)
                 .ok_or(anyhow!("could not set head pro completion queue"))?,
             (*ring)
                 .add_offset(params.cq_off.ring_mask as usize)
                 .ok_or(anyhow!("could not set ring mask"))?,
             (*ring)
                 .add_offset(params.cq_off.ring_entries as usize)
                 .ok_or(anyhow!("could not set entries"))?,
             (*ring)
                 .add_offset(params.cq_off.flags as usize)
                 .ok_or(anyhow!("could not set flags"))?,
             (*ring)
                 .add_offset(params.cq_off.cqes as usize)
                 .ok_or(anyhow!("could not set cqes"))?)
        },
    };

    Ok(IoUringCompleteQueue {
        head,
        tail,
        mask,
        entries,
        flags,
        ring: map,
        cqes,
    })
}

pub(crate) fn setup_send_ring<'a>(
    map: MMap,
    params: &io_uring_params,
    sqes: MMap,
) -> Result<IoUringSendQueue<'a>> {
    let head = map
        .add_offset(params.sq_off.head as usize)
        .ok_or(anyhow!("could not set the head for send queue"))?;
    let tail = map
        .add_offset(params.sq_off.tail as usize)
        .ok_or(anyhow!("could not set head for send queue"))?;
    let mask = map
        .add_offset(params.sq_off.ring_mask as usize)
        .ok_or(anyhow!("could not set ring mask"))?;
    let entries = map
        .add_offset(params.sq_off.ring_entries as usize)
        .ok_or(anyhow!("could not set entries"))?;
    let flags = map
        .add_offset(params.sq_off.flags as usize)
        .ok_or(anyhow!("could not set flags"))?;

    Ok(IoUringSendQueue {
        head,
        tail,
        mask,
        entries,
        flags,
        ring: map,
        sqes,
    })
}

pub struct IoUring<'a> {
    pub(crate) send_queue: IoUringSendQueue<'a>,
    pub(crate) complete_queue: IoUringCompleteQueue<'a>,
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

        let parameters: &mut io_uring_params = &mut (&params).into();
        let fd = unsafe { io_uring_setup(entries, parameters) };

        if !flags.contains(IoUringSetupFlags::NoMmap) {}

        Ok(io_uring_queue_mmap(fd, &parameters)?)
    }
}

/*
 * For users that want to specify sq_thread_cpu or sq_thread_idle, this
 * interface is a convenient helper for mmap()ing the rings.
 * Returns -errno on error, or zero on success.  On success, 'ring'
 * contains the necessary information to read/write to the rings.
 */
fn io_uring_queue_mmap<'a>(
    file_descriptor: OwnedFd,
    io_uring_params: &io_uring_params,
) -> Result<IoUring<'a>> {
    let mut send_ring_size = io_uring_params.sq_off.array as usize
        + io_uring_params.sq_entries as usize * size_of::<u32>();
    let mut complete_ring_size = io_uring_params.cq_off.cqes as usize
        + io_uring_params.cq_entries as usize * size_of::<io_uring_cqe>();

    if io_uring_params.features as u32 & IORING_FEAT_SINGLE_MMAP > 0 {
        if complete_ring_size > send_ring_size {
            send_ring_size = complete_ring_size;
        }
        complete_ring_size = send_ring_size;
    }

    let send_ring = MMap::new(
        &file_descriptor,
        IORING_OFF_SQ_RING as off_t,
        send_ring_size,
    )?;

    let complete_ring = if io_uring_params.features as u32 & IORING_FEAT_SINGLE_MMAP > 0 {
        IoUringQueueOwnership::Refers(&send_ring)
    } else {
        IoUringQueueOwnership::Owns(MMap::new(
            &file_descriptor,
            IORING_OFF_CQ_RING as off_t,
            complete_ring_size,
        )?)
    };

    let size = io_uring_params.sq_entries as usize * size_of::<io_uring_sqe>();

    let send_queue_qes =
        MMap::new(&file_descriptor, IORING_OFF_SQES as off_t, size)?;

    let complete_queue = setup_cq_ring(complete_ring, io_uring_params)?;

    let send_queue = setup_send_ring(send_ring, io_uring_params, send_queue_qes)?;

    Ok(IoUring {
        send_queue,
        complete_queue,
        flags: io_uring_params.flags,
        ring_file_descriptor: file_descriptor,
    })
}

#[cfg(test)]
mod when_initializing_io_uring {
    use crate::io_uring::{IoCqRingOffsets, IoSqRingOffsets, IoUring, IoUringParams};

    #[test]
    pub fn io_uring_setup_does_not_throw() {
        let params = IoUringParams {
            sq_entries: 0,
            cq_entries: 0,
            flags: 0,
            sq_thread_cpu: 0,
            sq_thread_idle: 0,
            features: 0,
            wq_fd: 0,
            resv: [0, 0, 0],
            sq_off: IoSqRingOffsets {
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
            cq_off: IoCqRingOffsets {
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

        let io_uring = IoUring::initialize(1, IoUringParams::from(params));

        assert!(io_uring.is_ok());
    }
}
