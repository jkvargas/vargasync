use anyhow::{bail, Result};
use errno::errno;
use libc::{
    c_void, exit, mmap, munmap, off_t, strerror, MAP_FAILED, MAP_POPULATE, MAP_SHARED, PROT_READ,
    PROT_WRITE,
};
use log::debug;
use std::{
    ffi::CStr,
    marker::PhantomData,
    os::fd::{AsRawFd, OwnedFd},
    ptr::{null_mut, NonNull},
};

const UNMAP_FAILED: i32 = -1;

pub(crate) struct MMap<'a, T> {
    addr: NonNull<c_void>,
    len: usize,
    __owns_addr: PhantomData<&'a T>,
}

impl<'a, T> MMap<'a, T> {
    pub(crate) fn new(fd: &OwnedFd, offset: off_t, len: usize) -> Result<Self> {
        unsafe {
            match mmap(
                null_mut(),
                len,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_POPULATE,
                fd.as_raw_fd(),
                offset,
            ) {
                MAP_FAILED => {
                    let error_number = errno().0;
                    let error_string = strerror(error_number);
                    let error = CStr::from_ptr(error_string).to_string_lossy().into_owned();
                    bail!(error);
                }
                addr => {
                    let result = NonNull::new_unchecked(addr);
                    Ok(Self {
                        addr: result,
                        len,
                        __owns_addr: PhantomData::default(),
                    })
                }
            }
        }
    }

    pub(crate) unsafe fn as_qe(&self) -> &'a T {
        self.addr.cast().as_ref()
    }

    pub(crate) fn add_offset(&self, offset: usize) -> Option<NonNull<c_void>> {
        NonNull::new(unsafe { self.addr.as_ptr().add(offset) })
    }
}

impl<'a, T> Drop for MMap<'a, T> {
    fn drop(&mut self) {
        unsafe {
            let error_code = munmap(self.addr.as_ptr(), self.len);
            if error_code == UNMAP_FAILED {
                let error_number = errno().0;
                let error_string = strerror(error_number);
                let error = CStr::from_ptr(error_string).to_string_lossy().into_owned();
                debug!("{}", &error);
                exit(1);
            }
        }
    }
}
