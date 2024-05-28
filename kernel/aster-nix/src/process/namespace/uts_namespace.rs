use crate::prelude::*;

pub struct UtsNamespace {
    name: RwLock<UtsName>,
}

impl Default for UtsNamespace {
    fn default() -> Self {
        // We don't use the real name and version of our os here. Instead, we pick up fake values witch is the same as the ones of linux.
        // The values are used to fool glibc since glibc will check the version and os name.
        let mut uts_name = UtsName::new();
        let sys_name: CString = CString::new("Linux").unwrap();
        let node_name: CString = CString::new("WHITLEY").unwrap();
        let release: CString = CString::new("5.13.0").unwrap();
        let version: CString = CString::new("5.13.0").unwrap();
        let machine: CString = CString::new("x86_64").unwrap();
        let domain_name: CString = CString::new("").unwrap();
        copy_cstring_to_u8_slice(&sys_name, &mut uts_name.sysname);
        copy_cstring_to_u8_slice(&node_name, &mut uts_name.nodename);
        copy_cstring_to_u8_slice(&release, &mut uts_name.release);
        copy_cstring_to_u8_slice(&version, &mut uts_name.version);
        copy_cstring_to_u8_slice(&machine, &mut uts_name.machine);
        copy_cstring_to_u8_slice(&domain_name, &mut uts_name.domainname);
        Self {
            name: RwLock::new(uts_name),
        }
    }
}

impl UtsNamespace {
    pub fn new(uts_name: UtsName) -> Arc<Self> {
        Arc::new(Self {
            name: RwLock::new(uts_name),
        })
    }

    pub fn name(&self) -> UtsName {
        *self.name.read()
    }

    pub fn copy_uts_ns(old_uts_ns: &Arc<UtsNamespace>) -> Arc<Self> {
        let new_uts_name = old_uts_ns.name.read().clone();
        Self::new(new_uts_name)
    }

    pub fn sethostname(&self, new_hostname: CString) {
        let mut uts_name = self.name.write();
        copy_cstring_to_u8_slice(&new_hostname, &mut uts_name.nodename);
    }
}

fn copy_cstring_to_u8_slice(src: &CStr, dst: &mut [u8]) {
    let src = src.to_bytes_with_nul();
    let len = src.len().min(dst.len());
    dst[..len].copy_from_slice(&src[..len]);
}

pub const UTS_FIELD_LEN: usize = 65;

#[derive(Debug, Clone, Copy, Pod)]
#[repr(C)]
pub struct UtsName {
    sysname: [u8; UTS_FIELD_LEN],
    nodename: [u8; UTS_FIELD_LEN],
    release: [u8; UTS_FIELD_LEN],
    version: [u8; UTS_FIELD_LEN],
    machine: [u8; UTS_FIELD_LEN],
    domainname: [u8; UTS_FIELD_LEN],
}

impl UtsName {
    const fn new() -> Self {
        UtsName {
            sysname: [0; UTS_FIELD_LEN],
            nodename: [0; UTS_FIELD_LEN],
            release: [0; UTS_FIELD_LEN],
            version: [0; UTS_FIELD_LEN],
            machine: [0; UTS_FIELD_LEN],
            domainname: [0; UTS_FIELD_LEN],
        }
    }
}