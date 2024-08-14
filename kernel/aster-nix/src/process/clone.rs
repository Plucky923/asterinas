// SPDX-License-Identifier: MPL-2.0

use core::sync::atomic::Ordering;

use ostd::{
    cpu::UserContext,
    user::{UserContextApi, UserSpace},
};

use super::{
    credentials,
    namespaces::net_namespace::NetNamespace,
    posix_thread::{PosixThread, PosixThreadBuilder, PosixThreadExt, ThreadName},
    process_table,
    process_vm::ProcessVm,
    signal::sig_disposition::SigDispositions,
    Credentials, Process, ProcessBuilder,
};
use crate::{
    cpu::LinuxAbi,
    fs::{file_table::FileTable, fs_resolver::FsResolver, utils::FileCreationMask},
    prelude::*,
    process::namespaces::Namespaces,
    thread::{allocate_tid, thread_table, Thread, Tid},
};

bitflags! {
    pub struct CloneFlags: u32 {
        const CLONE_VM      = 0x00000100;       /* Set if VM shared between processes.  */
        const CLONE_FS      = 0x00000200;       /* Set if fs info shared between processes.  */
        const CLONE_FILES   = 0x00000400;       /* Set if open files shared between processes.  */
        const CLONE_SIGHAND = 0x00000800;       /* Set if signal handlers shared.  */
        const CLONE_PIDFD   = 0x00001000;       /* Set if a pidfd should be placed in parent.  */
        const CLONE_PTRACE  = 0x00002000;       /* Set if tracing continues on the child.  */
        const CLONE_VFORK   = 0x00004000;       /* Set if the parent wants the child to wake it up on mm_release.  */
        const CLONE_PARENT  = 0x00008000;       /* Set if we want to have the same parent as the cloner.  */
        const CLONE_THREAD  = 0x00010000;       /* Set to add to same thread group.  */
        const CLONE_NEWNS   = 0x00020000;       /* Set to create new namespace.  */
        const CLONE_SYSVSEM = 0x00040000;       /* Set to shared SVID SEM_UNDO semantics.  */
        const CLONE_SETTLS  = 0x00080000;       /* Set TLS info.  */
        const CLONE_PARENT_SETTID = 0x00100000; /* Store TID in userlevel buffer before MM copy.  */
        const CLONE_CHILD_CLEARTID = 0x00200000;/* Register exit futex and memory location to clear.  */
        const CLONE_DETACHED = 0x00400000;      /* Create clone detached.  */
        const CLONE_UNTRACED = 0x00800000;      /* Set if the tracing process can't force CLONE_PTRACE on this clone.  */
        const CLONE_CHILD_SETTID = 0x01000000;  /* Store TID in userlevel buffer in the child.  */
        const CLONE_NEWCGROUP   = 0x02000000;	/* New cgroup namespace.  */
        const CLONE_NEWUTS	= 0x04000000;	    /* New utsname group.  */
        const CLONE_NEWIPC	= 0x08000000;	    /* New ipcs.  */
        const CLONE_NEWUSER	= 0x10000000;	    /* New user namespace.  */
        const CLONE_NEWPID	= 0x20000000;	    /* New pid namespace.  */
        const CLONE_NEWNET	= 0x40000000;	    /* New network namespace.  */
        const CLONE_IO	= 0x80000000;	        /* Clone I/O context.  */
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CloneArgs {
    new_sp: u64,
    stack_size: usize,
    parent_tidptr: Vaddr,
    child_tidptr: Vaddr,
    tls: u64,
    clone_flags: CloneFlags,
}

impl CloneArgs {
    /// Clone Args for syscall fork.
    /// TODO: set the correct values
    pub const fn for_fork() -> Self {
        CloneArgs {
            new_sp: 0,
            stack_size: 0,
            parent_tidptr: 0,
            child_tidptr: 0,
            tls: 0,
            clone_flags: CloneFlags::empty(),
        }
    }

    pub const fn new(
        new_sp: u64,
        stack_size: usize,
        parent_tidptr: Vaddr,
        child_tidptr: Vaddr,
        tls: u64,
        clone_flags: CloneFlags,
    ) -> Self {
        CloneArgs {
            new_sp,
            stack_size,
            parent_tidptr,
            child_tidptr,
            tls,
            clone_flags,
        }
    }
}

impl From<u64> for CloneFlags {
    fn from(flags: u64) -> Self {
        // We use the lower 32 bits
        let clone_flags = (flags & 0xffff_ffff) as u32;
        CloneFlags::from_bits_truncate(clone_flags)
    }
}

impl CloneFlags {
    fn check_unsupported_flags(&self) -> Result<()> {
        let supported_flags = CloneFlags::CLONE_VM
            | CloneFlags::CLONE_FS
            | CloneFlags::CLONE_FILES
            | CloneFlags::CLONE_SIGHAND
            | CloneFlags::CLONE_THREAD
            | CloneFlags::CLONE_SYSVSEM
            | CloneFlags::CLONE_SETTLS
            | CloneFlags::CLONE_PARENT_SETTID
            | CloneFlags::CLONE_CHILD_SETTID
            | CloneFlags::CLONE_CHILD_CLEARTID
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWUTS
            | CloneFlags::CLONE_NEWNET;
        let unsupported_flags = *self - supported_flags;
        if !unsupported_flags.is_empty() {
            panic!("contains unsupported clone flags: {:?}", unsupported_flags);
        }
        Ok(())
    }
}

/// Clone a child thread or child process.
///
/// FIXME: currently, the child process or thread will be scheduled to run at once,
/// but this may not be the expected bahavior.
pub fn clone_child(
    ctx: &Context,
    parent_context: &UserContext,
    clone_args: CloneArgs,
) -> Result<Tid> {
    clone_args.clone_flags.check_unsupported_flags()?;
    if clone_args.clone_flags.contains(CloneFlags::CLONE_THREAD) {
        let child_thread = clone_child_thread(ctx, parent_context, clone_args)?;
        child_thread.run();

        let child_tid = child_thread.tid();
        Ok(child_tid)
    } else {
        let child_process = clone_child_process(ctx, parent_context, clone_args)?;
        child_process.run();

        let child_pid = child_process.pid();
        Ok(child_pid)
    }
}

fn clone_child_thread(
    ctx: &Context,
    parent_context: &UserContext,
    clone_args: CloneArgs,
) -> Result<Arc<Thread>> {
    let Context {
        process,
        posix_thread,
        thread: _,
        task: _,
    } = ctx;

    let clone_flags = clone_args.clone_flags;
    debug_assert!(clone_flags.contains(CloneFlags::CLONE_VM));
    debug_assert!(clone_flags.contains(CloneFlags::CLONE_FILES));
    debug_assert!(clone_flags.contains(CloneFlags::CLONE_SIGHAND));
    let child_root_vmar = process.root_vmar();

    let child_user_space = {
        let child_vm_space = child_root_vmar.vm_space().clone();
        let child_cpu_context = clone_cpu_context(
            parent_context,
            clone_args.new_sp,
            clone_args.stack_size,
            clone_args.tls,
            clone_flags,
        );
        Arc::new(UserSpace::new(child_vm_space, child_cpu_context))
    };
    clone_sysvsem(clone_flags)?;

    // Inherit sigmask from current thread
    let sig_mask = posix_thread.sig_mask().load(Ordering::Relaxed).into();

    let child_tid = allocate_tid();
    let child_thread = {
        let credentials = {
            let credentials = ctx.posix_thread.credentials();
            Credentials::new_from(&credentials)
        };

        let thread_builder = PosixThreadBuilder::new(child_tid, child_user_space, credentials)
            .process(posix_thread.weak_process())
            .sig_mask(sig_mask);
        thread_builder.build()
    };

    process.threads().lock().push(child_thread.clone());

    let child_posix_thread = child_thread.as_posix_thread().unwrap();
    clone_parent_settid(child_tid, clone_args.parent_tidptr, clone_flags)?;
    clone_child_cleartid(child_posix_thread, clone_args.child_tidptr, clone_flags)?;
    clone_child_settid(child_posix_thread, clone_args.child_tidptr, clone_flags)?;
    Ok(child_thread)
}

fn clone_child_process(
    ctx: &Context,
    parent_context: &UserContext,
    clone_args: CloneArgs,
) -> Result<Arc<Process>> {
    let Context {
        process,
        posix_thread,
        thread: _,
        task: _,
    } = ctx;

    let clone_flags = clone_args.clone_flags;

    // clone vm
    let child_process_vm = {
        let parent_process_vm = process.vm();
        clone_vm(parent_process_vm, clone_flags)?
    };

    // clone user space
    let child_user_space = {
        let child_cpu_context = clone_cpu_context(
            parent_context,
            clone_args.new_sp,
            clone_args.stack_size,
            clone_args.tls,
            clone_flags,
        );
        let child_vm_space = {
            let child_root_vmar = child_process_vm.root_vmar();
            child_root_vmar.vm_space().clone()
        };
        Arc::new(UserSpace::new(child_vm_space, child_cpu_context))
    };

    // clone file table
    let child_file_table = clone_files(process.file_table(), clone_flags);

    // clone fs
    let child_fs = clone_fs(process.fs(), clone_flags);

    // clone umask
    let child_umask = {
        let parent_umask = process.umask().read().get();
        Arc::new(RwLock::new(FileCreationMask::new(parent_umask)))
    };

    // clone sig dispositions
    let child_sig_dispositions = clone_sighand(process.sig_dispositions(), clone_flags);

    // clone system V semaphore
    clone_sysvsem(clone_flags)?;

    // inherit parent's sig mask
    let child_sig_mask = posix_thread.sig_mask().load(Ordering::Relaxed).into();

    // inherit parent's nice value
    let child_nice = process.nice().load(Ordering::Relaxed);

    let child_tid = allocate_tid();

    let child = {
        let child_elf_path = process.executable_path();
        let child_thread_builder = {
            let child_thread_name = ThreadName::new_from_executable_path(&child_elf_path)?;

            let credentials = {
                let credentials = ctx.posix_thread.credentials();
                Credentials::new_from(&credentials)
            };

            PosixThreadBuilder::new(child_tid, child_user_space, credentials)
                .thread_name(Some(child_thread_name))
                .sig_mask(child_sig_mask)
        };

        let mut process_builder =
            ProcessBuilder::new(child_tid, &child_elf_path, posix_thread.weak_process());

        process_builder
            .main_thread_builder(child_thread_builder)
            .process_vm(child_process_vm)
            .file_table(child_file_table)
            .fs(child_fs)
            .umask(child_umask)
            .sig_dispositions(child_sig_dispositions)
            .nice(child_nice);

        process_builder.build()?
    };

    // Deals with clone flags
    let child_thread = thread_table::get_thread(child_tid).unwrap();
    let child_posix_thread = child_thread.as_posix_thread().unwrap();
    clone_parent_settid(child_tid, clone_args.parent_tidptr, clone_flags)?;
    clone_child_cleartid(child_posix_thread, clone_args.child_tidptr, clone_flags)?;
    clone_child_settid(child_posix_thread, clone_args.child_tidptr, clone_flags)?;

    // clone namespaces and switch to new namespaces
    let child_namespaces = clone_namespaces(&child, current.namespaces(), clone_flags);
    child.switch_namespaces(child_namespaces);

    // Sets parent process and group for child process.
    set_parent_and_group(process, &child);

    Ok(child)
}

fn clone_child_cleartid(
    child_posix_thread: &PosixThread,
    child_tidptr: Vaddr,
    clone_flags: CloneFlags,
) -> Result<()> {
    if clone_flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
        *child_posix_thread.clear_child_tid().lock() = child_tidptr;
    }
    Ok(())
}

fn clone_child_settid(
    child_posix_thread: &PosixThread,
    child_tidptr: Vaddr,
    clone_flags: CloneFlags,
) -> Result<()> {
    if clone_flags.contains(CloneFlags::CLONE_CHILD_SETTID) {
        *child_posix_thread.set_child_tid().lock() = child_tidptr;
    }
    Ok(())
}

fn clone_parent_settid(
    child_tid: Tid,
    parent_tidptr: Vaddr,
    clone_flags: CloneFlags,
) -> Result<()> {
    if clone_flags.contains(CloneFlags::CLONE_PARENT_SETTID) {
        CurrentUserSpace::get().write_val(parent_tidptr, &child_tid)?;
    }
    Ok(())
}

/// Clone child process vm. If CLONE_VM is set, both threads share the same root vmar.
/// Otherwise, fork a new copy-on-write vmar.
fn clone_vm(parent_process_vm: &ProcessVm, clone_flags: CloneFlags) -> Result<ProcessVm> {
    if clone_flags.contains(CloneFlags::CLONE_VM) {
        Ok(parent_process_vm.clone())
    } else {
        ProcessVm::fork_from(parent_process_vm)
    }
}

fn clone_cpu_context(
    parent_context: &UserContext,
    new_sp: u64,
    stack_size: usize,
    tls: u64,
    clone_flags: CloneFlags,
) -> UserContext {
    let mut child_context = *parent_context;
    // The return value of child thread is zero
    child_context.set_syscall_ret(0);

    if clone_flags.contains(CloneFlags::CLONE_VM) {
        // if parent and child shares the same address space, a new stack must be specified.
        debug_assert!(new_sp != 0);
    }
    if new_sp != 0 {
        // If stack size is not 0, the `new_sp` points to the BOTTOMMOST byte of stack.
        if stack_size != 0 {
            child_context.set_stack_pointer(new_sp as usize + stack_size);
        }
        // If stack size is 0, the new_sp points to the TOPMOST byte of stack.
        else {
            child_context.set_stack_pointer(new_sp as usize);
        }
    }
    if clone_flags.contains(CloneFlags::CLONE_SETTLS) {
        child_context.set_tls_pointer(tls as usize);
    }

    child_context
}

fn clone_fs(
    parent_fs: &Arc<RwMutex<FsResolver>>,
    clone_flags: CloneFlags,
) -> Arc<RwMutex<FsResolver>> {
    if clone_flags.contains(CloneFlags::CLONE_FS) {
        parent_fs.clone()
    } else {
        Arc::new(RwMutex::new(parent_fs.read().clone()))
    }
}

fn clone_files(
    parent_file_table: &Arc<Mutex<FileTable>>,
    clone_flags: CloneFlags,
) -> Arc<Mutex<FileTable>> {
    // if CLONE_FILES is set, the child and parent shares the same file table
    // Otherwise, the child will deep copy a new file table.
    // FIXME: the clone may not be deep copy.
    if clone_flags.contains(CloneFlags::CLONE_FILES) {
        parent_file_table.clone()
    } else {
        Arc::new(Mutex::new(parent_file_table.lock().clone()))
    }
}

fn clone_namespaces(
    process: &Arc<Process>,
    parent_namespaces: &Arc<Mutex<Namespaces>>,
    clone_flags: CloneFlags,
) -> Arc<Mutex<Namespaces>> {
    let parent_namespaces = parent_namespaces.lock();

    let new_mnt_ns = if clone_flags.contains(CloneFlags::CLONE_NEWNS) {
        parent_namespaces.mnt_ns().copy_mnt_ns(process)
    } else {
        parent_namespaces.mnt_ns().clone()
    };

    let new_uts_ns = if clone_flags.contains(CloneFlags::CLONE_NEWUTS) {
        parent_namespaces.uts_ns().copy_uts_ns()
    } else {
        parent_namespaces.uts_ns().clone()
    };

    let mut new_net_ns = parent_namespaces.net_ns().clone();
    if clone_flags.contains(CloneFlags::CLONE_NEWNET) {
        (new_net_ns, _) = NetNamespace::new_with_loopback();
    }

    Arc::new(Mutex::new(Namespaces::new(
        new_mnt_ns, new_uts_ns, new_net_ns,
    )))
}

fn clone_sighand(
    parent_sig_dispositions: &Arc<Mutex<SigDispositions>>,
    clone_flags: CloneFlags,
) -> Arc<Mutex<SigDispositions>> {
    // similer to CLONE_FILES
    if clone_flags.contains(CloneFlags::CLONE_SIGHAND) {
        parent_sig_dispositions.clone()
    } else {
        Arc::new(Mutex::new(*parent_sig_dispositions.lock()))
    }
}

fn clone_sysvsem(clone_flags: CloneFlags) -> Result<()> {
    if clone_flags.contains(CloneFlags::CLONE_SYSVSEM) {
        warn!("CLONE_SYSVSEM is not supported now");
    }
    Ok(())
}

fn set_parent_and_group(parent: &Process, child: &Arc<Process>) {
    let process_group = parent.process_group().unwrap();

    let mut process_table_mut = process_table::process_table_mut();
    let mut group_inner = process_group.inner.lock();
    let mut child_group_mut = child.process_group.lock();
    let mut children_mut = parent.children().lock();

    children_mut.insert(child.pid(), child.clone());

    group_inner.processes.insert(child.pid(), child.clone());
    *child_group_mut = Arc::downgrade(&process_group);

    process_table_mut.insert(child.pid(), child.clone());
}

pub fn unshare(unshare_flags: CloneFlags) -> Result<()> {
    let current = current!();
    let child_namespaces = clone_namespaces(&current, current.namespaces(), unshare_flags);
    current.switch_namespaces(child_namespaces);
    Ok(())
}
