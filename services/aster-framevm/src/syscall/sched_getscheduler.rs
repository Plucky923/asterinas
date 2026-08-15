// SPDX-License-Identifier: MPL-2.0

use super::{
    SyscallReturn,
    sched_getattr::{LinuxSchedAttr, SchedAttrAccess, access_sched_attr_with},
};
use crate::{prelude::*, thread::Tid};

pub fn sys_sched_getscheduler(tid: Tid, ctx: &Context) -> Result<SyscallReturn> {
    let policy = access_sched_attr_with(tid, SchedAttrAccess::Read, ctx, |attr| Ok(attr.policy()))?;
    let policy = LinuxSchedAttr::try_from(policy)?.sched_policy;
    Ok(SyscallReturn::Return(policy as isize))
}
