# FrameVM Design: CPU, Memory, and I/O Virtualization

This page specifies the three mechanisms that make a FrameVM service behave
as an isolated virtualized execution domain, and maps each claim to the
current implementation:

1. Task groups connect Host scheduling with the FrameVM's per-vCPU
   scheduling domains.
2. The memory domain gives each FrameVM an independent limit, allocator
   bridge, physical-page ownership model, and teardown boundary.
3. The device model gives the FrameVM service a private virtual PCI bus,
   typed FrameV devices, and generation-safe I/O paths to Host resources.

FrameVM is Host-integrated virtualization. It does not start a second QEMU
process or emulate a complete hardware machine. A FrameVM service is a
kernel-shaped, safe-Rust program running on Host-backed tasks. FrameVisor
owns the VM boundary around those tasks: execution, memory, devices,
interrupts, and lifecycle.

For the control-file ABI and the user-space transaction that creates a VM,
see [FrameVM Control Device](framevm.md). This page focuses on what happens
after the control plane has handed a configuration to FrameVisor.
For the complete FrameV control-plane, data-plane, claim, lifecycle, and
virtual-interrupt design, see
[FrameV Design: Type-Safe Paravirtual I/O](framev-design.md).

## Design contract: model, assumptions, and claims

The document deliberately separates a **mechanism** from a **property**. A
mechanism names the concrete object or protocol used by the current tree. A
property is the safety or progress condition that mechanism is intended to
establish. This distinction matters: a field layout or a test is evidence for
a property, but is not the property itself.

### System model

For a FrameVM identity `v`, the Host creates a tuple

```text
VM(v) = (E_v, M_v, D_v, G_v)

E_v     execution context: vCPUs, Host-backed tasks, and service scheduler
M_v     memory domain and v-indexed physical/logical custody state
D_v     private virtual PCI topology and FrameV function runtimes
G_v     aggregate TaskGroup plus one FrameSchedGroup per vCPU
```

The tuple is a single authority boundary: `FrameVm` owns its members. Global
registries are indexes, not alternate owners. In particular, a lookup by VM
ID never authorizes a resource use on its own; scheduling, memory release, or
device access must additionally carry the appropriate object identity,
ownership evidence, or a resource claim token.

There are three relevant participants:

- **Host** owns physical CPUs, physical memory, and hardware resources.
- **FrameVisor** is the privileged provider of `VM(v)`: it admits resources,
  mediates cross-domain operations, and tears the tuple down.
- **FrameVM service** is the kernel-shaped program executing inside `E_v`.
  In a FrameV protocol direction it is the **FrameV Guest**; the corresponding
  FrameVisor component is the **FrameV Host**.

An outer QEMU process used by development tests is outside this model. It is
a carrier for the Host kernel and neither schedules a FrameVM service nor
defines the FrameVM memory limit.

### Assumptions and fault model

The claims below are conditional on the trusted substrate: the Host kernel and
OSTD primitives correctly enforce their contracts; a `FrameVm` is not
silently aliased under a second live identity; and, for assigned PCI, the
platform IOMMU and interrupt-remapping facilities enforce the DMA and IRQ
isolation configured by FrameVisor. The document does not claim to defend
against arbitrary native-code execution that bypasses those trusted
substrates.

Within that boundary, the design treats the following as ordinary events:
allocation failure, stale task or device work after restart, concurrent
allocation and teardown, a failed device operation, and a FrameVM that must
stop while it still owns resources. A failure must be reported locally or
leave the VM in a diagnosable stopping state; it must not silently transfer
ownership to another FrameVM.

### Safety properties and conditional progress

The design makes five safety claims for every live `VM(v)`:

1. **Execution attribution.** A Host-backed FrameVM task executes only with
   the `FrameVcpuId(v, i)` to which it was bound.
2. **Memory confinement.** Physical backing, Host control charges, and
   registered logical RRef payloads are admitted against `M_v`, never against
   a sibling VM's domain.
3. **Exclusive physical custody.** A tracked physical extent has at most one
   `OwnerRecord`; a release must prove the VM and domain identity expected by
   that record.
4. **I/O authority confinement.** A FrameV operation requires a current,
   family-typed claim for a private virtual PCI function; a BDF alone is not
   authority to use a Host resource.
5. **Resource freshness.** Work, claims, virtual interrupts, and retained
   receive state carry the owning resource identity; after restart or
   revocation, an old resource claim cannot regain authority.

The design has deliberately narrower progress claims. Given eventual Host
scheduling, completion of already-admitted calls, and release of retained
resources, a stopping VM drains and can restart. If those preconditions do
not hold, FrameVisor keeps the VM in `Stopping` and reports the remaining
accounting state instead of falsely publishing `Stopped`. Thus `Stopped` is a
drain-completion certificate, not merely a requested lifecycle state.

The remainder of this page states the protocols that establish these claims.
Each protocol is presented as an invariant, its transition rule, and the
implementation objects that discharge the rule.

## Terminology

| Term | Meaning in this design |
| --- | --- |
| Host | The ordinary Asterinas kernel that owns physical CPUs, memory, and Host devices. |
| FrameVisor | The privileged component that creates and manages FrameVM instances. |
| FrameVM | One execution and resource domain represented by a `FrameVm`. |
| FrameVM service | The trimmed Asterinas service loaded into a FrameVM. It contains the guest kernel-like runtime and starts the guest workload. |
| FrameV | The virtual-device ABI and device families used by the FrameVM service. |
| FrameV Guest / FrameV Host | The protocol directions of a FrameV operation: the FrameVM service initiates or consumes an operation as the Guest, and the corresponding FrameVisor component provides it as the Host. These terms do not imply a conventional hardware VM. |
| FrameV control plane | The VM-private PCI discovery, configuration, BAR-layout, claim, and virtual-interrupt interface. It is not a payload transport or a Host-memory mapping. |
| FrameV data plane | The family-specific operation and ownership contract used after a function is claimed. It deliberately has no universal ring, descriptor, or simulated-DMA object. |
| `TaskGroup` | The ordinary kernel scheduler's hierarchical fair-scheduling object. It aggregates a FrameVM's Host scheduler weight. |
| `FrameSchedGroup` | The FrameVisor object for one vCPU. It is the entity placed in the Host outer runqueue. |
| `FrameTaskData` | Binding metadata attached to a Host-backed task. It records the FrameVM, vCPU group, and task kind. |
| `MemoryDomain` | The per-FrameVM admission controller. It owns the page-rounded limit, reservation state, physical and logical counters, and teardown wait queue. |
| `MemoryReservation` | A revocable admission transaction. It contributes to the domain's reserved bytes until it either commits a resource charge or drops and rolls back. |
| `FrameVmAllocator` | The per-FrameVM bridge that installs FrameVM service provider cells and routes frame, segment, heap, and custom-provider operations to Host OSTD. |
| `FrameLease` | The ownership handle attached to a Host-backed frame or segment. Its final release participates in the FrameVM owner table and memory accounting. |
| RRef accounting | The exchange-layer accounting adapter that charges Guest-owned payloads to the owning `MemoryDomain`; it is not the VM state owner. |
| Resource claim token | A device, interrupt, or ownership token that is checked at the resource boundary and invalidated when that resource is revoked. |
| `FunctionClaim` | The current, non-forgeable capability to use one FrameV family on one virtual PCI function during one generation. |
| Mediated PCI passthrough | Exclusive delegation of a physical PCI function whose native driver protocol is reused by the service, while FrameVisor retains configuration/BAR validation, DMA/IRQ isolation, and revocation authority. |
| `framevmm` | A user-space client of `/dev/framevm`. Its QEMU-shaped command line does not make it a VMM. |

The service is sometimes called the guest because it is the guest
kernel-like runtime. Processes started by the service are the guest
workload. The outer QEMU used by tests, when present, is only a carrier for
the Host kernel and is not the FrameVM implementation.

## Authority and ownership partition

The current design has two different kinds of group. They must not be
treated as aliases:

| Object | Cardinality | Queue or state it owns | Responsibility |
| --- | ---: | --- | --- |
| `TaskGroup` | One scheduler object for a FrameVM start | Per-CPU fair attributes, per-CPU fair runqueues, user/system tick counters | Places the FrameVM's aggregate fair weight in the Host task-group hierarchy. |
| `FrameSchedGroup` | One per FrameVM vCPU | One `RunState`, one Host CPU binding, one `InterruptHandler`, weak references to service tasks | Represents that vCPU as a fair entity in the Host scheduler and arbitrates interrupt-handler work against service work. |
| FrameVM service scheduler | One per FrameVM, with a local runqueue per vCPU | Inner service-task queues | Chooses which service task runs after the Host scheduler has selected a vCPU group. |
| `Vcpu` | One per FrameVM vCPU | vCPU index, `InterruptHandler`, and its `FrameSchedGroup` | Couples the virtual CPU identity to interrupt handling and scheduling. |
| `FrameTaskData` | One per Host-backed FrameVM task | VM reference, bound vCPU, and `Bootstrap`/`Service`/`Interrupt` kind | Prevents a task from being scheduled through a foreign VM or vCPU. |
| `MemoryDomain` | One per FrameVM | Limit, state, reservation counter, physical/RRef committed counters, reusable bytes | Makes live FrameVM allocation paths obey one page-granular limit and one stop fence. |
| `FrameVmAllocator` | At most one active allocator per loaded service image | Frame/heap provider cells, heap state, custom-provider grants, provider fault state | Connects service-side OSTD allocation APIs to VM-scoped Host backing and release. |
| `OwnerRecord` / `FrameLease` | One owner record per tracked physical extent | Physical address, FrameVM owner, hidden metadata, domain, cache/provider/service flags, busy count | Prevents duplicate adoption and controls when a physical page may be scrubbed and returned to Host. |
| RRef accounting | Exchange-layer accounting adapter | RRef owner, payload size, and `MemoryDomain` charge | Accounts logical shared-heap payloads without becoming a VM owner. |
| `VirtualPciBus` | One per FrameVM | Virtual functions, BDFs, config space, BARs, MSI-X state | Owns the guest-visible device topology and PCI configuration authority. |
| `FunctionRuntime` | One per virtual PCI function | Admission state, claim, generation, and active-call count | Serializes device start/stop with FrameV Guest and FrameV Host calls. |

The resulting ownership chain is:

```text
FrameVm
├── MemoryDomain
│   ├── page-granular limit and reservation state
│   └── physical ownership and RRef charges
├── FrameVmAllocator
│   ├── FrameProvider
│   ├── HeapProvider
│   └── clone of the MemoryDomain used for allocation admission
├── Vcpu[0..n)
│   └── FrameSchedGroup
│       ├── Host outer fair-queue entity
│       ├── InterruptHandler
│       └── FrameVM service-task bindings
├── FrameVM service scheduler
│   └── per-vCPU inner runqueues
└── Devices
    └── VirtualPciBus
        └── VirtualPciFunction
            └── FunctionRuntime
```

`FrameVm` is the owner of the per-VM state. The global VM registry is only a
lookup and lifecycle-management facility. It is not a second owner of a
vCPU, task, memory domain, virtual function, or device payload. The
The RRef accounting adapter and physical-frame owner table are global indexes required by
their respective object representations; the VM identity and
`MemoryDomain` remain the authority for a FrameVM's memory budget.

## CPU virtualization: two-level scheduling

### Scheduling contract

FrameVM virtualizes a CPU as a **two-level scheduling composition**, not as a
Host task per service thread. For VM `v` with `n` vCPUs, let `G_v` denote its
aggregate `TaskGroup` and `g_(v,i)` denote the `FrameSchedGroup` for vCPU
`i`. The Host scheduler chooses a runnable `g_(v,i)` under the fair hierarchy
rooted at `G_v`; only after that choice does the FrameVM service scheduler
choose one service task for vCPU `i`.

```text
Host fair scheduler:       G_v -> g_(v,i)
FrameVM service scheduler: g_(v,i) -> task(v, i)
```

The critical safety rule is:

```text
run(task, v, i)  =>  task.vm = v ∧ task.group = g_(v,i)
```

The design therefore never infers a FrameVM context from a Host CPU alone.
CPU placement answers *where* `g_(v,i)` may run; the inner queue and task
binding answer *which* FrameVM task may run there. Rebinding is completed
before a task becomes observable in its final inner queue, which preserves
the rule under migration.

The progress property is conditional. If the Host eventually selects a
runnable `g_(v,i)`, the group presents either deliverable interrupt work or
a runnable service task. interrupt handler work is preferred to avoid interrupt-driven
deadlock, but after eight consecutive interrupt handler selections a runnable service task
is given a selection opportunity. This is a starvation bound on the local
selection policy, not a latency or Host-wide CPU-share guarantee.

### 1. The kernel `TaskGroup` is the aggregate fair-scheduling layer

`TaskGroup` lives in the ordinary kernel scheduler. It is a hierarchical
fair-scheduling object, similar in purpose to a cgroup scheduling node. Its
current fields are:

```text
TaskGroup
├── parent: Weak<TaskGroup>
├── fair_attrs[cpu]: FairAttr
├── fair_rqs[cpu]: FairClassRq
├── user_ticks[cpu]: AtomicU64
└── system_ticks[cpu]: AtomicU64
```

The root group has no parent. A child stores a weak parent reference, which
keeps the hierarchy acyclic. Every group has per-CPU fair attributes and
per-CPU fair runqueues; the tick counters charge user-mode and system-mode
time to the group on the relevant Host CPU.

When a FrameVM is started, the Host scheduler creates one child group under
the caller's current task-group parent. The configured FrameVM share is
converted to the kernel scheduler's normal weight scale:

```text
weight = max(
    1,
    saturating_mul(share, DEFAULT_CGROUP_WEIGHT)
        / DEFAULT_FRAMEVM_SHARE,
)
```

The share is validated before this conversion. Saturating arithmetic keeps
an oversized user value from wrapping into a small weight. The group is a
scheduler object; it does not contain the FrameVM's task binding metadata.

The creation parent is captured at FrameVM start. Moving the creator task to
another group later does not move the already-created FrameVM group. This is
important because the parent relationship is part of the scheduling
contract for that VM, not a live lookup of the creator's current group.

### 2. `FrameSchedGroup` is the actual Host scheduling entity

`FrameSchedGroup` lives in FrameVisor and is created for each `Vcpu`. Its
identity is explicit:

```text
FrameVcpuId {
    vm_id: VmId,
    vcpu_index: usize,
}
```

The object contains the state required to place and pick one virtual CPU:

```text
FrameSchedGroup
├── id: FrameVcpuId
├── share: u32
├── host_cpu: HostSpinLock<HostCpuId>
├── interrupt_handler: Arc<InterruptHandler>
├── state: HostSpinLock<RunState>
└── service_tasks: HostSpinLock<Vec<Weak<HostTask>>>
```

The `FrameSchedGroup` is registered as a fair entity in the Host outer
runqueue with the FrameVM's kernel `TaskGroup` as its scheduling parent. A
FrameVM with four vCPUs therefore has one aggregate `TaskGroup` and four
outer scheduling entities. It does not have one kernel `TaskGroup` per
vCPU.

`RunState` records whether the group is queued, whether new work is admitted,
bootstrap handoff state, service handoff state, and the recent interrupt-handler
pick count. It is the small amount of state needed
to make an outer fair-queue entity reflect an inner scheduler without
putting the inner queue inside the Host runqueue.

### 3. CPU placement and affinity

Each `FrameSchedGroup` is bound to one Host CPU at a time. Registration uses
the requested CPU affinity and the Host scheduler's placement state:

1. discard CPUs outside the requested affinity;
2. prefer a CPU with the lowest number of assigned FrameVM groups;
3. use the outer runqueue length and a round-robin cursor to break ties;
4. bind the group and enable FrameVisor preemption on the selected CPU.

The scheduler keeps the placement decision under a placement lock. An
affinity update can migrate a group only after work on a disallowed source
CPU has been asked to yield. The old outer entity is dequeued before the new
CPU binding is published, and it is re-enqueued only if the inner group is
still runnable. Destroying a VM first removes all of its groups from the
Host scheduler and then removes the FrameVisor placement records.

This gives the two `smp` concepts distinct meanings:

```text
outer Host SMP / CPU affinity  -> where a FrameSchedGroup runs
FrameVM -smp                   -> how many Vcpu/FrameSchedGroup objects exist
```

### 4. Task kinds and binding

FrameVM service execution uses Host-backed tasks. `FrameTaskData` is attached
to each such task and contains:

```text
FrameTaskData
├── frame_vm: Arc<FrameVm>
├── bound_vcpu: HostSpinLock<FrameVcpuId, HostLocalIrqDisabled>
├── kind: FrameTaskKind
└── stack charge
```

The task kind is closed over three values:

| Kind | Role | Scheduling source |
| --- | --- | --- |
| `Bootstrap` | Runs the early service setup before the per-VM service scheduler is ready. | A temporary bootstrap task associated with the vCPU group. |
| `Service` | Runs normal FrameVM service threads and kernel tasks. | The FrameVM service scheduler's vCPU-local runqueue. |
| `Interrupt` | Drains virtual-interrupt work and runs the vCPU interrupt-handling context. | The vCPU's `InterruptHandler`. |

Creating `FrameTaskData` charges a fixed FrameVM task-stack budget and binds
the task to its owning `FrameVm` and vCPU. A task can be rebound only to a
group belonging to the same `FrameVm`. A normal lookup rejects a `Bootstrap`
task; bootstrap lookup is a separate operation.

The enqueue path binds a service task before making it visible to the inner
service scheduler. If the inner scheduler selects a different vCPU than the
initial binding, the task is rebound to the final `FrameSchedGroup` before
the enqueue operation completes. This ordering prevents a task from being
visible in one vCPU's queue while its task-local context names another vCPU.

Each group also keeps weak references to its service tasks. Host-side wakeup
can take strong references while holding the group lock, release the lock,
and only then call `wake_up`. The wakeup enters the Host scheduler, so it is
never performed while the group task list or a Host runqueue lock is held.

### 5. How the two schedulers cooperate

The scheduling path is object-first:

```text
work becomes runnable
        │
        ├── virtual IRQ becomes deliverable
        │       └── interrupt handler context marks the vCPU runnable
        └── service task wakes
                └── inner service runqueue becomes runnable
        │
        ▼
FrameSchedGroup::has_runnable_work()
        │
        ├── admission open: deliverable interrupt handler work OR service work
        └── admission closed: pending exit work only
        │
        ▼
Host outer fair runqueue
        │
        ▼
pick FrameSchedGroup
        │
        ├── pick interrupt handler work when deliverable
        ├── periodically hand off to service work
        └── pick the vCPU-local service task
        │
        ▼
Host-backed task runs in FrameVM vCPU scope
```

The outer runqueue contains the `FrameSchedGroup` object, not every inner
service task. When the outer scheduler picks that object, it first preserves
an in-flight task if one is still valid. Otherwise it asks the group to
select inner work. The result can be an interrupt handler task, a service task, or no work.

`has_runnable_work` checks the handler and vCPU-local service queue directly.
If the group is still admitting work, both sources can keep it runnable. If
admission is closed, only a pending exit is allowed to keep the group
runnable. The outer scheduler rechecks readiness after the inner operation
returns; the inner IRQ guard never calls back into the Host scheduler.

Picking is interrupt-handler-first by default because virtual interrupt delivery
may be needed to make service progress. To prevent a busy interrupt source from
starving the service scheduler, the group forces a service handoff after eight
consecutive interrupt-handler picks. If the preferred class has no task,
selection falls back to the other class.

After a task is selected, the scheduler enters the FrameVM vCPU scope. The
scope supplies the current `FrameVcpuId` used by task binding, device claims,
virtual interrupt delivery, and service entry-point dispatch. The task is
therefore identified by both its Host task object and its FrameVM context.

### 6. Admission and teardown

The scheduler state is admission-based:

```text
Stopped --open_admission--> Starting/Running
Running --close_admission--> stopping
Stopped --open_admission--> Running
```

`open_admission` opens service work and resets bootstrap handoff, service
handoff, and interrupt handler-pick accounting.
`close_admission` prevents new service work from keeping the outer group
runnable, but leaves pending exit work deliverable so tasks can leave
cleanly.

The important start sequence is:

1. `FrameVm::start` changes the VM from `Stopped` to `Starting`.
2. Memory, control-resource charges, the allocator, task admission, and
   VM CPU-local state are activated.
3. Every vCPU resets its interrupt handler state, opens admission, and starts its interrupt handler task.
4. Device runtimes become ready.
5. The VM publishes `Running`.

If a step fails, the activated pieces are rolled back. New work is not
admitted until the normal reset and start path has completed.

The important stop sequence is:

1. close FrameVM task admission;
2. close virtual-function admission and revoke PCI claims;
3. drain calls that were already admitted;
4. request service and interrupt handler execution to stop;
5. wait for owned vCPU/interrupt handler tasks to exit;
6. release scheduler groups and VM-owned resources.

The exact cleanup is split between `FrameVm`, `Devices`, the scheduler, and
the control-plane object, but the ordering rule is the same: new work is
closed before old work is destroyed. A task, device call, or interrupt from
the old runtime cannot re-enter a restarted VM.

### 7. Locking and scheduling invariants

The cross-layer lock order is:

```text
Host scheduler / outer runqueue
    -> FrameSchedGroup state
        -> FrameVM service scheduler / inner runqueue
            -> task-local state
```

The implementation follows these rules:

- Do not block, perform service work, or perform I/O while holding a Host
  spinlock.
- Do not synchronously wake a Host task while holding a runqueue lock.
- Keep virtual IRQ versus service-queue arbitration inside `FrameSchedGroup`;
  never wake the Host scheduler from an inner IRQ guard.
- Resolve the final vCPU group after an inner-scheduler rebind instead of
  trusting an initial CPU choice.
- Treat `FrameTaskData` as binding metadata. The VM, vCPU, and inner
  scheduler remain the owners of their respective state.

## Memory virtualization: transactional admission and custody

### Memory contract

For a VM `v`, define `L_v` as its configured, page-rounded limit;
`P_v` as charged physical backing (including committed Host control charges);
`R_v` as charged logical RRef payloads; and `T_v` as bytes admitted by an
in-flight transaction but not yet committed. The central memory invariant is

```text
I_mem(v):  P_v + R_v + T_v <= L_v
```

`reusable_v` is a subset of `P_v`, not additional capacity. A cached page is
therefore still charged to `v` until it is scrubbed and returned to the Host.
This prevents a VM from retaining an uncharged private cache and makes the
observable `active_v = P_v + R_v - reusable_v` a liveness/accounting
diagnostic rather than a second limit.

Every live FrameVM physical allocation path, and every registered
Guest-owned RRef payload path, follows one transaction protocol:

1. **Reserve.** While the domain is `Accepting`, atomically test `I_mem(v)`
   with the requested byte count and add that count to `T_v`.
2. **Establish.** Obtain and initialize Host backing, adopt its ownership, or
   create the logical RRef metadata. This work happens after admission and may
   fail.
3. **Commit or roll back.** A successful establishment transfers the
   reservation into `P_v` or `R_v`. Every unsuccessful path drops the
   reservation, restoring `T_v` and, for cache reuse, `reusable_v`.

The induction is straightforward. Creation establishes the invariant with a
zeroed domain plus its explicit Host-control charge. Reserve preserves the
inequality by its check; commit preserves the total by moving bytes between
counters; rollback decreases `T_v`; and release decreases a committed term.
No successful path can increase a charged term without first holding the
corresponding reservation. The remaining sections identify the concrete
paths that must satisfy this proof obligation.

Memory isolation is not a claim that every allocation succeeds. `NoMemory` is
the specified local result when the reserve step cannot preserve `I_mem(v)`.
It is preferable to a Host-wide abort or borrowing from another domain.

### 1. The memory boundary is a per-FrameVM domain

FrameVM has two different memory limits that must not be confused:

```text
outer QEMU `MEM`        -> memory available to the Host kernel and test carrier
FrameVM `-m`             -> memory admitted to one FrameVM service and its VM-owned objects
```

The inner limit is carried by `FrameVmConfig::memory_limit_bytes` and is
validated by the FrameVM control path as a page-aligned value. `FrameVm::new`
creates one `MemoryDomain` for that VM, rejects a zero limit, and rounds the
limit to a page boundary. The domain is stored directly in `FrameVm`; it is
not looked up through a global accounting map.

Creation also computes a conservative Host-control budget from the vCPU
count, configured block devices, networking, and assigned PCI state. That
budget is charged to the new domain before devices and vCPUs are published.
It accounts for VM-specific Host objects such as task stacks and control
metadata, while physical backing allocated later enters the same domain
through the provider and ownership paths.

The boundary can therefore be summarized as:

```text
FrameVm
├── MemoryDomain                 one limit and lifecycle fence
├── control_memory_charge        Host-owned VM control resources
├── FrameVmAllocator              service-facing provider bridge
├── OwnerRecord / FrameLease      physical extent ownership
└── RRef accounting               logical shared-heap payload charges
```

`FrameVm::memory_stats()` returns a snapshot from this domain. The global VM
registry can find the `FrameVm`, but it does not own or independently count
the memory represented by these objects.

### 2. Counters and reservation semantics

`MemoryDomain` is an admission controller rather than a physical allocator.
Its `MemoryDomainInner` contains the limit, a lifecycle state, two small
spinlock-protected state blocks, and a wait queue used while reservations
drain.

The externally visible counters have the following meaning:

| Counter | Meaning |
| --- | --- |
| `limit` | The configured page-rounded upper bound for this VM. |
| `committed` | `physical_committed + rref_committed`: physical extents that are still charged, plus logical shared-heap payloads. |
| `reserved` | Bytes held by an allocation transaction between admission and commit or rollback. |
| `reusable` | Physical committed bytes whose VM-visible object is gone and whose backing can be reused. They remain committed until the backing is actually returned to Host. |
| `active` | `committed - reusable`: charged bytes still holding live VM state. |
| `oom_count` | Number of failed domain-limit admission attempts. |
| `reclaim_count` | Number of cached physical extents returned to Host. |

All byte values are rounded to pages. New and logical allocations use the
following admission condition, including in-flight transactions:

```text
physical_committed + rref_committed + reserved + requested <= limit
```

An allocation that fails this check returns `NoMemory` and increments
`oom_count`; it does not terminate the VM or affect a sibling VM. A
reusable allocation is a different transaction: it atomically moves bytes
from `reusable` to `reserved`, so two concurrent callers cannot claim the
same cached extent. Committing that transaction consumes the cache without
increasing `committed`; dropping it restores `reusable`.

The lifecycle state is part of the accounting contract:

```text
Accepting --begin_stopping--> Stopping --close--> Closed
                                \--resume--> Accepting
```

`Accepting` permits new backing and RRef charges. `Stopping` rejects new
reservations but lets already-admitted work finish. `Closed` permits no
further accounting transition. `resume` is allowed only for an empty
stopping domain, which is what makes a stopped VM restartable only after its
previous execution has completely drained.

`MemoryReservation` is an RAII transaction. Its three kinds are:

- `New`: a new physical extent is reserved, then `physical_committed` is
  increased on commit.
- `Reusable`: an already cached physical extent is reserved and removed from
  the reusable pool; commit activates it without a second physical charge.
- `Logical`: an `RRef` payload is reserved, then `rref_committed` is
  increased on commit.

If a backing allocation, metadata adoption, or provider callback fails
before commit, dropping the reservation rolls back `reserved` and restores
the reusable pool when appropriate. When the last reservation drains, the
domain wakes the stop waiter. Host-owned control resources use the same
accounting through `MemoryCharge`: `charge_host` reserves and commits the
bytes, and dropping the charge releases them from `physical_committed`.

### 3. From a service allocation to a charged physical page

The FrameVM service uses OSTD-shaped allocator interfaces. During service
image setup, `FrameVmAllocator` installs or relocates the frame and heap
provider cells used by the service. The service therefore invokes a normal
frame or heap API, while the call is routed to the allocator belonging to
the current `FrameVm`.

The physical allocation path is conceptually:

```text
FrameVM service OSTD allocation
        │
        ▼
relocated frame_cell / heap_cell
        │
        ▼
FrameVmAllocator
        ├── FrameProvider      page and segment backing
        └── HeapProvider       small slots and large heap allocations
        │
        ▼
MemoryDomain reservation
        │
        ▼
Host OSTD raw allocation and fresh-backing scrub
        │
        ▼
FrameVm owner adoption
        │
        ▼
typed Frame/Segment handle with FrameLease
```

`FrameProvider` applies the domain reservation before obtaining raw Host
backing and commits the transaction only after the backing is valid. The
allocator and ownership layer then attach the VM owner and hidden metadata
needed by OSTD-shaped frame handles. `FrameVmAllocator::alloc_service_frame`
and `alloc_service_segment` provide the corresponding service-owned page and
segment paths; they validate sizes, use checked multiplication for segment
lengths, perform an additional zero when requested, and fail closed if
ownership cannot be established. Fresh backing is scrubbed before it is
adopted regardless of the caller's zeroed flag; that flag also controls
whether a reused cached page is zeroed before reuse.

The built-in VM frame path has an explicit reuse-first policy:

```text
alloc_frame_for_vm / alloc_service_untyped_frame
    ├── reserve_reusable(PAGE_SIZE)
    │     └── take_cached_frame(vm_id, domain)
    │           └── commit; zero if requested; return existing handle
    └── if no cached frame is available:
          reserve(PAGE_SIZE)
          -> Host frame allocation and unconditional scrub
          -> adopt_frame
          -> commit; return a new handle
```

Reusing the existing OSTD handle is significant: reconstructing a cached
physical page from only its address would lose the hidden reference-count and
metadata state that the owner table protects. Custom image providers remain
on their grant/refill path and do not use this built-in cache shortcut.

`HeapProvider` keeps the service heap's `HeapState`. Small allocations are
served from heap slots backed by service-owned untyped frames; larger
allocations use segment backing. Empty heap pages can be cleared during
reclaim. The important property is that both heap and frame paths eventually
pass through the same `MemoryDomain` and owner checks, rather than allowing
the service heap to bypass the VM limit.

The allocator also supports a custom provider installed by the service. A
custom provider receives explicitly granted raw ranges, recorded in
`granted_ranges`. When it returns a frame or segment, FrameVisor checks that
the physical address is inside a live grant, consumes the grant, validates
the provider callback, and adopts the object with provider metadata. An
ambiguous callback or ownership result is a provider fault: the allocator
fails closed and the range is quarantined instead of silently returning
unaccounted memory to Host. During grant cleanup, raw pages are scrubbed,
their domain charge is released, and only then is the raw Host extent
deallocated.

### 4. Physical ownership is separate from allocation admission

The memory limit answers “may this VM acquire this many bytes?” The owner
table answers “which VM may release or use this physical extent?” Both are
needed because an OSTD frame can outlive the function that allocated it.

For each adopted physical page, `OwnerRecord` stores:

```text
OwnerRecord
├── owner: FrameOwner::FrameVm(vm_id)
├── hidden: OSTD metadata and reference-counted frame state
├── domain: the exact MemoryDomain handle
├── cached: whether the physical page is reusable
├── provider_managed: whether a custom provider controls its lifecycle
├── service_owned: whether the loaded service image may still reference it
└── busy: in-flight ownership/use count
```

`adopt_frame` rejects a physical address already present in the owner table.
It records the VM identity and exact domain identity, then returns the typed
OSTD frame together with a `FrameLease`. Release helpers validate the VM,
domain, cache/provider/service flags, busy count, and reference count before
removing the record and releasing its domain charge. `MemoryDomain::is_same`
uses `Arc` identity, so a numerically identical limit in another VM cannot be
used to release this VM's page.

This is why a dropped service frame does not immediately mean “return the
page to the Host.” The final release must first prove that no typed handle,
provider handle, service-owned object, or in-flight operation still refers
to the extent. A physical page becomes `reusable` only after its VM-visible
object is no longer live; it leaves `committed` only when the Host backing is
actually released.

### 5. RRef payloads use logical memory accounting

Shared-heap RRef payloads use logical memory accounting. FrameV Sock uses an
internal Guest-domain RRef as its routing exchange carrier, but it does not
transfer the service packet's allocation: submit copies into the shared carrier
and receive copies back into service-private memory. That copied carrier has an
allocation size and Guest owner domain, so it is charged to the target VM even
though it is tracked by the shared heap rather than by a physical `FrameLease`.

Production FrameVisor installs an accounting adapter for the exchange layer.
When a payload owned by `DomainId::Guest(vm_id)` is registered while that VM
has a live registry entry, the adapter looks up the VM, reserves
`MemoryDomain::reserve_rref`, and commits the logical charge. Releasing the
payload calls `release_rref`. Host-owned RRefs are not charged to a Guest
domain, while a Guest-to-Guest ownership transfer charges the target domain
before updating metadata and releases the source charge only after the
transfer succeeds. The unregistered-Guest exception exists only for
synthetic registry tests; it is not a live FrameVM data path.

The exchange registry is intentionally only a global metadata index. It records RRef
IDs, payload sizes, owners, and borrow/reclaim state, but `FrameVm::memory()`
remains the accounting authority. A VM cannot be destroyed while
FrameVM-owned RRefs are still live; `destroy_vm` retains the VM identity until
those references drain. This prevents a late device packet or shared-heap
borrow from charging a removed or restarted VM.

### 6. OOM and reclaim

Domain OOM is a local allocation result, not a Host-wide failure. A failed
domain admission returns `NoMemory` to the caller and does not terminate the
VM or affect a sibling VM. The raw provider path performs a separate retry
only when Host OSTD cannot supply backing after domain admission has
succeeded: it drops that reservation, calls `reclaim_after_oom(vm_id)`, and
tries again. That helper clears empty heap pages for the VM and then asks the
ownership layer to reclaim one safe cached page.

The current cached-page candidate must satisfy all of these conditions:

- it is owned by a FrameVM;
- it is marked `cached` and is not `service_owned`;
- its hidden OSTD reference count is one;
- its `busy` count is zero; and
- its metadata identifies an untyped page.

The selected page is released through the ownership path, which removes the
cache charge and returns the physical extent to Host. A successful reclaim
increments `reclaim_count`. If no safe page exists, the allocation remains a
normal `NoMemory` failure. In particular, reclaim does not take pages from a
live typed service object, an in-flight device transfer, or a foreign VM.

### 7. Memory teardown and restart

Memory teardown is a closure protocol over the same domain, not a best-effort
sequence of frees. Its completion certificate is

```text
stopped(v)  =>  P_v = 0 ∧ R_v = 0 ∧ T_v = 0
```

The protocol first changes the domain to `Stopping`, which rejects every new
reservation; it then drains already-admitted work before unloading service
code or releasing backing that may still carry service metadata. A VM that
does not satisfy the certificate remains `Stopping`. This choice preserves
memory safety under delayed RRefs or leaked provider handles at the cost of
withholding restart progress until the owner is repaired or drains.

Memory teardown is coupled to execution, device, loader, and RRef teardown.
The current stop path is ordered as follows:

1. `request_stop` closes task admission and calls
   `MemoryDomain::begin_stopping`, so workers cannot start a new VM-owned
   backing allocation.
2. `finish_stop` waits for `reserved` transactions to commit or roll back,
   then starts CPU-local teardown and stops all devices.
3. IRQ and timer runtime state is cleared. The allocator is quiesced while
   the service image is still mapped, and service-owned provider handles are
   released before the image is unloaded; those handles may contain service
   vtables and metadata callbacks.
4. The service image is unloaded, assigned PCI is released or quarantined,
   and vCPU interrupt handler state is reset.
5. Quiesced VM-owned pages are released, then the Host-control
   `MemoryCharge` is dropped.
6. The VM becomes `Stopped` only when both `committed` and `reserved` are
   zero. Otherwise it remains `Stopping` and records the counters, including
   whether live VM RRefs remain.

The ordinary stop path leaves an empty domain in `Stopping` so a later start
can call `resume` and reopen it for a new execution. Destruction is
terminal for an already-stopped VM: after live FrameVM-owned RRefs are ruled
out, `destroy_vm` stops admission, waits for reservations, drops control
charges, closes the empty domain, and only then removes the VM from the
registry. A stale `Arc<FrameVm>` therefore cannot turn a destroyed identity
back into an accepting domain.

### 8. Memory status and observable behavior

The management ABI exposes `FRAMEVM_GET_MEMORY_STATUS`. Its
`FrameVmMemoryStatus` snapshot contains:

```text
limit_bytes       configured page-rounded limit
committed_bytes   physical plus logical committed bytes
reserved_bytes    in-flight allocation reservations
reusable_bytes    cached physical bytes available for reuse
active_bytes      committed bytes holding live VM state
oom_count         cumulative domain admission failures
reclaim_count     cumulative cached-page reclaims
```

The control file can return the configured limit before the `FrameVm` object
has been published; the other counters are then zero. Once a VM exists, the
values are read from `FrameVm::memory_stats()`. Runtime tests should set the
inner `-m` limit deliberately, create pressure from service heap/frame,
Host-control, and device-payload paths, and verify that a local OOM leaves
the Host and sibling FrameVMs alive. After stop and a subsequent start, the
same VM must show no stale ownership, leaked reservation, or double release.

## I/O virtualization: typed capabilities and asynchronous state

This section gives the I/O role in the overall FrameVM architecture. The
standalone [FrameV design](framev-design.md) is the detailed account of the
synthetic-device protocol and should be read before the mediated-passthrough
section below.

### I/O contract

FrameVM does not virtualize I/O by exposing a generic DMA ring or a Host
memory aperture. It separates a private PCI **control plane** from typed
FrameV **data planes**. The control plane permits discovery, configuration,
BAR layout, and virtual interrupt programming. The data plane consists of
family-specific calls and objects: borrowed block cursors for synchronous I/O,
owned Sock packets with an explicit service/Host copy boundary, and bounded
owned receive buffers for Net.

For a virtual function `f` owned by VM `v` and of family `k`, a FrameV Guest
call is admitted only when

```text
I_io(call, f):
  current_vm = v
  ∧ family(call) = k = family(f)
  ∧ runtime(f) = Running
  ∧ claim_id(call) = current_claim_id(f)
```

`FunctionClaim` carries the function runtime, a monotonically allocated claim
ID, and the current generation. Stop and reset revoke the current claim before
they drain in-flight calls. Consequently, a stale claim cannot become valid
merely because a later generation reuses the same BDF: its old claim ID is no
longer current. The `current_vm` check prevents an otherwise valid claim from
being replayed by a task in a different FrameVM.

An asynchronous **Host Event** has the complementary protocol: the FrameV
Host first publishes VM-owned state, then—only for a vector-bearing
function—raises a generation-tagged virtual interrupt. The interrupt conveys
readiness, not ownership of a payload. The FrameV Guest later consumes the
typed state through the same family-specific interface. This publication
ordering prevents a service task awakened by an interrupt from observing an
uninitialized queue entry or buffer reference.

The resulting device safety property is capability confinement: a malformed
or stale PCI address, claim, family, generation, or vector fails locally with
access denial or a rejected event; it cannot select a different FrameVM's
function or turn a synthetic BAR offset into arbitrary Host memory.

### 1. FrameV: split control and data planes

Every `FrameVm` owns a `Devices` value. The current structure contains a
console, Sock, RNG, zero or more block devices, an optional network device,
one private `VirtualPciBus`, and, on x86-64, optional assigned-PCI state.

The device model has four layers:

```text
Guest-visible control plane
    VirtualPciBus
        └── VirtualPciFunction: BDF, identity, config, BAR, MSI-X

Per-function authority
    FunctionRuntime
        └── function claim epoch, claim, active-call admission

Typed FrameV data plane
    Console / Rng / Block / Sock / Net FrameV Host components

Service adapter
    FrameVPciDriver
        └── FrameVConsole / FrameVRng / FrameVBlock /
            FrameVSock / FrameVNet
```

PCI is used for discovery, identity, configuration, BAR and interrupt
semantics. The data path is deliberately typed. Console and RNG use
synchronous direct calls; block uses typed read/write buffers; Sock moves
owned packet objects; and Net transfers owned receive buffers. There is no
universal simulated-DMA ring that every device must implement.

The following protocol separates what PCI decides from what a FrameV family
operation decides:

| Phase | FrameV control plane | FrameV data plane | Isolation consequence |
| --- | --- | --- | --- |
| Enumerate | The FrameV Guest scans only its `VirtualPciBus`, decodes vendor/device identity, validates BAR layout, and configures MSI-X only when advertised. | None. | A BDF establishes a local function identity, not Host-resource authority. |
| Claim | `claim_current_function` binds the current FrameVM context, BDF, and closed function family to one `FunctionClaim`. | None. | A foreign VM, BDF, family, stopped runtime, or second claimant is rejected before device state is reached. |
| Invoke | The claim admits the call through `FunctionRuntime`. | The family receives its own typed arguments: bytes, block cursors, a Sock packet, or an owned receive buffer. | Callers cannot smuggle a generic Host address, descriptor chain, or VM ID through a common payload format. |
| Notify | The bus validates MSI-X enablement, vector, mask/PBA state, target, and the function claim epoch. | The FrameV Host has already published family-owned state. | An interrupt is a wakeup for valid state, not a capability or payload transfer. |
| Revoke | Stop/reset clears claims and pending virtual delivery state. | Each family stops admission and drains or reclaims its retained values. | A BDF reused in a later function claim epoch does not revive an old call or event. |

This split keeps the FrameVM-facing interface kernel-shaped while allowing the
FrameV Host to use the resource type that actually owns the data. The
virtual PCI BAR is not a generic Host-memory window: for synthetic FrameV
functions, the meaningful mutable device state is the validated PCI
configuration, optional MSI-X state, and the typed FrameV operation itself.

### 2. Virtual PCI topology

`VirtualPciBus::new` constructs a private topology for one VM. It always
creates synthetic Console, RNG, and Sock functions. It adds one Block
function for each configured block image and adds Net when networking is
configured. An optional assigned physical function is attached through a
separate x86-64 path.

Each synthetic function has:

```text
VirtualPciFunction
├── bdf: VirtualPciBdf
├── stable_id: u64
├── runtime: Arc<FunctionRuntime>
├── config: [u32; CONFIG_DWORD_COUNT]
├── synthetic BAR bytes and BAR base
├── optional MSI-X capability/table/PBA state
└── per-vector delivery_pending state (empty for RNG and Block)
```

The bus allocates BDFs from the VM-local topology. Block functions retain a
stable ID so a block image keeps the same virtual identity within the
configuration. Queue-count fields that are supported by a function are
derived from the configured vCPU count. A Sock function also carries the
configured guest CID and queue identity.

The bus is the only authority for the synthetic PCI configuration space:

- `read32` and `write32` require an aligned configuration dword and resolve
  the BDF within this VM's bus;
- absent functions read as all ones, following PCI discovery convention;
- command-register writes are restricted to supported command bits;
- BAR relocation is validated against the function's supported BAR layout;
- MSI-X control and table writes update only the selected virtual function;
- BAR accesses use a VM/function-specific `VirtualBarHandle` and a checked
  range.

For synthetic functions, writable BAR subregions, where present, are limited
to MSI-X table state. Payload access is performed through the typed FrameV
operations. This prevents a guest from turning a synthetic BAR offset into an
arbitrary Host physical address.

### 3. Function runtime and claims

PCI configuration identifies a function, but it is not sufficient authority
to issue an I/O call. Each virtual function has a `FunctionRuntime`:

```text
FunctionRuntime
├── vm_id
├── virtual BDF
├── FrameV family
├── state: Stopped / Running / Stopping / Failed
├── current claim ID
├── current generation
└── active call count
```

The runtime is the admission and lifecycle authority for that function.
Its transitions are:

```text
Stopped --start--> Running(generation G)
Running --begin_stop--> Stopping
Stopping --active_calls = 0--> Stopped
```

Starting increments the generation and requires no active calls. A failed
generation counter overflow moves the runtime to `Failed`. While `Running`,
`claim` allocates a monotonically increasing claim ID and returns a
`FunctionClaim` containing the runtime, claim ID, and generation. Only one
claim is current for a function.

The service obtains a claim during `FrameVPciDriver::probe`:

1. decode the PCI identity into a FrameV family;
2. validate the function layout and configure MSI-X vectors when the function
   advertises them;
3. call `claim_current_function` using the current FrameVM PCI context;
4. store the claim in the typed FrameV frontend.

The claim cannot be redirected by passing a different VM ID or BDF to a
later data call. On entry, it checks the current `FrameVcpuId`, verifies the
VM and expected family, and asks the runtime to validate that the claim ID is
still current. Claim IDs are allocated within a running generation and
revoked at stop, which makes that current-ID check the generation fence for a
guest call. A FrameVisor-side wrapper uses the same runtime through the
explicit Host-entry path. Dropping a claim releases it.

This gives the service API the following shape:

```text
FrameV frontend
    -> FunctionClaim
        -> current FrameVM/vCPU context check
        -> FunctionRuntime::enter(claim_id)
        -> typed FrameV Host
        -> release_call
```

`enter` increments `active_calls`. `begin_stop` changes the state to
`Stopping`, so no new call can enter. `wait_until_stopped` waits for the
active count to reach zero and then completes the transition to `Stopped`.
`revoke_claims` additionally clears claims and pending MSI-X state during VM
reset or stop.

### 4. Device lifecycle

The `Devices` object keeps the lifecycle order for all FrameV families.

On every new VM start:

1. `reset_for_start` revokes old PCI claims and resets console, Sock, RNG,
   block, and Net state.
2. `mark_ready_all` starts each function runtime and the FrameV Host
   components.
3. Net starts its endpoint when configured.
4. Sock publishes the new function claim epoch after its queues are ready.
5. The service is allowed to probe and use the devices.

On stop:

1. the virtual bus revokes synthetic-function claims;
2. every function runtime closes admission;
3. `wait_until_stopped` drains calls that entered before the stop fence;
4. console, Sock, RNG, block, and Net backends stop;
5. queues, callbacks, and endpoint state are reset before a later function
   claim epoch.

On x86-64, `FrameVm::finish_stop` separately releases or quarantines the
physical PCI assignment after the service image is unloaded and before
quiesced VM-owned backing is released. It is not part of the synthetic
function claim-revocation loop.

The function claim epoch is the common stale-work fence. It covers claims,
Sock packets, Net receive buffers, and MSI-X deliveries. A restarted VM may
reuse the same BDF, but an old claim or event still carries the old epoch and
is rejected.

### 5. MSI-X and virtual interrupt delivery

Only Console, Sock, and Net currently advertise virtual MSI-X; RNG and Block
have zero virtual vectors. For a vector-bearing function, the guest first
programs the virtual MSI-X table and enables the function. A backend then
raises a family/vector pair for the current function claim epoch.

The raise path is:

```text
FrameV Host publishes queue/device state
        │
        ▼
VirtualPciBus::raise(family, vector, generation)
        │
        ├── verify current claim and generation
        ├── reject an invalid vector
        ├── coalesce an already-pending vector
        ├── set PBA state when masked
        └── validate the guest MSI-X address/data and Host IRQ line
        │
        ▼
MsixDelivery { BDF, vector, generation, IRQ line, target vCPU }
        │
        ▼
enqueue_virtual_irq(vm_id, target_vcpu, irq_line)
        │
        ▼
interrupt handler makes the vCPU runnable and the service frontend consumes the state
```

For a vector-bearing asynchronous event, state publication precedes the
MSI-X raise. The interrupt is therefore a notification that causes the interrupt handler
and service scheduler to run; it is not the owner of the payload. Sock
receive vectors target the corresponding vCPU queue. Other FrameV vectors
currently target vCPU zero unless the function's routing policy says
otherwise.

If the virtual IRQ enqueue fails, the bus rolls back the pending vector and
sets the pending-bit state again when the BDF and generation still match.
When the service handles the IRQ, `complete_irq` verifies the expected vCPU
and MSI-X message data before clearing the pending vector.

### 6. FrameV device data paths

The following table describes the current Host/service split.

| Device | Service frontend | Data and ownership contract | FrameV Host rule | Notification |
| --- | --- | --- | --- | --- |
| Console | `FrameVConsole` | Synchronous borrowed output bytes; bounded owned input state. | `Console` accepts writes and retains input only in the target VM's queue; each operation is at most 4096 bytes. | Input state is published before a virtual vector is raised. |
| RNG | `FrameVRng` | Synchronous mutable destination slice; no retained device payload. | `Rng` fills through the Host random source in chunks of at most 4096 bytes. | Request/response only; no generic device ring or MSI-X vector. |
| Block | `FrameVBlock` | Borrowed direction-typed `BlockSources` or `BlockDestinations`; no copied staging payload. | `Block` validates sector range and read-only state, and reads, writes, or flushes at most 32 extents. | Synchronous `read`, `write`, or `flush` returns status; Block has no MSI-X vector. |
| Sock | `FrameVSock` | Takes an owned `FrameVsockPacket`; service-to-Host and Host-to-service crossings copy through a FrameVisor-managed shared exchange carrier in the Guest domain. | `Sock` activates queues and routes by VM/CID/queue policy. A failed submit returns the original service packet. | Queue state is published before receive or completion vector delivery. |
| Net | `FrameVNet` | Borrowed validated TX frame; bounded owned RX buffer moved through a posted/recycled lifecycle. | `Net` uses a connected Unix datagram endpoint and validates Ethernet policy, MAC, and MTU. | RX buffers are published before MSI-X and recycled by generation. |

#### Console and RNG

The guest terminal and random APIs use the normal service subsystems. Their
FrameV frontends retain the PCI function claim and call the corresponding
claimed OSTD helper. The FrameV Host enters the function runtime and performs
the operation on the VM-owned console or Host random source. Input is
bounded and retained in per-VM state; it is never delivered through another
VM's console queue.

#### Block

The guest block frontend turns BIO operations into typed FrameV block calls:

```text
guest BIO
    -> FrameVBlock::read/write/flush
    -> FunctionClaim and sector validation
    -> direction-typed buffers, at most 32 extents
    -> Block FrameV Host
    -> captured image or assigned storage
```

The operation direction is encoded in the buffer view. A read cannot be
passed a write-only source view, and a write cannot be passed a destination
view intended for reads. The backend is responsible for completing an
accepted request once; stop prevents new admission and drains admitted
requests before the claim is revoked.

#### Sock

FrameV Sock is a packet transport rather than a universal byte-stream bridge.
It explicitly copies between the service's private heap and a FrameVisor-managed
shared exchange carrier allocated in the Guest domain: submit copies into that
carrier before routing, while receive copies back into service memory. A failed
submit returns the original owned `FrameVsockPacket`. Queue IDs, guest CID, VM
identity, and the current function claim epoch determine whether a packet can be submitted
or received.
The Sock runtime publishes queue state and then raises the virtual MSI-X
vector selected for the receiving vCPU. Reset closes the old function claim
epoch and does not reinterpret its packets in a new one.

#### Net

FrameV-net captures a connected Unix datagram endpoint as the Host backing.
The service sends frames through `FrameVNet::send` and posts owned receive
buffers through `post_receive_buffer`. The FrameV Host validates the Ethernet
frame, source/destination MAC policy, and MTU before transmission. RX uses a
bounded owned-buffer pool; the service either consumes or returns ownership
through the FrameV frontend.

The implementation does not copy every packet through a generic bridge
queue. Endpoint loss returns `NetworkEndpointError::Lost` and is logged; it
cannot cause the backend to silently switch to another endpoint, and buffers
from a revoked resource are not published after restart.

### 7. FrameV Guest-to-Host and FrameV Host-to-guest paths

The normal guest-to-Host path is synchronous and capability-based:

```text
guest syscall or kernel subsystem
    -> normal service API
    -> FrameV frontend
    -> claimed virtual PCI function
    -> OSTD claimed helper
    -> FunctionRuntime admission
    -> typed FrameV Host
    -> Host resource
```

The asynchronous Host-to-guest path has a different order:

```text
Host resource event
    -> update VM-owned device state
    -> publish queue/buffer/event state
    -> if the function has a vector: raise virtual MSI-X for the current generation
    -> interrupt handler virtual interrupt handling
    -> FrameVM service scheduler
    -> FrameV frontend consumes or recycles the payload
```

Keeping these paths separate matters. A virtual interrupt is not a data
ownership transfer by itself, and a guest-provided BDF is not a Host-device
capability. The claim and runtime checks are performed at the call boundary;
the payload path then uses the already-validated typed owner.

### 8. Mediated PCI passthrough: native-driver reuse without raw authority

The standalone [NVMe mediated-passthrough design](nvme-passthrough-design.md)
gives the detailed current protocol for this path.

An assigned physical PCI function is not synthesized like Console, RNG,
Sock, Block, or Net. The service can bind an eligible **native driver**—the
current assigned path validates an NVMe function—rather than a FrameV
frontend. Thus the service reuses the device's normal PCI configuration,
register, queue, and driver protocol. It does **not** receive unmediated
physical-MMIO, DMA, or interrupt authority.

The design is deliberately *mediated passthrough*. FrameVisor retains an
`AssignedPciDevice` containing the exclusive requester group, an isolated
`PciDmaDomain`, and generation-scoped `AssignedPciAccess`. The access object
is the authority to physical config space and BAR capabilities; the service
receives only a virtual BDF and constrained virtual BAR ranges.

#### Assignment protocol

```text
control plane reserves one physical requester group
        -> FrameVisor validates the physical function
        -> snapshots config, requires FLR and supported BARs
        -> creates requester-scoped DMA domain
        -> claims the requester group under VM assignment identity
        -> attaches AssignedPciFunction to the VM-private PCI topology
        -> native service driver enumerates the assigned PCI identity
```

The validation is a security boundary, not a convenience check. The current
implementation accepts only an NVMe-class function; requires bus mastering,
memory-space, and I/O-space decoding to be disabled before assignment; and
rejects enabled ATS, PRI, or PASID translation features. It snapshots the
physical configuration, requires Function-Level Reset (FLR), and acquires
only valid memory BAR capabilities. A request that fails any validation has
no guest-visible assigned function.

The assigned function is attached while `FrameVm` is constructed on x86-64,
not at `START`. Topology allocation gives it a BDF private to that VM even
though its configuration identity identifies the physical device. This makes
ordinary PCI enumeration possible without making the physical BDF a
cross-VM capability.

#### Register, DMA, and interrupt mediation

The service sees a synthesized BAR placement inside the assigned MMIO window,
not the physical BAR address. `AssignedPciFunction` translates only a checked
subrange of that virtual BAR into an acquired physical BAR capability. Every
read or write revalidates the current FrameVM, access width, alignment, and
range before `AssignedPciAccess` performs the physical operation. Configuration
writes are also narrow: the command register admits only selected command
bits, and MSI-X updates are limited to the discovered MSI-X control offset.
Other physical configuration state is not a service-writable control surface.

DMA isolation is not delegated to the native driver. FrameVisor creates the
requester-scoped `PciDmaDomain`; the platform IOMMU maps and revokes DMA
translations for that requester. Similarly, physical interrupt routing is
created only through `AssignedPciAccess`: it checks the assignment identity,
allocates a Host IRQ/remapping route, tags the callback with the VM and
generation, and enqueues the resulting physical interrupt into that VM's interrupt handler
path. In the current route implementation, assigned physical IRQs target
vCPU zero; this is an implementation policy, not a general PCI property.

#### Revocation protocol

Passthrough teardown must make reuse safe for both the next VM and the Host:

```text
close AssignedPciAccess admission
        -> wait for active BAR/config/IRQ operations to drain
        -> close IRQ routes and drop acquired BAR capabilities
        -> begin requester revocation
        -> perform and verify function-level reset
        -> invalidate requester DMA translations by dropping the DMA domain
        -> finish revocation and return the group to the assignable pool
```

If admission cannot be cleanly revoked, FLR fails, or the post-reset device
cannot be refreshed, FrameVisor quarantines the requester group rather than
assigning uncertain hardware state to another VM. This is why passthrough
teardown happens before the remaining VM-owned memory is released: live
service code must never retain a capability to a function whose DMA domain or
BAR authority has already been revoked.

#### FrameV versus mediated passthrough

| Dimension | FrameV synthetic device | Mediated PCI passthrough |
| --- | --- | --- |
| Guest-visible function | FrameVisor-created FrameV PCI identity. | A VM-private BDF carrying the assigned device's PCI identity. |
| Service driver | FrameV frontend that holds a `FunctionClaim`. | Eligible native PCI driver, currently the NVMe path. |
| Data path | Family-typed direct call, borrowed cursor, explicit Sock packet copy, or owned receive buffer. | Native driver register/queue protocol over checked BAR operations and the assigned DMA domain. |
| Data-plane authority | `FunctionClaim` plus current FrameVM/vCPU context. | `AssignedPciAccess`, requester-scoped DMA domain, and assigned IRQ routes retained by FrameVisor. |
| Interrupt semantics | Virtual MSI-X is a readiness notification for FrameV-owned state. | Physical IRQ is remapped and generation-tagged before it enters FrameVM interrupt handler. |
| Reuse boundary | Revoke claims and reset family-owned state at generation change. | Drain access, reset hardware, invalidate DMA, then release or quarantine the requester group. |

The two branches share the lifecycle principle—authority is VM-scoped,
generation-aware, and revoked before reuse—but they intentionally do not
share a payload protocol. FrameV is a project-native paravirtual API; PCI
passthrough preserves a native hardware-driver contract behind FrameVisor's
resource custody boundary.

## End-to-end virtualization sequence

The complete path from a running vCPU forks at PCI function identity. The
synthetic FrameV path and mediated-passthrough path deliberately share only
the scheduling, lifecycle, and ownership boundary:

```text
Host outer scheduler
    -> selects FrameSchedGroup(vCPU i)
        -> FrameVM inner scheduler selects interrupt handler or Service task
            -> task runs with current FrameVcpuId(vm, i)
                -> PCI function identity
                    -> synthetic FrameV function
                        -> FrameV frontend enters FunctionClaim
                        -> FunctionRuntime validates VM/family/current claim
                        -> typed FrameV Host accesses its resource
                        -> synchronous result, or published state + virtual MSI-X/interrupt handler
                    -> assigned physical PCI function
                        -> native driver accesses virtual assigned BAR
                        -> AssignedPciAccess revalidates VM/range/operation
                        -> physical device via requester-scoped DMA/IRQ authority
                        -> remapped generation-tagged physical IRQ enters interrupt handler
```

The memory path crosses the same boundary before the service can use an
object:

```text
service frame/heap/RRef request
    -> FrameVmAllocator or the RRef accounting adapter
    -> MemoryDomain reservation
    -> Host backing or shared-heap registration
    -> OwnerRecord / RRef owner metadata
    -> service-visible typed object
```

The virtualization boundary is therefore distributed, but each ownership
decision is singular: `FrameVm` owns the VM state and memory domain,
`FrameSchedGroup` owns the vCPU scheduling entity, `OwnerRecord` owns the
physical extent decision, and `FunctionRuntime` owns the admission of each
virtual function. No global map is allowed to become an implicit owner.

## Lifecycle and isolation invariants

The relevant lifecycle is:

```text
Created -> Starting -> Running -> Stopping -> Stopped -> Destroyed
```

The implementation is structured to enforce these invariants:

- A FrameVM has one aggregate kernel `TaskGroup` and one
  `FrameSchedGroup` per vCPU.
- The Host outer scheduler schedules groups; the FrameVM scheduler schedules
  service tasks inside a selected group.
- Every live FrameVM physical allocation path, and every registered RRef
  owned by a live Guest domain, is admitted by that VM's `MemoryDomain`; the
  outer QEMU memory size is not the FrameVM limit.
- `reserved` bytes are transactional and cannot be left behind after a
  completed start, stop, or failed allocation.
- A physical frame has at most one `OwnerRecord`, and its release checks the
  VM, domain identity, metadata state, busy count, and provider/service flags.
- Reusable physical pages remain charged until the backing is scrubbed and
  returned to Host; they are not counted as active VM state while cached.
- A live Guest-owned `RRef` payload remains charged while its metadata is
  registered. Ownership transfer is rejected while it is borrowed, and VM
  destruction rejects remaining VM-owned RRefs.
- A task's VM and bound vCPU are checked together.
- A virtual PCI function is private to one `VirtualPciBus` and one VM.
- A `FunctionClaim` cannot be used by a foreign VM, family, claim ID, or
  function claim epoch.
- A FrameV synthetic function and an assigned physical function use distinct
  data-plane contracts; a PCI BDF alone is authority for neither contract.
- An assigned PCI BAR is exposed only through a VM-bound, range-checked
  `AssignedPciAccess`; physical BAR addresses and raw requester DMA authority
  are never service-visible capabilities.
- A vector-bearing device publishes its state before raising its MSI-X
  notification.
- Stop closes admission before draining calls and destroying execution.
- Virtual IRQs, queues, endpoint state, and physical-device routes are
  revoked or quarantined before a new generation is allowed to run.
- Host spinlocks are not held across blocking, I/O, service execution, or
  synchronous task wakeup.

These invariants are the reason FrameVM can reuse ordinary Asterinas
subsystems in the service without exposing the Host's global task, memory,
PCI, or network state.

## Evidence and falsification obligations

The implementation map below identifies the code that enforces each
mechanism; it is not a substitute for a runtime proof. A paper-quality claim
must name the observation that would falsify it.

| Claim | Required observation | Falsifying outcome |
| --- | --- | --- |
| Memory confinement | Drive service heap, frame/segment, Host-control, RRef, and device-buffer paths under an explicit inner `-m` limit; inspect `FRAMEVM_GET_MEMORY_STATUS`. | A successful allocation exceeds `L_v`, a local OOM aborts the Host or a sibling VM, or stop leaves permanent reservations. |
| Exclusive custody | Create, release, reuse, and tear down physical extents across repeated VM lifecycles. | Duplicate owner adoption, cross-domain release, stale contents after reuse, or a double release. |
| Execution attribution | Exercise affinity changes, multiple vCPUs, restart, and concurrent interrupt handler/service work. | A task runs with a foreign VM/vCPU binding or a stale task binding. |
| I/O authority confinement | Reuse BDFs across restart; submit stale claims, invalid families, invalid vectors, and cross-VM calls. | A stale or foreign operation reaches a FrameV Host resource. |
| Mediated PCI passthrough | Reserve an eligible function, complete native driver I/O, force or orderly stop, then immediately attempt a second assignment. | A service can use an unchecked BAR/DMA capability, a stale physical IRQ reaches a later assignment, or the requester is reused without reset/revocation. |
| Teardown progress | Repeatedly create, start, stop, and destroy while retaining/dropping RRefs and device work at controlled points. | `Stopped` is published before counters drain, or a later VM observes stale resource state. |

The current test framework deliberately distinguishes these runtime outcomes
from a build or service-architecture check: a successful artifact build is
evidence only for packaging and static contracts. It does not establish a
clean FrameVM lifecycle, Host health, or the conditional progress claims
above. Conversely, a runtime failure is a counterexample or an environment
blocker to investigate, not evidence that a marker printed by the service
completed teardown.

## Implementation map

| Area | Main location | Responsibility |
| --- | --- | --- |
| Host `TaskGroup` | `kernel/src/sched/sched_class/task_group.rs` | Hierarchical fair attributes, per-CPU fair queues, and tick accounting. |
| FrameVM group creation | `kernel/src/vmm/mod.rs` and `kernel/src/sched/sched_class/` | Converts the configured share, creates the parent-linked group, and registers vCPU groups. |
| Outer group scheduler | `kernel/src/sched/sched_class/frame_group.rs` and `kernel/src/sched/sched_class/` | CPU placement, outer runqueue entities, affinity updates, and group picking. |
| vCPU group | `kernel/comps/framevisor/src/vm/frame_group.rs` | `FrameSchedGroup`, `RunState`, interrupt handler/service arbitration, and service-task wake tracking. |
| vCPU and task binding | `kernel/comps/framevisor/src/vm/vcpu.rs` and `kernel/comps/framevisor/src/task/frame_task.rs` | `Vcpu`, `FrameTaskData`, task kinds, VM/vCPU binding, and rebinding. |
| Inner service scheduler | `kernel/comps/framevisor/src/task/scheduler/` | Per-vCPU service runqueues and service-task enqueue/pick operations. |
| VM lifecycle | `kernel/comps/framevisor/src/vm/mod.rs` | `FrameVm` state transitions, interrupt-handler startup, memory admission, service-image ordering, and resource rollback. |
| Memory domain | `kernel/comps/framevisor/src/vm/memory.rs` | Page-granular limit, reservation transactions, Host charges, reusable bytes, RRef charges, and stop/close state. |
| Provider bridge | `kernel/comps/framevisor/src/mm/provider.rs` | Frame/segment/heap providers, service-owned allocations, custom-provider grants, provider faults, and OOM reclaim. |
| Physical ownership | `kernel/comps/framevisor/src/mm/ownership.rs` | `OwnerRecord`, `FrameLease`, domain checks, cached-page release, and quiesced VM teardown. |
| Shared payload accounting | `kernel/comps/framevisor/src/rref_registry.rs` | Guest-owned RRef reservation, release, transfer, reclaim metadata, and live-reference checks. |
| Memory status ABI | `kernel/libs/framevm-abi/src/lib.rs` and `kernel/src/device/misc/framevm/` | `FRAMEVM_GET_MEMORY_STATUS`, page-aligned creation limits, and management snapshots. |
| Device collection | `kernel/comps/framevisor/src/device/mod.rs` | FrameVisor-owned Console, RNG, Block, Sock, Net, and assigned-PCI resources. |
| Mediated PCI passthrough | `kernel/comps/framevisor/src/assigned_pci.rs` | Assignment validation, physical config/BAR access authority, requester DMA domain, IRQ routes, reset, revocation, and quarantine. |
| Virtual PCI | `kernel/comps/framevisor/src/pci.rs` | Private topology, BDF/config/BAR state, claims, MSI-X, and virtual IRQ delivery. |
| Function admission | `kernel/comps/framevisor/src/device/state.rs` | `FunctionRuntime`, `FunctionClaim`, generations, active calls, and stop draining. |
| FrameV service driver | `services/aster-framevm/comps/framev-pci/` | PCI probing, MSI-X setup, claims, and typed frontend handles. |
| FrameV frontends | `services/aster-framevm/comps/framev-{blk,console,net,rng,sock}/` | Adapt normal service APIs to claimed FrameV operations. |
| FrameV ABI | `kernel/comps/framev-{blk,console,net,pci,rng,sock}/` | Device identities, configuration, payloads, and completion/status types. |

For the FrameVM control transaction and artifact-loading boundary, see
[FrameVM Control Device](framevm.md). The executable test ownership
inventory is maintained in
`test/initramfs/src/framevm/README.md` in the repository.
