# NVMe Mediated Passthrough: Assignment and I/O Protocol

FrameVM can assign one physical NVMe PCI function to one FrameVM on x86-64.
The FrameVM service reuses the ordinary PCI/NVMe driver: it programs native
controller registers, creates native submission and completion queues, rings
native doorbells, and handles native NVMe completions.

This is **mediated passthrough**, not raw device ownership. FrameVisor keeps
the authority that could affect the Host or another FrameVM: physical PCI
custody, physical BAR access, IOMMU mappings, MSI-X routes, reset, and device
reuse.

## 1. What is passed through

| Passed to the service | Mediated by FrameVisor | Never exposed to the service |
| --- | --- | --- |
| The native NVMe programming model. | Virtual BDF and BAR placement. | Physical BDF and physical BAR base. |
| The existing `NvmePciDriver`. | Checked physical MMIO access. | Arbitrary physical MMIO. |
| Native NVMe queues and doorbells. | Requester-scoped IOMMU DMA mappings. | Host-wide DMA addresses or mappings. |
| Native MSI-X completion behavior. | Physical IRQ route validation and delivery. | Arbitrary Host IRQ binding. |

The service therefore sees enough of an NVMe controller to reuse the normal
driver, but it never receives a raw capability for the Host PCI topology,
Host memory, or the physical requester.

## 2. Atomic stages

An atomic stage is a protocol commitment point, not a non-preemptible CPU
instruction. A successful stage publishes the result used by the next stage.
A failed stage does not give the next stage access to the device.

~~~text
physical NVMe function
    -> 1. reserve and validate
    -> 2. reset and commit assignment
    -> 3. present a VM-local PCI function
    -> 4. run native MMIO, DMA, and MSI-X I/O
    -> 5. contain an assigned-device fault, if any
    -> 6. revoke, reset, and release or quarantine
~~~

Stages 1–3 and 6 are the assignment control plane. Stage 4 is the native NVMe
data plane. Stage 5 is the fault path.

## 3. Stage 1: reserve and validate

**Input.** A FrameVM creation request names one physical PCI segment and BDF.

**Action.** The Host PCI subsystem exclusively reserves the requester group
that contains the function. The current creation ABI rejects more than one
assignment request. FrameVisor validates that the reserved function is an NVMe
controller and is safe to prepare.

**Checks.** The current path requires an NVMe class function, disabled memory
decoding and bus mastering before assignment, a memory BAR, MSI-X, and
Function-Level Reset (FLR). It rejects unsupported active translation features
such as ATS, PRI, and PASID.

**Committed result.** The Host holds one exclusive `ReservedPciGroup`. The
FrameVM service cannot yet enumerate or access the controller.

**Failure result.** The request fails before a virtual function, DMA domain,
or service driver endpoint exists.

**Why it matters.** Exclusive reservation prevents two FrameVMs from
programming the same PCI requester. Disabled pre-assignment state prevents
FrameVisor from inheriting a controller that is already issuing DMA or MMIO
transactions.

## 4. Stage 2: reset and commit assignment

**Input.** An exclusive, validated requester group and the target FrameVM ID.

**Action.** FrameVisor prepares the function through `AssignedPciAccess`: it
captures the configuration needed for the assignment, performs FLR, refreshes
the Host PCI view, and validates the function again. It then creates:

- a `PciAssignmentIdentity` for this FrameVM and assignment generation;
- `AssignedPciAccess`, the generation-scoped authority for physical
  configuration, BAR, and IRQ-route operations; and
- `PciDmaDomain`, an IOMMU domain bound to the physical PCI requester.

**Committed result.** The requester group is marked assigned only after both
the access capability and its requester-scoped DMA domain exist.

**Failure result.** No partially assigned controller is presented to the
service. The reserved group remains under Host control.

**Why it matters.** A device is never “assigned” without a DMA boundary. The
assignment identity ties later MMIO access, IRQ delivery, faults, and revocation
to one owner and one lifetime.

## 5. Stage 3: present a VM-local NVMe function

**Input.** One committed physical assignment.

**Action.** FrameVisor inserts an `AssignedPciFunction` into the target VM’s
private PCI bus. It gives the function a VM-local BDF and virtual BAR ranges.
The configuration image retains the identity and capabilities required by a
native driver, but rewrites BAR placement and restricts configuration writes.

**Committed result.** The existing service-side `NvmePciDriver` discovers the
function through its ordinary PCI-bus registration and initializes it as an
NVMe controller.

**Failure result.** If presentation cannot be constructed, the controller has
not entered the service’s PCI topology and the assignment is released through
the normal revocation path.

**Key distinction.** The driver sees a conventional NVMe PCI device, not a
FrameV device. It does not issue FrameV block operations or use a FrameV
request format. The BDF and BAR it sees are VM-local handles rather than
physical addresses.

## 6. Stage 4: execute native NVMe I/O

After initialization, the service runs the normal NVMe protocol. FrameVisor
does not translate NVMe commands into a software queue. It mediates the three
ways in which that native protocol crosses the FrameVM boundary.

### 6.1 MMIO path: controller registers and doorbells

~~~text
native NVMe driver register access
    -> VM-local BAR handle
    -> validate BAR index, offset, width, and range
    -> enter AssignedPciAccess
    -> physical controller register or doorbell
~~~

The virtual BAR handle identifies one assigned BAR and a bounded subrange.
FrameVisor rejects an unsupported access width, misalignment, arithmetic
overflow, or an access beyond that subrange. `AssignedPciAccess` admits the
physical access only while the assignment is accepting operations.

**Result.** The driver can use the controller’s native register interface, but
cannot retain a general physical MMIO mapping or access another BAR.

### 6.2 DMA path: queue memory and data buffers

~~~text
service NVMe queue or data segment
    -> PciDmaDomain::map
    -> allocate one device-address range
    -> IOMMU maps those pages for this physical requester
    -> PciDmaSegment retained by the NVMe operation
    -> NVMe PRP or SGL contains that device address
~~~

`PciDmaDomain` accepts only a non-empty, page-aligned segment. It returns a
`PciDmaSegment`, which owns both the source segment and the device-address
mapping. Dropping that mapping invalidates the translation and releases the
device-address range.

**Result.** The controller can DMA only to service pages that have a live
mapping in this requester’s IOMMU domain. Owning the NVMe controller does not
authorize DMA to arbitrary Host memory.

### 6.3 Completion path: native MSI-X

~~~text
physical NVMe MSI-X
    -> route bound to the assigned requester
    -> FrameVisor validates the assignment identity
    -> enqueue virtual interrupt for the owning FrameVM generation
    -> FrameVM interrupt handling schedules the native NVMe driver
    -> driver reads native completion queue
~~~

The MSI-X interrupt is a completion wakeup, not the completion payload. The
driver still consumes its native completion queue. A route is accepted only
for the physical requester of this assignment, and delivery is tagged with the
owner and assignment generation.

**Result.** A foreign requester cannot wake this FrameVM, and an old assignment
route cannot signal a later owner of reused hardware.

## 7. Stage 5: contain a device or IOMMU fault

**Input.** An assigned-PCI fault carrying the assignment identity.

**Action.** FrameVisor resolves the identity to its owning FrameVM and stops
that VM for assigned-device failure. It reports the failure to the lifecycle
owner; if the report cannot be accepted, it destroys the FrameVM.

**Committed result.** The fault is treated as a FrameVM-local containment
event. The controller does not continue under uncertain ownership.

**Why it matters.** A device fault is not merely an I/O error returned to one
NVMe command. It may indicate that the hardware, DMA mapping, or ownership
boundary can no longer be trusted.

## 8. Stage 6: revoke, reset, and release

**Input.** Normal FrameVM stop or assigned-device fault containment.

**Action.** Release follows this order:

~~~text
close AssignedPciAccess admission
    -> wait for already admitted config, BAR, and route operations
    -> close IRQ routes and release physical BAR capabilities
    -> begin requester-group revocation
    -> FLR and refresh the physical PCI function
    -> drop PciDmaDomain: deny all and invalidate translations
    -> finish revocation and return the group to the reservation subsystem
~~~

**Committed result.** After successful revocation, a later FrameVM can reserve
the requester group as a new assignment.

**Failure result.** If revocation cannot begin, reset fails, or post-reset
refresh fails, FrameVisor drops the DMA domain and quarantines the group. It is
not reassigned merely because the old VM stopped.

**Why this order matters.** Closing access first prevents new service MMIO
operations. Draining existing operations prevents them from racing released
BAR capabilities. Resetting the requester before dropping its DMA domain
ensures that a still-active controller cannot issue DMA after translations
have been removed.

## 9. Protocol invariants

1. **One requester group has one owner.** Reservation is exclusive.
2. **One assignment has one DMA domain.** Every device address belongs to the
   physical requester and a live `PciDmaSegment`.
3. **VM-visible addresses are virtual.** The service BDF and BAR do not expose
   physical PCI topology or physical BAR bases.
4. **Native NVMe semantics are preserved.** The existing driver uses native
   registers, queues, doorbells, and completion queues.
5. **Every escape to physical hardware is mediated.** MMIO, DMA, and IRQ
   routes are checked by FrameVisor.
6. **Revocation precedes reuse.** Access closes, the requester resets, DMA is
   denied, and failure quarantines rather than reassigns unsafe hardware.

## 10. Relation to FrameV

FrameV is a typed paravirtual interface for project-defined virtual devices.
NVMe passthrough is different: it preserves the native hardware-driver
interface while virtualizing and mediating the physical resources beneath it.

Both designs share the same safety principle: an operation receives only
VM-scoped authority, and that authority is revoked before its resources can be
reused. For the FrameV protocol itself, see
[FrameV Protocol: Atomic Interface Stages](framev-design.md).
