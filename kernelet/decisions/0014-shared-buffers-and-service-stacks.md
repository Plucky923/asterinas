<!-- SPDX-License-Identifier: MPL-2.0 -->

# Shared buffer grants and service stack selection

This implementation follows [book PR #11](https://github.com/tatetian/kernelet-book/pull/11)
at `cab56658fdea000ead358301633250f60f58779d` and
[book PR #9](https://github.com/tatetian/kernelet-book/pull/9)
at `e1b0073eae1019c6e26f794334680bf7c24728cd`.
It implements shared-buffer block and inter-instance datagram devices on Asterinas.
Startup selection also connects ordinary filesystem and socket operations to borrowed block and shared Ethernet backends.
The integration boundaries and validation limits are listed below.

## Buffer ownership

For shared-buffer devices and shared Ethernet, Host OSTD owns initialized DMA allocations outside tenant memory grants.
Each allocation has one issued grant, active grant, or backend operation.
A token contains an allocation identity and a nonwrapping generation.
Allocation identities are never reused.
Transfer, submission, and return advance the generation.
Submission reserves the return generation before acceptance.

The registry keeps the allocation's node through these transitions.
Completion and return do not allocate another registry node.
Each participant has at most 64 allocated buffers and 16 MiB of retained payload storage.
Import credit separately limits retained buffer count and capacity to the same bounds.
A buffer holds at most 1 MiB; allocation rounds capacity to a page and zeroes it.
Each allocation also reserves one page for bounded grant, operation, and registry metadata.

`ReadBuffer` exposes a reader.
`ReadWriteBuffer` also exposes a writer through an exclusive borrow.
Neither type exposes a frame, mapping operation, backing handle, identifier constructor, or owning clone.
Handoff and submission consume the wrapper; rejection returns that wrapper.
These accessors operate locally after the Host activates a grant exactly once.

The Host authorizes connections through `Kernelet::connect_shared_buffers`.
`SHARED_BUFFER_CONNECT` requires capabilities for both running sandboxes and returns their connection identities.
The runtime exposes this operation through `shared-buffer-connect local peer` and private holder sockets.
Repeated authorization returns the existing connection without consuming another peer slot.
Dead peer records without pending deliveries no longer consume connection credit.
Images enumerate those connections and transfer original allocations through the buffer service.
Preallocated delivery storage and import credit bound pending grants.
Polling delivery does not consume the grant; successful redemption removes its delivery entry.
Concurrent redemption cannot create a second wrapper.

`BackendBuffer` holds an accepted operation.
BIO views and callbacks retain an `Arc<BackendBuffer>`.
The block submission hook places accepted buffers into a bounded device queue.
An adopted Host worker submits physical BIOs with IRQs and preemption enabled, so queue-lock contention can sleep.
Each worker participates in the instance's scheduling share and Host memory reservation.
Recording completion does not return access.
The last backend hold synchronizes DMA and publishes completion.
Polling then creates a fresh return grant.
Cancellation retains storage while access remains possible.
Dropping a pending request requests cancellation and discards its result after backend holds drain.

Sender accounting and the endovisor's endpoint reservation remain attached to the allocation.
The endpoint reservation belongs to the UID and survives sender destruction until the allocation's final owner releases it.
They survive sender exit while a recipient or backend holds storage.
Marking an instance dying closes admission.
Reaping ends its local grants only after its carriers retire.
Other participants' grants survive.
Backend holds drain without executing image destructors.

## Transparent device selection

Applications retain the ordinary Linux file, mapping, TCP, and UDP interfaces.
The runtime selects device backends before `START` through `org.asterinas.kernelet.io-devices`:

```json
{"block":"borrowed","network":"shared","blockBackings":["/dev/vdb"]}
```

The OCI annotation contains this object encoded as a JSON string.
Both fields default to `copy` and can be selected independently.
Shared networking requires an enabled runtime network configuration.
Native builds and existing copying devices remain available.
The explicit `ZERO_COPY_BLOCK` and inter-instance datagram interfaces retain their independent device namespaces.

### Borrowed Image DMA pages

`BORROWED_BLOCK` retains the existing Image VirtIO frontend, descriptor ring, page cache, and filesystem interfaces.
Its Host backend borrows the Image's already registered DMA pages instead of staging their payloads.
`GuestDmaLease` validates the range and registration and retains a `MemoryPin` through every physical BIO hold and callback.
The restricted BIO segment exposes a device address and synchronization operations, without a Host CPU payload accessor.
Each submitted segment checks that its DMA address equals the original Image descriptor address.
No duplicate `prepare_dma`, fabricated owning segment, or second DMA mapping is created.

This path reuses the existing Image-page lending protocol.
It has a different ownership contract from the exclusive Host-pool grants above.
Image byte access follows the native untyped-memory and page-cache synchronization rules;
the lease prevents retirement or reuse of the allocation while physical DMA can access it.
Scatter/gather submissions respect the physical driver's segment limit.
Partial submission failure drains all accepted BIOs before reporting failure.
Cancellation and reset cannot release their leases while a driver hold remains.
Flush requests retain the existing backing-device synchronization path.

The initial backend requires coherent x86-64, a non-confidential VM, disabled IOMMU DMA remapping,
and a whole-device VirtIO block driver.
ATTACH checks these conditions, and START checks the retained backing again.
Unsupported environments, regular files, partitions, and other block drivers fail with `EOPNOTSUPP`;
a borrowed attachment never selects the copying backend after failure.

Borrowed runtime mode requires explicit absolute `blockBackings`, ordered root first and then directory binds in OCI mount order.
Their count must match the generated root and bind-image count.
The caller prepares the corresponding filesystems, including the agent in the root backing.
The runtime does not populate those devices from its generated regular-file images.
Its immutable backing and tmpfs-overlay policy remains unchanged.
A control client may configure a writable borrowed backing independently of that OCI policy.

### Shared Ethernet storage

`SHARED_NET` attaches a separate Ethernet backend to the existing Host network endpoint and NAT worker.
The Image backend implements the normal `AnyNetworkDevice` interface and supplies shared packet storage to `aster-bigtcp`.
Ordinary socket operations allocate and parse packets through the existing packet interfaces.
Exclusive grants carry those allocations across the Host/Image boundary without payload staging copies.
Preallocated pools, import credit, and return notifications bound storage and recycle consumed buffers.
The private Host/Image connection is not exposed as an inter-instance datagram device.

The Host validates frame metadata before parsing the owned payload.
Grant holds preserve active byte borrows during close, and successful handoff consumes the sender's accessor.
Compatibility conversions from native packet storage increment separate payload-copy counters.
TCP stream buffers, application transfers, native Host sockets, and physical NIC drivers retain their own copying behavior.
The zero-copy claim covers the selected Host/Image payload boundary, not the complete TCP/IP path.

`IO_PATH_STATS` aggregates Host-owned device counters for running and exited instances.
It reports borrowed block submissions and original DMA address checks, shared network traffic and reuse,
and boundary or compatibility payload-copy counts.
These counters support path checks; they do not measure latency, throughput, or every system copy.

## Stack selection and entry

Each ordinary service has an assembly-defined, read-only budget initialized to `HOST_STACK`.
The stub validates the Host-owned live stack slot before its first push or call.
It compares remaining space with the budget and selects the carrier stack when admission fails.
Stack selection preserves the active page-table reservation.
Schedulable services use the existing root protocol.
Rust cleanup finishes before the assembly tail resumes Image execution.

OSDK retains LLVM `.stack_sizes` and analyzes the final linked Host instructions.
The analyzer counts simultaneous frames through finite direct-call paths and audited assembly entry and return tails.
It rejects missing metadata, unsupported instructions, unresolved control flow, recursion, cycles, and unproved stack adjustments.
Instruction widths, register writes, stack-derived addresses, return-address storage, and call clobbers constrain admission.
The analysis relies on trusted Host Rust code and compiler frame metadata; it does not verify arbitrary inline assembly or pointer validity.

The same-tick, non-scheduling `vcpu_on_spin` branch has an independently audited return tail.
An unsuccessful fast admission switches to the carrier stack before the ordinary implementation runs.
Remote stop also switches to the carrier stack before cleanup.
All other service paths retain `HOST_STACK` until they have an audited non-scheduling boundary and a proved bound.
The current optimized test build derives 406 bytes: 24 bytes of service use and 382 bytes of entry allowance.
The entry allowance covers hardware and assembly frames, alignment, and permitted nesting before a safe-stack handoff.

OSDK writes a separate packaging ELF and changes only reserved eight-byte budget cells.
It verifies every other byte, preserving code, addresses, section sizes, and the original Cargo artifact.
The final audit recomputes the bound from the packaged ELF and checks every published value.
A `*.stack-budgets.json` sidecar records numerical bounds and fallback reasons.
These checks establish stack admission conditions; they do not establish a service-call speedup.

For physical IRQs on Image stacks, assembly switches to a guarded per-CPU stack before calling Rust.
IRQ stacks retain the native Task stack capacity.
Nested entries preserve the current pointer and outer occupancy.
The outer entry clears occupancy only after leaving the IRQ stack.
Scheduling remains deferred to the existing Image return redirection.
Non-IST exceptions switch to the carrier stack; double fault retains its independent IST.
An attributed double fault leaves its bounded IST precheck for the carrier stack before callbacks or termination bookkeeping.

Guard-overflow attribution requires the fault address and interrupted stack pointer to identify the same live guard slot.
Invalid Image stack pointers retain their separate depth-zero containment path and report `StackReserve`.
An unattributed double fault retains normal Host fault handling.
Recovery snapshots APIC ISR state before acknowledgment and completes one attributable fixed-delivery IRQ through normal callbacks and EOI ordering.
Multiple in-service vectors are not attributed to an abandoned entry prefix.
Carrier entry requires native task context and an empty ISR before Image execution starts.
Existing function-entry reserve checks and stack probes remain enabled.

## Integration and validation limits

The shared-buffer API and an independent `ZeroCopyBlock` device are implemented.
`ATTACH` with `ZERO_COPY_BLOCK` creates an entry in a separate device namespace.
The userspace `attach_zero_copy_block` method configures this attachment before start.
It does not allocate a VirtIO MMIO slot or change an existing `BLOCK` attachment.
Images discover these devices through `ZeroCopyBlock::open` and submit owning buffers through `read`, `write`, or `write_read_only`.
Disk reads require a read/write grant; disk writes can consume a read-only grant.
The Host checks the configured device, alignment, bounds, and read-only policy before accepting a request.
Rejected requests preserve the original wrapper and active grant.

Only audited whole-device VirtIO block backends accept zero-copy attachments.
Their BIOs retain and use the original DMA allocation.
Incompatible backends fail attachment with `EOPNOTSUPP`; the zero-copy device does not silently copy payloads.
Other block adapters and buffered files remain usable through the existing copying devices.
Existing copying VirtIO block requests retain their transport.
Borrowed VirtIO requests keep the same Image transport and use the independent lending backend described above.
Native builds retain their original trap sequence and public BIO backing interface.
Native I/O, existing copying transport, and explicit shared-buffer requests remain separate paths.
Each authorized connection exposes an independent `ZeroCopyNet` datagram device.
`ZeroCopyDatagramSocket` accepts owning buffers and returns imported packets for direct parsing or forwarding.
The kernel socket adapter keeps the owning packet instead of requiring a receiver-posted byte destination.
Successful sends issue a read-only receiver grant; queue rejection returns the original buffer or packet.
The interface is nonblocking and permits datagrams of 0 to 65535 bytes.
Concurrent receive contention reports pending without consuming a later packet.
Accepted deliveries remain discoverable after sender exit; disconnected, drained devices report a connection error.
This transport provides no Ethernet, IP, UDP, or physical NIC implementation.
Startup-selected shared Ethernet connects ordinary Linux sockets to the existing Host NAT worker.
Its queues and NAT receive state carry compact shared handles independently of inline copying frames.
The worker keeps one prepared transmit reservation across unused paired receive tokens.
Internal recycling and transmission do not notify the already-running worker.
External Image deliveries, explicit kicks, and cancellation retain the generation-based wake protocol.
Other connections can release Image import credit without a NIC notification.
The worker retries blocked import admission after 10 ms; each failed attempt arms at most one retry.
Buffer exhaustion still waits for the ordinary return notification.
The private NIC exchange returns up to 32 empty grants and activates up to 32 pending grants in one service call.
The Host pins the complete registered DMA metadata range and validates every return before changing ownership.
Rejected exchanges preserve the input owners; descriptor copies contain metadata only.
Generic shared-buffer receipt retains its separate observation and redemption operations.
Copying VirtIO network devices and physical receive paths remain available independently.
The OCI annotation `org.asterinas.kernelet.zero-copy-blocks` configures explicit additional block attachments before start.
There is no Linux Host implementation in this repository.

Kernel tests cover grant permissions, stale tokens, credit rejection, generation exhaustion, delayed completion, cancellation, and teardown.
Compiler checks use the real image-side OSTD types to reject unauthorized writers, duplicate owners, and transfers with live borrows.
Assembly audits check the actual entry and return instruction sequences; fixtures are regenerated from the assembly sources.
The opt-in shared-I/O regression boots two real images and exercises the public kernel interfaces.
It checks a dedicated QEMU VirtIO block driver's read, write, and readback against the original allocation.
It also checks four datagram sizes, round-trip allocation identity, connection rejection, capability delegation, and successful instance teardown.
QEMU validates this virtual device path; it does not establish bare-metal DMA behavior, end-to-end copy counts, latency, or throughput.
The transparent-I/O regression adds ordinary file read/write, `fsync`, `MAP_SHARED`/`msync`, and TCP/UDP echo workloads.
It uses separate copying and shared root disks, native Host echo servers, device counters, and offline disk-content checks.
Results apply to the tested Host/Image pair; a different build requires its own integrated run.
Concurrent mapping writes, concurrent writeback, and cancellation during physical DMA need separate coverage.
No performance result follows from the fixture or its elapsed-time observations.
No experiment-plan item is marked complete by these implementation checks.
