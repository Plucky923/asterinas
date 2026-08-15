# FrameV Protocol: Atomic Interface Stages

FrameV is the typed paravirtual I/O interface between a FrameVM service and
FrameVisor. It is not a PCI register ABI, a generic descriptor-ring protocol,
or a Host-memory mapping interface.

The current service adapter uses synthetic PCI to discover an offered function,
but PCI ends before a FrameV call begins. The FrameV interface begins with a
bound `FunctionClaim` and a family-specific typed operation.

This document specifies the common protocol only. Console, RNG, Block, Sock,
and Net define their own operation types and backing-resource policies within
this protocol.

## 1. Interface boundary

The service-side transport surface is the closed module tree:

~~~text
ostd::framev::console
ostd::framev::rng
ostd::framev::blk
ostd::framev::sock
ostd::framev::net
~~~

There is deliberately no universal `FrameVRequest`, `FrameVCompletion`, or
`FrameV` trait. The interface names the device family and encodes the payload
shape in the Rust type. A frontend cannot use a generic operation to reach an
unrelated family.

| Term | Protocol meaning |
| --- | --- |
| Function family | One of Console, RNG, Block, Sock, or Net. It selects the typed operation vocabulary. |
| Frontend | The service object that retains a `FunctionClaim` and calls one family module. |
| `FunctionClaim` | Opaque authority for one FrameVM, one family, and one running generation. |
| Typed payload | A borrowed slice, mutable slice, direction-typed Block view, packet, or owned Net buffer. It defines what the Host may access. |
| Generation | The lifecycle epoch of a running function. A later start creates a new epoch. |

## 2. What “atomic stage” means

An atomic stage is a protocol commitment point, not a non-preemptible CPU
instruction. A stage either commits the result stated below, so that the next
stage can observe it, or returns an error without granting the next stage’s
authority or ownership.

The common protocol has six stages:

~~~text
Stopped
    -> 1. make function available
    -> 2. bind one frontend
    -> 3. admit one call
    -> 4. execute typed data operation
    -> 5. publish and consume asynchronous state, when needed
    -> 6. revoke and stop
    -> Stopped
~~~

Stages 1, 2, and 6 are the common control plane. Stages 3–5 are the data
plane. A family may omit stage 5 when all of its operations return
synchronously.

## 3. Stage 1: make a function available

**Input.** The function is stopped and has no admitted calls.

**Action.** FrameVisor starts the function runtime, advances its generation,
and makes the family backing state available.

**Committed result.** The function is running and can issue one current claim.

**Failure result.** The function remains unavailable; no frontend can begin a
FrameV operation.

**Why it matters.** Generation separates lifetimes. A later start represents a
new endpoint even if it offers the same family as an earlier instance.

## 4. Stage 2: bind one frontend

**Input.** A running offered function and the current FrameVM service context.

**Action.** A binding adapter identifies the family, validates its
binding-specific configuration, and acquires a `FunctionClaim`. It stores that
claim in the matching frontend.

**Committed result.** Exactly one current frontend holds the claim for that
function.

**Failure result.** No frontend is bound. The caller receives no data-plane
authority.

**Key rule.** Discovery data is not part of the FrameV interface. The current
adapter may use PCI to find a function, but a FrameV transport call takes
neither a BDF, a BAR offset, nor a PCI handle. A different binding mechanism
could produce the same claim without changing any `ostd::framev` operation.

## 5. Stage 3: admit one typed call

**Input.** A frontend supplies its retained `FunctionClaim` and one
family-specific operation.

**Action.** The runtime checks that the current FrameVCPU belongs to the
claim’s FrameVM, that the requested family matches, that the function is
running, and that this is still the current claim. It then records one active
call.

**Committed result.** The operation is admitted. The family Host may execute
exactly this typed operation while the call is active.

**Failure result.** The operation is rejected before it reaches family state or
a Host resource. Any caller-owned input remains with the caller.

**Key rule.** The VM, family, and lifecycle are derived from execution context
and the opaque claim. They are not mutable fields in a caller-supplied request.

## 6. Stage 4: execute the typed data operation

**Input.** One admitted call and the family’s typed arguments.

**Action.** The family executes its operation and returns its typed result.
There is no shared FrameV request header or completion object.

**Committed result.** The result describes exactly what happened to the
payload. The common payload forms are:

| Payload form | Host authority | Completion rule |
| --- | --- | --- |
| `&[u8]` | Inspect bytes only during this call. | Return when the synchronous operation finishes. |
| `&mut [u8]` | Fill bytes only during this call. | Return the filled slice to the caller’s scope. |
| Direction-typed Block view | Read from or write to the stated direction only. | Return a Block status. |
| `OwnedNetworkBuffer` | Retain the buffer only after successful posting. | Transfer it back by completion or reclamation. |

For example, Console writes consume a borrowed byte slice only for the call’s
lifetime. RNG fills a mutable byte slice in that same lifetime. Block uses
direction-typed views. These operations do not create a background FrameV
request.

When a call returns, its active-call record is released. A stop can therefore
wait for all previously admitted operations without admitting new ones.

## 7. Stage 5: publish and consume asynchronous state

Only families with retained or incoming state use this stage. It has three
atomic handoffs.

### 7.1 Submit owned storage

**Input.** A service-owned `OwnedNetworkBuffer` and an admitted Net call.

**Action.** Net either accepts the buffer as receive storage or rejects it.

**Committed result.** On acceptance, ownership transfers from the frontend to
Net. On admission failure or Net rejection, the result returns the exact
buffer to the frontend.

This is the only point at which a posted receive buffer becomes Host-owned. It
prevents an ambiguous state in which both sides believe they own the buffer.

### 7.2 Publish ready state

**Input.** Family-owned state becomes ready: for example, Net fills a posted
receive buffer, Console queues input, or Sock receives a packet.

**Action.** The family publishes the typed state in its own queue or completion
state before requesting a service wakeup.

**Committed result.** A later service observation can retrieve the state. The
notification carries neither payload bytes nor a new capability.

**Ordering rule.** Publication happens before notification. A wakeup is only a
readiness hint; the typed family state is authoritative.

### 7.3 Consume or reclaim typed state

**Input.** The frontend runs after a readiness notification, or polls a family
operation directly.

**Action.** It invokes the family’s typed take/receive operation, such as
`take_claimed_input`, `recv_packet_claimed`, or
`take_completed_buffer_claimed`.

**Committed result.** The frontend receives one typed item, or `None` if no
item is available. For Net, a completed buffer returns with its valid byte
count; an endpoint-loss path returns an uncompleted buffer through the
reclamation operation.

**Key rule.** Completion and reclamation are distinct typed outcomes. FrameV
does not encode both in a shared completion ring or status word.

## 8. Stage 6: revoke and stop

**Input.** FrameVisor decides to stop a running function.

**Action.** It revokes the current claim and closes call admission, then waits
for already admitted calls to finish. It stops the family backing state only
after that drain point.

**Committed result.** The function is stopped. No stale frontend can begin a
new call, and no stale asynchronous state may become part of a later run.

**Failure result.** A stopped or stopping function rejects further calls rather
than exposing partially torn-down family state.

**Why it matters.** The next start advances the generation and requires a new
claim. An old claim, ready item, posted buffer, or notification cannot be
reinterpreted as state belonging to the new generation.

## 9. Family interface map

The common protocol does not prescribe per-family payload formats. The current
families bind it as follows:

| Family | Interface role | Data shape | Asynchronous state |
| --- | --- | --- | --- |
| Console | Output and input consumption. | Borrowed output bytes; typed input item. | Input readiness. |
| RNG | Random-byte fill. | Mutable byte slice. | None. |
| Block | Read, write, and flush. | Direction-typed Block views and status. | None. |
| Sock | Packet transport. | Typed packets with an explicit service/Host copy boundary. | Receive and reset state. |
| Net | Ethernet send and receive. | Borrowed transmit frame; owned posted receive buffer. | Completion, reclamation, and endpoint loss. |

The table is a binding map, not an additional protocol. A new family must use
the same six stages, but may introduce a new typed operation when its endpoint
semantics require one.

## 10. Protocol invariants

The following properties are the complete common contract:

1. **Authority is contextual.** A data operation cannot select another VM or
   function through a request field.
2. **Payload authority is typed.** No common operation accepts a Host pointer,
   physical address, generic DMA object, or untyped descriptor chain.
3. **Ownership has an explicit handoff.** Borrowed data stays borrowed; owned
   data transfers only at a documented submit, completion, or reclamation
   point.
4. **Notification is not data transport.** The service reads typed state after
   a wakeup instead of receiving bytes in interrupt context.
5. **Stop is an admission fence.** New calls fail after revocation, while
   admitted calls drain before teardown.
6. **Restart creates a new epoch.** Work from an old generation cannot enter a
   later generation.

These invariants describe the FrameV interface independently of the current
synthetic-PCI binding and virtual-interrupt implementation. For CPU, memory,
and device-assignment virtualization, see
[FrameVM Design: CPU, Memory, and I/O Virtualization](framevm-architecture.md).
