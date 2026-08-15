# VM-based Containers

VM-based containers run container workloads inside lightweight virtual machines.
They preserve the familiar container deployment model
while adding a stronger isolation boundary than process-based containers.

This chapter introduces how VM-based container runtimes can use Asterinas
as a guest kernel.

For the FrameV virtual-device architecture,
see [FrameV Protocol: Atomic Interface Stages](framev-design.md).
For native NVMe driver reuse with mediated PCI resource custody, see
[NVMe Mediated Passthrough: Assignment and I/O Protocol](nvme-passthrough-design.md).
For FrameVM CPU, memory, lifecycle, mediated PCI assignment, and the control
file ABI, see [FrameVM Design: CPU, Memory, and I/O Virtualization](framevm-architecture.md)
and [FrameVM Control Device](framevm.md).

## Why Asterinas?

Asterinas is a good fit for VM-based containers
because it offers a smaller attack surface
and a stronger security foundation than Linux.
Its [framekernel architecture](../the-framekernel-architecture.md)
helps reduce the Trusted Computing Base (TCB)
of the guest kernel.

At the same time,
Asterinas provides a Linux-compatible ABI.
This allows many existing Linux workloads
to migrate to Asterinas-based VM environments seamlessly,
without requiring changes to the applications themselves.

## Supported runtimes

Here is the list of secure container runtimes that have been verified to work with Asterinas:

- [Kata Containers](kata.md)
- [Confidential Containers (CoCo)](coco.md)
