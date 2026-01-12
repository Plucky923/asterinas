# Nested Virtualization Quickstart (L0 -> L1 -> L2)

This guide describes how to run nested KVM with this repository's initramfs
workflow and execute memory benchmarks in L2.

For the FrameVM memory comparison workflow, use
`test/framevm_linux_stack_runbook.md` as the authoritative runbook.

## 1. Build initramfs with QEMU in guest userspace

Enable both basic test apps and nested QEMU payload:

```bash
make -C test/initramfs \
  ENABLE_BASIC_TEST=true \
  ENABLE_NESTED_QEMU=true
```

This keeps default behavior unchanged unless `ENABLE_NESTED_QEMU=true` is set.

## 2. Boot L1 with nested virtualization exposed

Use KVM acceleration and expose virtualization features into L1.

Intel host example:

```bash
qemu-system-x86_64 \
  --no-reboot \
  -smp 4 \
  -m 8G \
  -machine q35,kernel-irqchip=split \
  -accel kvm \
  -cpu host,+x2apic,+vmx \
  -nographic \
  -serial chardev:mux \
  -monitor chardev:mux \
  -chardev stdio,id=mux,mux=on,signal=off,logfile=qemu.log \
  -drive if=none,format=raw,id=x0,file=test/initramfs/build/ext2.img \
  -device virtio-blk-pci,bus=pcie.0,addr=0x6,drive=x0,serial=vext2,disable-legacy=on,disable-modern=off \
  -device virtio-serial-pci,disable-legacy=on,disable-modern=off \
  -device virtconsole,chardev=mux \
  -device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid=3,disable-legacy=on,disable-modern=off \
  -kernel bzImage \
  -initrd test/initramfs/build/initramfs.cpio.gz \
  -append "console=hvc0 rdinit=/bin/sh mitigations=off hugepages=0 transparent_hugepage=never"
```

## 3. Validate nested KVM prerequisites inside L1

In minimal `rdinit=/bin/sh` environment, mount pseudo filesystems first:

```bash
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /ext2
mount -t ext2 /dev/vda /ext2 || mount -t ext2 /dev/sda /ext2
```

Then validate:

```bash
grep -E 'vmx|svm' /proc/cpuinfo | head -n 1
ls -l /dev/kvm
qemu-system-x86_64 --version
ls -lh /ext2/l2
```

## 4. Start L2 from inside L1

A helper script is installed at `/test/nested_l2_qemu.sh` when basic
tests are enabled.

```bash
sh /test/nested_l2_qemu.sh <L2_bzImage> <L2_initramfs.cpio.gz>
```

Recommended first launch (avoid overriding `L2_APPEND` to reduce quoting mistakes):

```bash
L2_SMP=1 L2_MEM=2G L2_CPU=host \
  sh /test/nested_l2_qemu.sh /ext2/l2/bzImage /ext2/l2/initramfs.cpio.gz
```

Example with optional L2 disk:

```bash
sh /test/nested_l2_qemu.sh /ext2/l2/bzImage /ext2/l2/initramfs.cpio.gz \
  -drive if=none,format=raw,id=d0,file=/ext2/l2/ext2.img \
  -device virtio-blk-pci,drive=d0
```

Tunable environment variables:

```bash
L2_SMP=2 L2_MEM=2G L2_CPU=host \
  sh /test/nested_l2_qemu.sh /ext2/l2/bzImage /ext2/l2/initramfs.cpio.gz
```

If L2 reports `unknown-block(0,0)`, verify initrd integrity in L1:

```bash
gzip -t /ext2/l2/initramfs.cpio.gz
```

## 5. Run memory benchmarks in L1/L2

Inside each guest (L1 and L2), run the same binaries/parameters:

```bash
cd /test/memory
./bench_memory_page_seq_cold
./bench_memory_page_seq_warm
./bench_memory_page_rand_warm
./bench_memory_word_seq_warm
```

For better stability, rebuild with repeated runs:

```bash
make -C test/initramfs/src/apps/memory compare_all MEM_COMPARE_RUNS=7
```

Then use median-based `Result` for comparisons.
