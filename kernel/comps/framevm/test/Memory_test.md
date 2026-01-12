# FrameVM 内存性能测试设计

## 1. 背景与动机

### 1.1 虚拟化内存开销来源

在虚拟化系统中，内存访问性能的主要开销来源于：

#### EPT 二阶段地址转换

| 环境 | 地址转换路径 | TLB miss 最坏情况 |
|------|-------------|------------------|
| **原生系统** | VA → PA (4级页表) | 4 次内存访问 |
| **Linux Guest (EPT)** | GVA → GPA → HPA (4×4级) | 24 次内存访问 |
| **FrameVM** | VA → PA (4级页表) | 4 次内存访问 |

```
原生/FrameVM:
  VA ──→ [L4] ──→ [L3] ──→ [L2] ──→ [L1] ──→ PA
              4 次页表访问

Linux Guest (EPT):
  GVA ──→ [Guest L4] ──→ ... ──→ [Guest L1] ──→ GPA
              │                        │
              ↓ (每级都需EPT转换)       ↓
          [EPT 4级]              [EPT 4级]

  最坏情况: 4 (Guest) × 4 (EPT) + 4 (最终GPA→HPA) = 24 次
```

#### Page Fault 处理路径

| 环境 | Page Fault 路径 | 开销 |
|------|----------------|------|
| **原生系统** | 异常 → 分配页 → 更新页表 → 返回 | ~1000-3000 cycles |
| **Linux Guest** | EPT violation → VM-Exit → Host处理 → 分配页 → VM-Entry | ~5000-20000 cycles |
| **FrameVM** | 异常 → 分配页 → 更新页表 → 返回 | ~1000-3000 cycles |

### 1.2 FrameVM 优势

FrameVM 采用基于语言的隔离而非硬件辅助虚拟化：
- **单阶段地址转换**：无 EPT/NPT 开销
- **无 VM-Exit**：Page Fault 在同一特权级处理
- **接近原生性能**：理论上与 Container/Host 相当

### 1.3 实验目标

通过精心设计的微基准测试，量化验证：
1. FrameVM 在 TLB miss 场景下的性能优势
2. FrameVM 在 Page Fault 场景下的性能优势
3. EPT 二阶段遍历的实际开销

---

## 2. FrameVM 页面加载策略

### 2.1 Demand Paging 确认 ✅

通过代码探索确认 FrameVM 使用 **延迟页面分配**：

```rust
// kernel/comps/framevm/src/vm.rs
let mut lazy_ranges = Vec::new();
load_segment(&vm_space, &ph, program, &mut lazy_ranges)?; // 记录 BSS lazy ranges

// kernel/comps/framevm/src/task.rs
pub fn user_page_fault_handler(exception: &CpuException) -> Result<(), ()> {
    handle_lazy_page_fault(task_data.vm_space.as_ref(),
                           task_data.lazy_ranges.as_ref(), info)
}
```

**关键证据**：
- `lazy_ranges`：BSS/未初始化段在加载时不映射物理页
- `user_page_fault_handler`：首次触页时分配并映射
- 静态数组位于 BSS：符合“首次访问才分配”的模型

### 2.2 测试含义

| 场景 | 预热状态 | 测量内容 |
|------|---------|---------|
| 首次访问 (cold) | 无 | Page Fault + 页分配 + 页表更新 |
| 再次访问 (warm) | 已预热 | 纯地址翻译（可能 TLB miss） |

**结论**：`page-seq + 无预热` 可以正确测量 Page Fault 开销。

---

## 3. 测试程序设计

### 3.1 设计约束

由于 FrameVM 原型系统仅支持简化的用户态执行环境：

| 约束 | 说明 |
|------|------|
| 纯用户态 | 无系统调用（除 exit） |
| 静态分配 | 编译时确定所有虚拟地址 |
| 非特权指令 | 仅 load/store/算术运算 |
| Freestanding C | `-nostdlib -fno-builtin` |

### 3.2 访问模式详解

| Pattern | 值 | 访问粒度 | 访问顺序 | 主要测量目标 |
|---------|---|---------|---------|-------------|
| `ACCESS_SEQ` | 0 | 8B word | 顺序 | 顺序访问基线（TLB 局部性更好） |
| `ACCESS_RAND` | 1 | 8B word | 随机 | Cache miss + 随机访问 |
| `ACCESS_PAGE_SEQ` | 2 | 4KB page | 顺序 | Page Fault 开销 |
| `ACCESS_PAGE_RAND` | 3 | 4KB page | 随机 | TLB miss + EPT walk |

### 3.3 Page-Stride 模式设计

**核心思想**：每页只访问首个 cache line，消除数据缓存干扰。

```c
// page-stride 访问：每 4096 字节访问一次
for (uint64_t i = 0; i < pages; i++) {
    volatile uint64_t *ptr = (volatile uint64_t *)(base + i * 4096);
    acc ^= *ptr;  // 仅访问页首 8 字节
}
```

**优点**：
- 消除 L1/L2/L3 data cache miss 干扰
- 地址翻译成为唯一瓶颈
- 每次访问对应一个独立的 TLB 条目

### 3.4 Pointer-Chase 技术

**目的**：阻止 CPU 硬件预取和乱序执行优化。

```c
// 随机 pointer-chase：下一个地址存储在当前位置
uint32_t idx = start;
for (uint64_t i = 0; i < steps; i++) {
    uint64_t val = data_array[idx * PAGE_STRIDE_WORDS];
    idx = (uint32_t)(val & 0xFFFFFFFF);  // 必须读取后才能确定下一地址
}
```

**效果**：
- 强制串行化访问
- 阻止预取器提前加载
- 每次访问的延迟完整体现

### 3.5 重要限制 ⚠️

**page-rand 模式无法测量 cold Page Fault**：

```c
// build_page_chain() 在测量前已触发所有页的 Page Fault
static void build_page_chain(uint32_t pages) {
    for (uint32_t i = 0; i < pages; i++) {
        uint32_t cur = page_order[i];
        uint32_t next = page_order[(i + 1) % pages];
        // 这里的写入会触发 Page Fault！
        data_array[(uint64_t)cur * PAGE_STRIDE_WORDS] = (uint64_t)next;
    }
}
```

| 模式 | 有效性 | 原因 |
|------|-------|------|
| `page-seq + cold` | ✅ 有效 | 顺序访问，无需预建链表 |
| `page-seq + warm` | ✅ 有效 | 预热后测量纯地址翻译 |
| `page-rand + warm` | ✅ 有效 | build 后预热，测量 TLB miss |
| `page-rand + cold` | ❌ 无效 | build 阶段已触发所有 PF |

---

## 4. 编译目标

### 4.1 核心测试目标

| 目标名 | Pattern | Warmup | 工作集 | 用途 |
|-------|---------|--------|-------|------|
| `bench_memory_page_seq_cold` | 2 | 0 | 512MB | Page Fault 开销 |
| `bench_memory_page_seq_warm` | 2 | 1 | 512MB | 基线对比（无 PF） |
| `bench_memory_page_rand_warm` | 3 | 1 | 512MB | TLB miss 开销 |
| `bench_memory_word_seq_warm` | 0 | 1 | 512MB | EPT 基础开销 |

### 4.2 工作集 Sweep 目标

用于绘制 "工作集大小 vs 延迟" 曲线：

| 目标名 | 工作集 | 页数 |
|-------|-------|------|
| `bench_memory_page_rand_warm_64k` | 64 KB | 16 |
| `bench_memory_page_rand_warm_128k` | 128 KB | 32 |
| `bench_memory_page_rand_warm_256k` | 256 KB | 64 |
| `bench_memory_page_rand_warm_512k` | 512 KB | 128 |
| `bench_memory_page_rand_warm_1m` | 1 MB | 256 |
| `bench_memory_page_rand_warm_2m` | 2 MB | 512 |
| `bench_memory_page_rand_warm_4m` | 4 MB | 1024 |
| `bench_memory_page_rand_warm_8m` | 8 MB | 2048 |
| `bench_memory_page_rand_warm_16m` | 16 MB | 4096 |
| `bench_memory_page_rand_warm_32m` | 32 MB | 8192 |
| `bench_memory_page_rand_warm_64m` | 64 MB | 16384 |

### 4.3 编译命令

```bash
cd kernel/comps/framevm/test

# 编译所有内存测试
make clean
make memory_all

# 仅编译工作集 sweep
make page_rand_warm_sweep

# 仅编译四场景对比
make compare_all

# 显示所有目标信息
make info
```

### 4.4 自定义编译

```bash
# 自定义工作集大小
make bench_memory_page_seq_cold MEM_COMPARE_WORKSET_BYTES=134217728  # 128MB

# 自定义重复次数（warm 目标）
make bench_memory_word_seq_warm MEM_WORD_SEQ_WARM_REPEAT=100

# 自定义随机种子
make bench_memory_page_rand_warm MEM_COMPARE_SEED=42
```

---

## 5. 实验设计

### 5.1 实验矩阵总览

| 实验目标 | Pattern | Warmup | 关键配置 | 测量内容 |
|---------|---------|--------|---------|---------|
| **Page Fault** | 2 (page-seq) | 0 | `REPEAT=1, DO_STORE=1` | 首次触页开销（写触页） |
| **TLB miss** | 3 (page-rand) | 1 | `REPEAT=200, DO_STORE=0` | 地址翻译开销 |
| **EPT 基础** | 0 (word-seq) | 1 | `REPEAT=200` | 顺序访问基线（TLB 局部性更好） |
| **基线对比** | 2 (page-seq) | 1 | - | 排除 PF 后的对比 |

### 5.2 实验 1：工作集大小 vs TLB miss 延迟

**目的**：验证工作集超过 TLB 覆盖范围时，EPT 二阶段遍历导致延迟急剧上升。

**配置**：
```
Pattern:   3 (page-rand)
Warmup:    1 (消除 Page Fault)
DO_STORE:  0 (load-only，避免 dirty bit 开销)
REPEAT:    200
SEED:      12345 (固定种子，确保可复现)
```

**工作集范围**：64KB → 64MB

**TLB 架构参考** (Intel Icelake)：

| TLB 层级 | 条目数 | 覆盖范围 (4KB页) |
|---------|-------|-----------------|
| L1 dTLB | 64 | 256 KB |
| L2 sTLB | 1536 | 6 MB |

**预期趋势**：

```
Cycles/page
    ^
    |
600 |                                         _____ Linux Guest (EPT)
    |                                    ____/
500 |                               ____/
    |                          ____/        (每次 TLB miss: 24次内存访问)
400 |                     ____/
    |                ____/
300 |           ____/
    |      ____/
200 |_____/_________________________________ FrameVM / Container / Host
    |                                        (每次 TLB miss: 4次内存访问)
100 |
    |
    +-------------------------------------------------> Workset
         64K  256K   1M    4M    8M   16M   32M   64M
              ↑           ↑
           L1 dTLB    L2 sTLB
           边界        边界
```

**关键观察点**：
1. 64KB-256KB：L1 dTLB 命中，所有环境性能相近
2. 256KB-6MB：L1 miss + L2 hit，开始出现分化
3. >6MB：L2 miss，EPT 开销完全暴露

### 5.3 实验 2：四场景对比

**目的**：在固定工作集下，区分 Page Fault、TLB miss、EPT 基础开销的贡献。

**固定工作集**：512MB (131072 pages)

| 场景 | 目标程序 | 测量内容 |
|------|---------|---------|
| A: page_seq_cold | `bench_memory_page_seq_cold` | Page Fault + 页表更新 |
| B: page_seq_warm | `bench_memory_page_seq_warm` | 基线（预热后顺序访问） |
| C: page_rand_warm | `bench_memory_page_rand_warm` | TLB miss + EPT walk |
| D: word_seq_warm | `bench_memory_word_seq_warm` | 顺序访问基线（TLB 局部性更好） |

**开销分解**：

```
开销 (Cycles/page)
    ^
    |
    |  ┌─────────────────┐
    |  │   Page Fault    │  ← A - B
    |  │     开销        │
    |  ├─────────────────┤
    |  │   TLB miss      │  ← C - D
    |  │     开销        │
    |  ├─────────────────┤
    |  │   EPT 基础      │  ← D (Linux Guest)
    |  │     开销        │     vs 0 (FrameVM)
    |  └─────────────────┘
    +-------------------------> 测试场景
         A    B    C    D
```

**四种测试环境**：

| 环境 | 类型 | 地址翻译 | 期望性能 |
|------|-----|---------|---------|
| Linux Guest (QEMU/KVM) | 硬件虚拟化 | 二阶段 (EPT) | 最慢 |
| Linux Container | 进程隔离 | 单阶段 | 快 |
| FrameVM | 语言隔离 | 单阶段 | 快 |
| Host (Asterinas) | 原生 | 单阶段 | 最快 |

**预期结论**：
1. **A > B**：Page Fault 开销显著
2. **C > D**：TLB miss 开销
3. **Linux Guest >> 其他**（在 C 和 D 中）：EPT 二阶段遍历
4. **FrameVM ≈ Container ≈ Host**：单阶段页表，性能接近

---

## 6. 运行指南

### 6.1 FrameVM 环境

#### 编译 Asterinas + FrameVM

```bash
make framevm \
    ENABLE_BASIC_TEST=true \
    VSOCK=on \
    SMP=1 \
    MEM=8G \
    ENABLE_KVM=1 \
    RELEASE_LTO=1
```

#### 运行测试

测试程序会被打包到 initramfs 中，通过 FrameVM 用户任务执行。

### 6.2 Linux Guest 环境

#### QEMU 启动参数

```bash
qemu-system-x86_64 \
    --no-reboot \
    -smp 1 \
    -m 8G \
    -machine q35,kernel-irqchip=split \
    -accel kvm \
    -cpu Icelake-Server,+x2apic \
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

#### 关键内核参数

| 参数 | 说明 | 必要性 |
|------|------|-------|
| `transparent_hugepage=never` | 禁用透明大页 | **必须** |
| `hugepages=0` | 不预留大页 | **必须** |
| `mitigations=off` | 关闭安全缓解措施 | 推荐（减少噪声） |

**为什么禁用大页**：
- 测试设计基于 4KB 页
- 大页会改变 TLB 覆盖范围
- 影响 Page Fault 粒度

### 6.3 Container 环境

```bash
# 在 Host 上直接运行测试程序
# 需要确保内核参数一致
echo never > /sys/kernel/mm/transparent_hugepage/enabled
./bench_memory_page_rand_warm
```

### 6.4 Host 环境

在 Asterinas 原生环境中运行，作为性能基线。

---

## 7. 输出格式

### 7.1 输出示例

```
========================================
 FrameVM Memory Benchmark
========================================
 Workset:     67108864 bytes
 Repeat:      1
 Iterations:  16384
 Mem ops:     16384
 Pattern:     page-rand
 Seed:        12345
 Op mode:     load-only
 Warmup:      yes
 Runs:        1
 Result:      200 cycles/op
========================================
```

### 7.2 字段说明

| 字段 | 说明 |
|------|------|
| Workset | 工作集大小（字节） |
| Repeat | 重复遍历次数 |
| Iterations | 总访问次数（pages × repeat 或 words × repeat） |
| Mem ops | 内存操作数（load-only 等于 iterations，load+store 是 2×） |
| Pattern | 访问模式 |
| Seed | 随机种子（仅 rand 模式） |
| Op mode | 操作模式（load-only 或 load+store） |
| Warmup | 是否预热 |
| Runs | 测量运行次数（多次取中位数） |
| Result | 统一结果指标（cycles/op，中位数口径） |

### 7.3 关键指标

- **实验 1 (工作集 sweep)**：关注 `Result`
- **实验 2 (四场景对比)**：关注 `Result`

---

## 8. 数据收集模板

### 8.1 实验 1：工作集 Sweep

| 工作集 | Linux Guest | Container | FrameVM | Host |
|-------|-------------|-----------|---------|------|
| 64 KB | | | | |
| 128 KB | | | | |
| 256 KB | | | | |
| 512 KB | | | | |
| 1 MB | | | | |
| 2 MB | | | | |
| 4 MB | | | | |
| 8 MB | | | | |
| 16 MB | | | | |
| 32 MB | | | | |
| 64 MB | | | | |

### 8.2 实验 2：四场景对比

**工作集：512MB**

| 场景 | Linux Guest | Container | FrameVM | Host |
|------|-------------|-----------|---------|------|
| page_seq_cold | | | | |
| page_seq_warm | | | | |
| page_rand_warm | | | | |
| word_seq_warm | | | | |

### 8.3 开销分解计算

```
Page Fault 开销 = page_seq_cold - page_seq_warm
TLB miss 开销   = page_rand_warm - word_seq_warm
EPT 额外开销    = Linux Guest 结果 - FrameVM 结果
```

---

## 9. 故障排除

### 9.1 常见问题

| 问题 | 可能原因 | 解决方案 |
|------|---------|---------|
| Cycles/page 异常高 | 透明大页未禁用 | 检查 `cat /sys/kernel/mm/transparent_hugepage/enabled` |
| 结果波动大 | CPU 频率变化 | 固定 CPU 频率或多次测量取中位数 |
| cold 和 warm 差异小 | 页面已被预热 | 确保每次测试前清空页面缓存 |
| 编译失败 | 缺少 syscalls.h | 确保在正确目录下编译 |

### 9.2 验证测试正确性

```bash
# 1. 验证 cold > warm（Page Fault 应有显著开销）
# 预期: page_seq_cold 的 cycles 应该远大于 page_seq_warm

# 2. 验证 page_rand > word_seq（TLB miss 应有开销）
# 预期: page_rand_warm 的 cycles/page 应该大于 word_seq_warm

# 3. 验证随机性
# 使用不同 SEED 应该得到相近但不完全相同的结果
```

---

## 10. 理论分析

### 10.1 TLB miss 开销估算

假设：
- 内存延迟：~100ns (~250 cycles @2.5GHz)
- 缓存延迟：L1=1ns, L2=4ns, L3=10ns

**单阶段页表遍历** (4 次访问)：
- 最坏情况：4 × 100ns = 400ns (~1000 cycles)
- 页表缓存命中：4 × 10ns = 40ns (~100 cycles)

**EPT 二阶段遍历** (最多 24 次访问)：
- 最坏情况：24 × 100ns = 2400ns (~6000 cycles)
- 部分缓存命中：~500-1500 cycles

### 10.2 Page Fault 开销估算

| 环境 | 主要开销来源 | 估算 |
|------|-------------|------|
| 原生 | 异常处理 + 页分配 + 页表更新 | ~1000-3000 cycles |
| EPT | + VM-Exit + VM-Entry + EPT 更新 | ~5000-20000 cycles |

### 10.3 预期加速比

| 场景 | 预期 FrameVM vs Linux Guest |
|------|----------------------------|
| Page Fault (cold) | 3-10x 更快 |
| TLB miss (large workset) | 2-6x 更快 |
| TLB hit | ~1x (相近) |

---

## 11. 参考资料

### 11.1 项目文件

| 文件 | 说明 |
|------|------|
| `bench_memory.c` | 测试程序源码 |
| `syscalls.h` | 系统调用封装 |
| `Makefile` | 编译配置 |

### 11.2 相关文档

- Intel SDM Volume 3, Chapter 28: VMX
- Intel SDM Volume 3, Chapter 4: Paging
- AMD APM Volume 2: System Programming (NPT)

### 11.3 相关论文

- "A Comparison of Software and Hardware Techniques for x86 Virtualization" (VMware, 2006)
- "Eliminating the Address Translation Overhead" (ASPLOS, 2018)
