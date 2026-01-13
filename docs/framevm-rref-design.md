# FrameVM/FrameVisor RRef 设计优化方案

## 1. 现状分析：当前实现 vs RedLeaf

### 1.1 架构对比

| 特性 | RedLeaf | 当前 FrameVM 实现 |
|------|---------|-------------------|
| **所有权存储位置** | 内联在共享堆（指针直接访问） | 全局 HashMap 查表 |
| **所有权转移开销** | O(1) - 1次内存写入 | O(1) 平均 - 但需要锁+HashMap查找 |
| **元数据结构** | 3个独立指针（domain_id, borrow_count, value） | RRefId + Option<T> |
| **注册表设计** | 仅用于分配/释放/崩溃恢复 | 每次转移都需要访问 |
| **借用计数** | 内联存储，O(1) 访问 | 已移除（no-op） |
| **类型注册** | 需要 DropMap 注册 | 不需要 |
| **崩溃清理** | 自动调用类型特定 drop | 仅移除注册表条目 |

### 1.2 当前实现的优点

1. **简洁性**：RRef 结构简单，只有 `id` 和 `value`
2. **类型安全**：利用 Rust 的 `Option<T>` 防止 use-after-consume
3. **分片锁**：64 个分片减少锁竞争
4. **无 unsafe**：`exchangeable` crate 完全不使用 unsafe

### 1.3 当前实现的问题

1. **所有权转移需要查表**：每次 `transfer_to()` 都需要：
   - 计算分片索引
   - 获取分片锁
   - HashMap 查找
   - 更新 owner 字段

2. **热路径开销**：vsock 每个数据包都创建 RRef，高吞吐场景下注册表成为瓶颈

3. **崩溃清理不完整**：`reclaim_domain()` 只移除注册表条目，不释放实际内存

4. **借用计数已废弃**：接口保留但实现为 no-op，增加代码复杂度

---

## 2. 优化方案

### 2.1 方案 A：内联元数据（RedLeaf 风格）

**核心思想**：将 `owner` 和 `borrow_count` 内联存储在 RRef 旁边，通过指针直接访问。

```rust
/// 共享堆分配的内存布局
/// +------------------+
/// | owner: AtomicU64 |  <- 8 bytes
/// +------------------+
/// | borrow_count: u64|  <- 8 bytes (可选)
/// +------------------+
/// | value: T         |  <- sizeof(T) bytes
/// +------------------+

pub struct RRef<T: Exchangeable> {
    /// 指向 owner 字段的指针（用于 O(1) 所有权转移）
    owner_ptr: *mut AtomicU64,
    /// 指向实际值的指针
    value_ptr: *mut T,
    /// 用于注册表查找（仅分配/释放/崩溃恢复时使用）
    id: RRefId,
}

impl<T: Exchangeable> RRef<T> {
    /// 所有权转移：O(1)，仅 1 次原子写入
    #[inline(always)]
    pub fn transfer_to(&self, new_owner: DomainId) {
        let owner_value = domain_id_to_u64(new_owner);
        unsafe {
            (*self.owner_ptr).store(owner_value, Ordering::Release);
        }
    }

    /// 获取当前所有者：O(1)，仅 1 次原子读取
    #[inline(always)]
    pub fn owner(&self) -> DomainId {
        let value = unsafe { (*self.owner_ptr).load(Ordering::Acquire) };
        u64_to_domain_id(value)
    }
}
```

**优点**：
- 所有权转移从 "锁+HashMap查找" 降为 "1次原子写入"
- 热路径完全不访问注册表
- 与 RedLeaf 性能特性一致

**缺点**：
- 需要引入 unsafe 代码
- 内存布局更复杂
- 需要自定义分配器

**适用场景**：极高吞吐量需求（>1M packets/sec）

---

### 2.2 方案 B：无锁注册表（推荐）

**核心思想**：保持当前架构，但用无锁数据结构替换分片 HashMap。

```rust
use crossbeam_skiplist::SkipMap;

pub struct RRefRegistry {
    /// 无锁跳表，支持并发读写
    entries: SkipMap<RRefId, RRefEntry>,
}

impl RRefRegistryOps for RRefRegistry {
    #[inline]
    fn register(&self, id: RRefId, owner: DomainId) {
        self.entries.insert(id, RRefEntry::new(owner));
    }

    #[inline]
    fn transfer(&self, id: RRefId, new_owner: DomainId) {
        // 无锁更新
        if let Some(entry) = self.entries.get(&id) {
            entry.value().owner.store(domain_id_to_u64(new_owner), Ordering::Release);
        }
    }

    // ... 其他方法
}
```

**优点**：
- 无需修改 RRef 结构
- 保持现有 API 兼容
- 消除锁竞争
- 实现相对简单

**缺点**：
- 仍需查表（但无锁）
- 依赖外部 crate

**适用场景**：中高吞吐量需求，希望最小化代码改动

---

### 2.3 方案 C：混合方案（推荐用于生产）

**核心思想**：结合方案 A 和 B 的优点，针对不同场景优化。

#### 2.3.1 快速路径：内联 owner

```rust
pub struct RRef<T: Exchangeable> {
    id: RRefId,
    /// 内联的 owner 字段，用于快速转移
    owner: AtomicU64,
    value: Option<T>,
}

impl<T: Exchangeable> RRef<T> {
    /// 快速所有权转移：O(1)，无需查表
    #[inline(always)]
    pub fn transfer_to(mut self, new_owner: DomainId) -> Self {
        self.owner.store(domain_id_to_u64(new_owner), Ordering::Release);
        // 注册表更新可以延迟或批量处理
        self
    }

    /// 快速所有者查询：O(1)
    #[inline(always)]
    pub fn owner(&self) -> DomainId {
        u64_to_domain_id(self.owner.load(Ordering::Acquire))
    }
}
```

#### 2.3.2 慢速路径：注册表用于崩溃恢复

```rust
pub struct RRefRegistry {
    /// 仅存储 RRefId -> 弱引用，用于崩溃恢复
    /// 不存储 owner（owner 在 RRef 内部）
    entries: SkipMap<RRefId, WeakRRefHandle>,
}

impl RRefRegistry {
    /// 崩溃恢复：扫描所有 RRef，检查内联 owner
    pub fn reclaim_domain(&self, domain: DomainId) -> Vec<RRefId> {
        let target = domain_id_to_u64(domain);
        let mut reclaimed = Vec::new();

        for entry in self.entries.iter() {
            if let Some(rref) = entry.value().upgrade() {
                if rref.owner.load(Ordering::Acquire) == target {
                    reclaimed.push(*entry.key());
                    // 触发清理
                }
            }
        }
        reclaimed
    }
}
```

**优点**：
- 热路径（所有权转移）为 O(1) 原子操作
- 冷路径（崩溃恢复）仍然可用
- 无需 unsafe（owner 是 RRef 的字段）
- 保持类型安全

**缺点**：
- RRef 结构体增大 8 bytes
- 崩溃恢复需要遍历

---

## 3. 详细设计：方案 C 实现

### 3.1 新的 RRef 结构

```rust
// kernel/comps/framevisor/exchangeable/src/lib.rs

use core::sync::atomic::{AtomicU64, Ordering};

/// Domain ID 编码
/// 0 = Host
/// 1..=u32::MAX = FrameVM(id - 1)
#[inline(always)]
fn domain_id_to_u64(domain: DomainId) -> u64 {
    match domain {
        DomainId::Host => 0,
        DomainId::FrameVM(id) => (id as u64) + 1,
    }
}

#[inline(always)]
fn u64_to_domain_id(value: u64) -> DomainId {
    if value == 0 {
        DomainId::Host
    } else {
        DomainId::FrameVM((value - 1) as u32)
    }
}

/// Remote Reference with inline ownership tracking
pub struct RRef<T: Exchangeable> {
    /// Unique identifier for registry (崩溃恢复用)
    id: RRefId,
    /// Inline owner for O(1) transfer (热路径优化)
    owner: AtomicU64,
    /// The actual value
    value: Option<T>,
}

impl<T: Exchangeable> RRef<T> {
    /// Create a new RRef with the current domain as owner
    #[inline]
    pub fn new(value: T) -> Self {
        let id = generate_rref_id();
        let owner = get_current_domain();
        let owner_encoded = domain_id_to_u64(owner);

        // 注册到全局表（用于崩溃恢复）
        if let Some(registry) = get_registry() {
            registry.register(id);
        }

        Self {
            id,
            owner: AtomicU64::new(owner_encoded),
            value: Some(value),
        }
    }

    /// O(1) ownership transfer - just an atomic store
    #[inline(always)]
    pub fn transfer_to(self, new_owner: DomainId) -> Self {
        self.owner.store(domain_id_to_u64(new_owner), Ordering::Release);
        self
    }

    /// O(1) owner query - just an atomic load
    #[inline(always)]
    pub fn owner(&self) -> DomainId {
        u64_to_domain_id(self.owner.load(Ordering::Acquire))
    }

    /// Check if current domain owns this RRef
    #[inline(always)]
    pub fn is_owned_by_current(&self) -> bool {
        self.owner() == get_current_domain()
    }

    // ... 其他方法保持不变
}
```

### 3.2 简化的注册表

```rust
// kernel/comps/framevisor/src/rref_registry.rs

use alloc::vec::Vec;
use crossbeam_skiplist::SkipSet;

/// Simplified registry - only tracks RRef existence, not ownership
/// Ownership is stored inline in RRef for O(1) access
pub struct RRefRegistry {
    /// Set of all active RRef IDs (for crash recovery)
    active_refs: SkipSet<RRefId>,
}

impl RRefRegistry {
    pub fn new() -> Self {
        Self {
            active_refs: SkipSet::new(),
        }
    }

    /// Register a new RRef (called on creation)
    #[inline]
    pub fn register(&self, id: RRefId) {
        self.active_refs.insert(id);
    }

    /// Unregister an RRef (called on drop)
    #[inline]
    pub fn unregister(&self, id: RRefId) {
        self.active_refs.remove(&id);
    }

    /// Get count of active RRefs
    pub fn count(&self) -> usize {
        self.active_refs.len()
    }
}

/// 新的 trait：简化版，移除 owner 相关方法
pub trait RRefRegistryOps: Send + Sync {
    fn register(&self, id: RRefId);
    fn unregister(&self, id: RRefId);
}
```

### 3.3 崩溃恢复机制

由于 owner 现在内联在 RRef 中，崩溃恢复需要不同的策略：

```rust
// kernel/comps/framevisor/src/domain.rs

/// 当 FrameVM 崩溃时的清理策略
pub enum CrashRecoveryStrategy {
    /// 立即清理：遍历所有 RRef，释放属于该域的
    Immediate,
    /// 延迟清理：标记域为已销毁，后续访问时清理
    Lazy,
    /// 引用计数：使用 Arc 自动清理
    RefCounted,
}

/// 推荐：延迟清理 + 域有效性检查
pub struct DomainManager {
    /// 活跃域集合
    active_domains: RwLock<BTreeSet<u32>>,
}

impl DomainManager {
    /// 销毁域：标记为非活跃
    pub fn destroy_domain(&self, vm_id: u32) {
        self.active_domains.write().remove(&vm_id);
    }

    /// 检查域是否活跃
    #[inline(always)]
    pub fn is_domain_active(&self, domain: DomainId) -> bool {
        match domain {
            DomainId::Host => true,
            DomainId::FrameVM(id) => self.active_domains.read().contains(&id),
        }
    }
}

/// RRef 访问时检查域有效性
impl<T: Exchangeable> RRef<T> {
    /// Safe access with domain validity check
    pub fn get_checked(&self) -> Option<&T> {
        let owner = self.owner();
        if DOMAIN_MANAGER.is_domain_active(owner) {
            self.value.as_ref()
        } else {
            // 域已销毁，触发清理
            None
        }
    }
}
```

---

## 4. 性能对比

### 4.1 微基准测试预估

| 操作 | 当前实现 | 方案 C |
|------|----------|--------|
| `RRef::new()` | ~100ns (HashMap insert) | ~50ns (SkipSet insert) |
| `transfer_to()` | ~80ns (锁+查找+更新) | **~5ns (原子写入)** |
| `owner()` | ~60ns (锁+查找) | **~3ns (原子读取)** |
| `drop()` | ~80ns (锁+删除) | ~40ns (SkipSet remove) |

### 4.2 吞吐量影响

假设 vsock 数据路径：
1. 创建 RRef
2. 转移到对端域
3. 对端处理
4. 释放 RRef

**当前实现**：每个包 ~320ns 注册表开销
**方案 C**：每个包 ~100ns 注册表开销

**预期提升**：~3x 注册表相关开销降低

---

## 5. 迁移计划

### Phase 1：内联 owner（低风险）

1. 修改 `RRef` 结构，添加 `owner: AtomicU64` 字段
2. 修改 `transfer_to()` 和 `owner()` 使用内联字段
3. 保持注册表不变（双写：内联 + 注册表）
4. 验证功能正确性

### Phase 2：简化注册表（中风险）

1. 移除注册表中的 owner 字段
2. 注册表仅跟踪 RRef 存在性
3. 更新崩溃恢复逻辑
4. 性能测试

### Phase 3：无锁数据结构（可选）

1. 引入 `crossbeam-skiplist` 或类似 crate
2. 替换分片 HashMap
3. 进一步性能优化

---

## 6. 其他优化建议

### 6.1 移除废弃的借用计数接口

当前 `increment_borrow`、`decrement_borrow`、`get_borrow_count` 都是 no-op，建议：

```rust
// 从 RRefRegistryOps trait 中移除
// pub trait RRefRegistryOps: Send + Sync {
//     fn increment_borrow(&self, id: RRefId);  // 移除
//     fn decrement_borrow(&self, id: RRefId);  // 移除
//     fn get_borrow_count(&self, id: RRefId) -> u32;  // 移除
// }

// 从 RRef 中移除
// impl<T: Exchangeable> RRef<T> {
//     pub fn borrow_tracked(&self) -> RRefBorrow<'_, T>;  // 移除
//     pub fn borrow_count(&self) -> u32;  // 移除
// }
```

### 6.2 批量操作优化

对于高吞吐场景，支持批量注册/注销：

```rust
impl RRefRegistry {
    /// 批量注册，减少锁获取次数
    pub fn register_batch(&self, ids: &[RRefId]) {
        for id in ids {
            self.active_refs.insert(*id);
        }
    }

    /// 批量注销
    pub fn unregister_batch(&self, ids: &[RRefId]) {
        for id in ids {
            self.active_refs.remove(id);
        }
    }
}
```

### 6.3 RRef 池化

对于频繁创建/销毁的场景，使用对象池：

```rust
pub struct RRefPool<T: Exchangeable> {
    pool: Mutex<Vec<RRef<T>>>,
    max_size: usize,
}

impl<T: Exchangeable + Default> RRefPool<T> {
    pub fn acquire(&self) -> RRef<T> {
        self.pool.lock().pop().unwrap_or_else(|| RRef::new(T::default()))
    }

    pub fn release(&self, mut rref: RRef<T>) {
        let mut pool = self.pool.lock();
        if pool.len() < self.max_size {
            // 重置状态
            rref.owner.store(domain_id_to_u64(DomainId::Host), Ordering::Release);
            pool.push(rref);
        }
        // 否则正常 drop
    }
}
```

---

## 7. 总结

### 推荐方案：方案 C（混合方案）

**核心改动**：
1. 将 `owner` 内联到 RRef 结构中（+8 bytes）
2. `transfer_to()` 和 `owner()` 变为 O(1) 原子操作
3. 注册表简化为仅跟踪 RRef 存在性
4. 崩溃恢复使用延迟清理策略

**预期收益**：
- 所有权转移性能提升 ~16x（80ns → 5ns）
- 所有者查询性能提升 ~20x（60ns → 3ns）
- 整体 vsock 吞吐量提升 ~10-20%

**风险**：
- RRef 结构体增大 8 bytes（可接受）
- 崩溃恢复逻辑需要重新设计（中等复杂度）

### 与 RedLeaf 的关键差异

| 方面 | RedLeaf | 我们的方案 C |
|------|---------|-------------|
| 内存布局 | 3个独立指针 | 内联 AtomicU64 |
| unsafe 使用 | 大量 | 无 |
| 类型注册 | 需要 DropMap | 不需要 |
| 崩溃清理 | 立即+类型特定 | 延迟+通用 |
| 复杂度 | 高 | 中 |

我们的方案保留了 RedLeaf 的核心优化（内联 owner），同时避免了其复杂性（unsafe、类型注册、自定义分配器）。

---

## 8. FrameVsock 通信优化

### 8.1 当前 FrameVsock 架构分析

```
┌─────────────────────────────────────────────────────────────┐
│                    Host Kernel (Asterinas)                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  FrameVsockSocket (kernel/src/net/socket/framevsock)│   │
│  │  - Connected state with RX/TX queues                │   │
│  │  - Credit-based flow control                        │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            ↕ RRef<DataPacket> 零拷贝传输
┌─────────────────────────────────────────────────────────────┐
│                    FrameVisor (Hypervisor)                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  vsock.rs - 包路由和分发                             │   │
│  │  - submit_data_packet() (Guest → Host)              │   │
│  │  - deliver_data_packet() (Host → Guest)             │   │
│  │  - Direct dispatch + IHT fallback                   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            ↕ RRef<DataPacket> 零拷贝传输
┌─────────────────────────────────────────────────────────────┐
│                    FrameVM (Guest)                          │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  FrameVsockSocket (framevm/src/vsock/socket.rs)     │   │
│  │  - pending_data_packets: VecDeque<RRef<DataPacket>> │   │
│  │  - Atomic flow control counters                     │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 8.2 当前实现的优点

1. **零拷贝数据传输**：`RRef<DataPacket>` 在域间传递时不复制数据
2. **Credit-based 流控**：防止接收方被淹没
3. **自适应阈值**：根据平均包大小动态调整 credit update 频率
4. **中断合并**：`GUEST_RX_PROCESSING` 标志减少冗余中断
5. **Direct Dispatch**：Host 直接调用 Guest handler，避免 IHT 队列开销

### 8.3 潜在优化点

#### 8.3.1 DataPacket 池化

当前每个数据包都创建新的 `Vec<u8>` 和 `RRef`，高吞吐场景下分配开销显著。

```rust
// kernel/comps/framevsock/src/pool.rs

use alloc::vec::Vec;
use spin::Mutex;

/// Pre-allocated packet pool for high-throughput scenarios
pub struct DataPacketPool {
    /// Pool of reusable Vec<u8> buffers
    buffers: Mutex<Vec<Vec<u8>>>,
    /// Default buffer capacity
    buffer_capacity: usize,
    /// Maximum pool size
    max_pool_size: usize,
}

impl DataPacketPool {
    pub fn new(buffer_capacity: usize, max_pool_size: usize) -> Self {
        Self {
            buffers: Mutex::new(Vec::with_capacity(max_pool_size)),
            buffer_capacity,
            max_pool_size,
        }
    }

    /// Acquire a buffer from pool or allocate new one
    #[inline]
    pub fn acquire(&self) -> Vec<u8> {
        self.buffers
            .lock()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(self.buffer_capacity))
    }

    /// Return buffer to pool for reuse
    #[inline]
    pub fn release(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        let mut pool = self.buffers.lock();
        if pool.len() < self.max_pool_size {
            pool.push(buffer);
        }
        // Otherwise drop the buffer
    }
}

/// Global packet pool (per-CPU for better locality)
pub static PACKET_POOL: Lazy<DataPacketPool> =
    Lazy::new(|| DataPacketPool::new(64 * 1024, 1024));
```

**使用方式**：

```rust
// 发送时
pub fn create_data_packet_pooled(
    src_cid: u64,
    src_port: u32,
    dst_cid: u64,
    dst_port: u32,
    data: &[u8],
) -> RRef<DataPacket> {
    let mut buffer = PACKET_POOL.acquire();
    buffer.extend_from_slice(data);
    RRef::new(DataPacket::new_rw(src_cid, dst_cid, src_port, dst_port, buffer))
}

// 接收完成后
pub fn recycle_packet(packet: DataPacket) {
    PACKET_POOL.release(packet.data);
}
```

#### 8.3.2 批量包处理

当前每个包单独处理，可以批量处理减少锁获取次数。

```rust
// kernel/comps/framevm/src/vsock/socket.rs

impl FrameVsockSocket {
    /// Batch receive - process multiple packets at once
    pub fn recv_batch(&self, bufs: &mut [&mut [u8]]) -> Vec<usize> {
        let mut results = Vec::with_capacity(bufs.len());
        let mut packets = self.pending_data_packets.lock();

        for buf in bufs.iter_mut() {
            if let Some(packet) = packets.pop_front() {
                let data = packet.get().payload();
                let len = core::cmp::min(data.len(), buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                results.push(len);

                // Update flow control
                self.fwd_cnt.fetch_add(len as u32, Ordering::Relaxed);
            } else {
                break;
            }
        }

        // Single credit update for entire batch
        if !results.is_empty() {
            self.maybe_send_credit_update();
        }

        results
    }
}
```

#### 8.3.3 无锁 RX 队列

当前 `pending_data_packets` 使用 `Mutex<VecDeque>`，可以改用无锁队列。

```rust
use crossbeam_queue::ArrayQueue;

pub struct FrameVsockSocket {
    /// Lock-free RX queue for better concurrency
    pending_data_packets: ArrayQueue<RRef<DataPacket>>,
    // ... other fields
}

impl FrameVsockSocket {
    pub fn new() -> Self {
        Self {
            pending_data_packets: ArrayQueue::new(flow_control::MAX_PENDING_PACKETS),
            // ...
        }
    }

    /// Push packet to RX queue (called by IRQ handler)
    #[inline]
    pub fn push_rx_packet(&self, packet: RRef<DataPacket>) -> Result<(), RRef<DataPacket>> {
        self.pending_data_packets.push(packet)
    }

    /// Pop packet from RX queue (called by recv syscall)
    #[inline]
    pub fn pop_rx_packet(&self) -> Option<RRef<DataPacket>> {
        self.pending_data_packets.pop()
    }
}
```

#### 8.3.4 Credit Update 优化

当前 credit update 可能过于频繁或过于稀疏，可以使用更智能的策略。

```rust
impl FrameVsockSocket {
    /// Intelligent credit update decision
    fn should_send_credit_update(&self) -> bool {
        let fwd_cnt = self.fwd_cnt.load(Ordering::Relaxed);
        let last_update = self.last_credit_update_fwd_cnt.load(Ordering::Relaxed);
        let consumed = fwd_cnt.wrapping_sub(last_update);

        let threshold = self.credit_update_threshold.load(Ordering::Relaxed);
        let buf_alloc = self.buf_alloc.load(Ordering::Relaxed);

        // Strategy 1: Consumed enough data
        if consumed >= threshold {
            return true;
        }

        // Strategy 2: Peer might be stalled (low credit watermark)
        let peer_fwd_cnt = self.peer_fwd_cnt.load(Ordering::Relaxed);
        let peer_buf_alloc = self.peer_buf_alloc.load(Ordering::Relaxed);
        let peer_available = peer_buf_alloc.saturating_sub(
            self.tx_cnt.load(Ordering::Relaxed).wrapping_sub(peer_fwd_cnt)
        );

        if peer_available < flow_control::low_credit_watermark(peer_buf_alloc) {
            return true;
        }

        // Strategy 3: Receiver has waiters (low latency mode)
        if self.recv_waiters.load(Ordering::Relaxed) > 0 && consumed > 0 {
            return true;
        }

        false
    }
}
```

### 8.4 性能优化总结

| 优化项 | 当前状态 | 优化后 | 预期提升 |
|--------|----------|--------|----------|
| **RRef 所有权转移** | HashMap 查表 | 内联 AtomicU64 | ~16x |
| **DataPacket 分配** | 每次 new | 池化复用 | ~3x |
| **RX 队列** | Mutex<VecDeque> | ArrayQueue | ~2x |
| **批量处理** | 单包处理 | 批量 recv | ~1.5x |
| **Credit Update** | 固定阈值 | 自适应+智能 | ~1.2x |

**综合预期**：vsock 吞吐量提升 30-50%

---

## 9. 实现优先级建议

### 高优先级（立即实施）

1. **内联 owner 到 RRef**（方案 C Phase 1）
   - 改动小，收益大
   - 不影响现有 API
   - 预期：所有权转移 16x 提升

2. **移除废弃的借用计数接口**
   - 清理代码
   - 减少维护负担

### 中优先级（短期实施）

3. **DataPacket 池化**
   - 减少分配开销
   - 对高吞吐场景收益明显

4. **简化注册表**（方案 C Phase 2）
   - 移除 owner 存储
   - 仅跟踪 RRef 存在性

### 低优先级（长期考虑）

5. **无锁 RX 队列**
   - 需要引入外部 crate
   - 收益取决于并发程度

6. **批量包处理**
   - 需要修改 syscall 接口
   - 对特定工作负载有效

---

## 10. 附录：关键文件索引

| 组件 | 文件路径 | 职责 |
|------|----------|------|
| **RRef 定义** | `kernel/comps/framevisor/exchangeable/src/lib.rs` | RRef 结构、Exchangeable trait |
| **注册表** | `kernel/comps/framevisor/src/rref_registry.rs` | 所有权跟踪、崩溃恢复 |
| **Vsock 协议** | `kernel/comps/framevsock/src/lib.rs` | 包结构、流控配置 |
| **Host Socket** | `kernel/src/net/socket/framevsock/stream/connected.rs` | Host 端连接状态 |
| **Guest Socket** | `kernel/comps/framevm/src/vsock/socket.rs` | Guest 端 socket 实现 |
| **包路由** | `kernel/comps/framevisor/src/vsock.rs` | 域间包分发 |
| **IHT** | `kernel/comps/framevisor/src/iht.rs` | 中断处理任务 |
