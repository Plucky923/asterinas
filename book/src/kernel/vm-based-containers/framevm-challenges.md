# FrameVM 的核心设计挑战与机制

FrameVM 的出发点是将资源抽象与隔离机制分离。它为 CPU、memory 和 device
组织一组可重新提供的基本资源契约：一个系统层可以消费这些契约，并向上
提供上层系统所依赖的同类接口，而不要求所有设备共享同一种 payload
representation。这种可嵌套结构使租户隔离不必侵入 Guest 的每个内核子系统：
Guest 仍然使用 kernel-shaped 资源接口，而资源仲裁、所有权检查和生命周期
控制可以留在一个独立的软件层中。由于这一层和 Guest 都由安全语言实现，
同步 fast path 可以在共享地址空间中通过普通函数调用低开销交互，而不必
强制经历地址空间切换；需要跨异步边界转移所有权的路径仍显式执行必要的
copy 或 handoff。

然而，接口可以被重新提供，并不意味着接口的语义天然可以被嵌套。
传统内核接口通常假设系统中只有一个内核、一个资源所有者和一个确定的
“当前执行上下文”，因而不会显式携带这些信息。把同一套接口放入多个
共享同一地址空间的系统层以后，这些隐含假设分别表现为三个问题：一次
阻塞或唤醒究竟应改变哪个调度域的状态，一个看似全局的 allocator 或
CPU-local 对象究竟属于哪个 VM，以及一个在调用返回后仍可能完成的设备
操作究竟还持有哪一代资源的权限。安全语言可以防止悬垂指针和非法别名，
却不能自动判断“类型正确的对象是否属于正确的 VM”或者“类型正确的回调
是否仍属于当前运行代”。因此，FrameVM 真正需要解决的不是重新设计三套
资源 API，而是在不污染这些 API 的前提下，把它们原本隐含的 execution
context、resource provenance 和 asynchronous lifetime 显式化。

## 挑战一：在两个调度域之间保持同步语义一致

一个 kernel-shaped Guest 不只是若干可由 Host 独立调度的线程。Guest 拥有
自己的 scheduler、wait queue、preemption 和 interrupt 语义，而 Host 又必须
把整个 VM 作为租户进行调度和计费。于是，同一次同步操作会同时改变两个
状态机：当 Guest 任务阻塞时，它必须从 Guest 的内层 run queue 中消失，其
Host backing task 也必须停止消耗物理 CPU；当另一个任务唤醒它时，内层任务
必须重新变为 runnable，对应的 Host 调度实体也必须恰好被激活一次。虚拟
中断使问题进一步复杂化：即使没有普通 Guest 任务可运行，只要存在可投递的
中断或必须完成的退出工作，该 vCPU 对 Host 而言仍然具有可推进工作。反过来，
一个已经 pending 但仍被虚拟 IRQ mask 阻塞的中断，又不能被错误地当作立即
可执行的工作。

几种直观方案都会破坏一侧的语义。把每个 Guest 任务直接摊平为 Host 调度
实体，会使 Guest 的调度策略失去控制，并让租户份额随内部线程数量变化；
只把 vCPU 当作不透明 Host 线程，则会隐藏阻塞、唤醒和中断造成的 runnable
变化，容易造成空转或丢失唤醒；让 Guest 的 wait queue 直接使用 Host 唤醒
路径，又可能绕过内层 scheduler，甚至把任务重新发布到错误的 VM 或 vCPU。
难点因而不是再实现一个 hierarchical scheduler，而是组合两个各自完整的
调度与同步状态机，同时保持唯一的资源计费点和可验证的状态转换。

FrameVM 为此提出 **scheduler-coherent vCPU groups**。每个 vCPU 由一个
`FrameSchedGroup` 作为 Host 可见的调度实体，VM 的所有 vCPU 再归入一个聚合
`TaskGroup`。Host 在 `TaskGroup` 层聚合租户的 share 和 accounting，在
`FrameSchedGroup` 层执行各 vCPU 的 placement 与外层选择；Guest scheduler
则继续拥有普通 service task 的内层选择策略。每个 group 从普通任务、可投递
虚拟中断和生命周期工作中派生一个无副作用的 runnable predicate，而不把
Guest 的完整 run queue 暴露给 Host。一次 blocking operation 通过两级
park/wake bridge 同时连接 Guest task、Host backing task 和 group 的外层
runnable transition；Host queue membership 保持幂等，内层 enqueue 则区分
普通 wake 与已经经过 Host bridge 的 wake，避免同一次事件被镜像两次。所有
跨层路径使用稳定的
`FrameVcpuId = (VmId, vcpu_index)`，因此任务绑定、虚拟中断和最终 outer
refresh 都以目标对象的归属为准，而不是依据发起者的 ambient context 或
当前物理 CPU 猜测归属。

这一组合还必须保持同步原语本身的算法语义。带 preemption 或 virtual-IRQ
guardian 的 `SpinLock`/`RwLock` 只用于短临界区，绝不能在 guard 内 park；
可能阻塞的 `Mutex`/`RwMutex` 则必须进入两级 wait/wake bridge，并在睡眠前
释放所有 spinning guard。相同的 API 名称并不能替代这一实现合同，否则一个
在单体内核中正确的 blocking primitive 可能在嵌套调度域中退化为 busy wait
甚至死锁。

这一机制的关键抽象不是“Host 能否看见 Guest 的每个线程”，而是“Host 是否
能可靠判断一个 vCPU 是否拥有能够推进系统状态的工作”。它要建立两条可证伪
的性质：任意执行任务都满足 `binding(task) = (VmId, vcpu_index)`，且一个 VM
的聚合 share 只应用一次，不随 Guest 内部线程或 vCPU 数量隐式放大；
interrupt-handler work 也必须计入所属 group。两级 bridge 的完整正确性还
要求用 cross-VM wake、cross-vCPU wake、stale-generation wake、park/release
race 和 stop-with-waiters 覆盖 lost wakeup 与重复 outer membership。因而，
FrameVM 在这里的贡献不是一般意义上的层次化调度，而是一套隐藏 Guest task
structure、同时组合 scheduler、blocking synchronization、virtual interrupt
和 tenant accounting 的 runnable-state protocol。

## 挑战二：在隐式全局接口之下恢复 VM-relative 资源归属

第二个挑战并不只是“为每个 VM 实现一个 allocator”。真正的困难是，OSTD
原有接口并不显式携带资源域：全局 allocator getter 返回
`&'static dyn GlobalFrameAllocator`，`cpu_local!` 展开为一个全局静态声明，
而 `Frame` 和 `Segment` 的析构路径通常只拿到地址与布局。这些接口在单体
内核中是自洽的，因为系统只有一个 allocator、一个 CPU namespace 和一个
最终释放者；在 FrameVM 中，同一份 OSTD 代码却被多个 Guest 在同一地址空间
中调用。于是，实现必须在保持 Guest-visible API shape、也不让 Guest 到处
传递 `VmId` 的前提下回答三个不同问题：本次调用应由哪个资源域处理，构造
过程中何时把物理资源转交给新对象，以及原调用上下文消失以后谁仍有权释放
它。换言之，FrameVM 必须把一个隐式全局的接口转换为 context-selected domain，
原子地转移 ownership，并让 provenance 活得比原 context 更久；memory/type
safety 本身并不编码 tenant ownership。

几个看似直接的实现都不成立。全局 registry 至多能根据 key 找到一个
allocator object，却不能证明本次调用有权使用它，还会在 `FrameVm` 之外形成
第二套 ownership 与 teardown authority；用“当前 VM”作 key 可以完成同步
allocation，却无法处理在 idle worker、延迟回调或 VM stop 期间发生的
contextless drop；按地址查询 owner table 又不能覆盖尚未 publication 的半构造
对象，也不能证明 provider 的私有 cache 已经排空。更危险的是，在上下文缺失
或 custom provider 出错时退回 Host allocator：这会让同一对象由一个域分配、
另一个域释放，把本应 fail-closed 的错误变成跨 VM free。CPU-local 也有同样
的问题：若把 vCPU index 直接解释为物理 CPU index，vCPU migration 会改变
对象含义；共享 service image 中的同一静态声明也会被多个 VM 解释为同一份
storage。

FrameVM 为此提出 **VM-relative resource domains**，并将一次资源操作拆成
三种互补的归属证明：**execution context 选择 provider，transaction 转移
resource ownership，persistent provenance 在 execution context 消失后验证
delayed release**。静态接口本身只是 selector，而不是 owner；owner table
只是 provenance index，而不是凭地址即可释放资源的 authority。每个 VM
分别拥有 `MemoryDomain`、`FrameVmAllocator` 和 `CpuLocalDomain`：前者是 quota
与生命周期的 admission authority，第二个封装该 VM 的 allocation policy，
第三个为同一静态 CPU-local 声明提供 VM-relative 的解释。这样，Guest 仍然
看到原来的 OSTD-shaped 接口，而 owner identity 只在 FrameVisor 的边界内
出现。

保持全局 allocator API shape 本身就带来一个 bootstrap 难题。返回值具有
`'static` 生命周期，因此 getter 不能临时返回一个借用自当前 VM 的 allocator；另一
方面，custom provider 的 trait object 和代码位于 Guest image 中，而装载这个
image 又已经需要分配 frame。FrameVM 使用一个固定的 `'static` dispatch
object 作为 ABI trampoline：调用到达以后，它才从当前 service-task binding
解析目标 VM，并转发到相应 provider。allocation/reallocation 会创建新的资源
归属，因此在缺少 FrameVM context 时直接失败，而不猜测
Host/default domain；释放与 idle notification 则可以在无上下文时通过
provenance 恢复原 owner。装载阶段先由 FrameVisor 控制的 bootstrap backing
映射 Guest image，检查并记录其中导出的 provider cell，最后才把该 provider
发布给 dispatch path。对于 Rust heap，装载器只有在确认 image 明确导出了
custom heap provider 后，才把 alloc、dealloc 与 realloc 这一组配对入口一起
切换到 FrameVM dispatch，避免一个对象的分配与释放落入不同 allocator。这个
顺序打破了“必须先调用 provider 才能装载 provider”的循环依赖，也划定了当前
原型的覆盖范围：VM-relative memory guarantee 覆盖 OSTD `Frame`/`Segment`
以及显式 opt-in 的 custom heap；默认 Rust `Box`/`Vec` 仍使用共享 heap，尚未
计入 `MemoryDomain` 的物理配额与 provenance。完整 heap accounting 需要完成
cross-boundary heap audit，并把成对切换 allocator 变成强制合同。

一次 frame allocation 也远不是一次函数调用。以 built-in service
`Frame`/`Segment` 路径为例，它跨越 quota reservation、Host backing 建立、
typed object 构造和 owner publication；任何一步都可能失败，而且失败次序会
决定谁负责回收。FrameVM 因此连接两个独立的事务边界。quota transaction
先增加 `reserved_v`，成功建立 backing 后才转为 `charged_v`，从而始终保持
`charged_v + reserved_v <= limit_v`；custody transaction 则先把 raw extent
标为 unpublished，只有 typed object 完整构造且 owner adoption 成功以后才
发布唯一 owner。这里最棘手的是 `Segment` 的部分构造：若第 `k` 个 frame
构造失败，OSTD 会自动 drop 已构造的前缀，而外层事务仍负责回滚整段 raw
extent。若两条路径都把自己当作 cleanup owner，就会 double free 或 double
uncharge；若都等待对方，又会泄漏。FrameVM 在构造期间登记 unpublished
extent，并记录已经尝试构造到哪一页。当构造失败时，OSTD 已经清理成功构造
的 prefix；外层 rollback 根据 attempted-page count 只把仍为 raw allocation
的 suffix 归还 Host，并恰好一次撤销整段 domain charge，而不能再次 deallocate
整个 extent。unpublished state 标记 custody 尚未发布，防止中途 drop 被误解
为正常的 owner release；它不能替代上述 prefix/suffix rollback 规则。当前
direct typed service helper 只允许能够给出这一证明的 built-in provider；
custom frame provider 会被拒绝，而不是套用一个不安全的通用 rollback。
reservation 因而只保证容量记账，unpublished construction state 和精确的
partial rollback 才把记账事务与对象构造事务接合起来；三者缺一都不能宣称
allocation 是原子的。

custom allocator 走的是另一条更难的事务路径，因为 memory safety 并不等于
allocator semantic correctness。一个安全 Rust provider 仍可能返回未对齐、
越界、重叠或属于另一个 VM 的 range，也可能在
`add_free_memory`/acceptance callback 中保留 backing 的 clone。FrameVM 因而
只把 **policy** 委托给 provider，而不委托 **physical authority**：新增
backing 先经 `MemoryDomain` admission，由 Host 建立并清零，再作为有边界的 grant
交给该 provider；provider 返回 range 后，FrameVisor 重新检查完整 extent 的
layout、grant membership 和当前 ownership，再执行 callback 与 owner adoption，
不能因 custom path 失败而 fallback 到 Host path。一个尤其容易被忽略的失败点
是：provider callback 已经接受并保留了 grant，但随后的 owner adoption 又因
并发冲突失败。此时 FrameVisor 已无法证明 grant 仍可安全收回，盲目 rollback
可能造成 use-after-free。实现只能锁存 provider fault 并 retain/quarantine
这段 ambiguous custody，而不能用“重试”掩盖协议破坏。换言之，built-in path
解决 partial construction，custom path 解决 opaque policy；二者共享 quota、
ownership 和 fail-closed invariants，但不是一条虚构的通用事务路径。

allocation 与 deallocation 的证据也天然不对称。allocation 发生在 service
调用中，可以用当前 `(VmId, vcpu_index)` 选择 provider；一个对象的最后一次
drop 却可能发生在原 task 已退出、VM 正在 drain，甚至执行者属于另一个 VM
的时候。FrameVM 因此在资源逃逸 fast path 前记录 extent、owner VM、domain
和 generation 等持久 provenance。deallocation 若有当前 VM，仍须先验证目标
extent 确属该 domain；若当前上下文已经不存在，才通过 provenance index 找回
唯一 owner。错误上下文至多导致操作 fail closed 和资源保留，不能授权释放
兄弟 VM 的 extent；完全未知的地址也绝不能作为 Host raw allocation 直接
free。这里的关键不是“有一张全局表”，而是 release authority 必须由原
`MemoryDomain` 与 provider 的状态共同验证，地址只用于查找证明。

CPU-local storage 是同一问题的另一种表现。共享地址空间中，每个
`cpu_local!` 声明在链接层面只有一个静态 identity，但它在语义上必须产生
`VM 数量 × vCPU 数量` 份互不共享的对象。FrameVM 把该静态对象降为 declaration
handle，并用稳定 key 与当前 `(VmId, vcpu_index)` 在对应 `CpuLocalDomain` 中
查找 entry；entry 第一次访问时在锁内唯一创建，随后执行 checked downcast，
再索引创建 VM 时固定大小的 vCPU slot。这样，同一 vCPU 迁移到另一物理 CPU
不会改变 CPU-local identity，不同 VM 使用同一声明也不会共享状态。缺失 VM
或越界 vCPU 都是错误，不能回退到 Host CPU-local 或单槽默认对象。

最后，provider 和 CPU-local 的析构又形成一个反向的 unload 循环：它们的
trait-object vtable、drop glue 以及私有 metadata 可能都位于 Guest image 中；
但只有执行这些析构代码以后，FrameVisor 才知道 image 是否可以卸载。先卸载
image 会让随后的 callback/drop 跳入未映射代码，先无条件归还 backing 则可能
释放仍在 provider cache 中的 extent。FrameVM 的 teardown 顺序因此是关闭新
allocation 与新执行，排空 task、IRQ 和 callback，停用 resource domains，在
image 仍映射时取出并析构可证明已经 quiescent 的 CPU-local 与 built-in
allocator state，最后才尝试卸载 image。取出 type-erased CPU-local map 时只在
锁内转移 ownership，实际 drop 在解锁后执行，避免未知析构代码在 spinlock 下
重入。对于 custom provider，当前实现还不存在成功的 closure proof：只要一个
image 安装过 custom frame 或 heap provider，FrameVM 就保守地保留 provider
cells、image 及相关 backing；重复 teardown 本身也不能证明 opaque cache 已经
清空。原因是当前 OSTD contract 尚无通用的 provider-wide shutdown/revoke
callback。这一 fail-safe retention 保持了隔离安全，但不保证资源回收的
liveness；要支持任意 custom allocator 的完整回收，接口还必须提供可验证的
closure boundary。

因此，这一机制并非 per-VM allocator、quota、owner table 与 CPU-local map 的
简单拼装。它拆开了传统内核隐式合并的三个事实——调用选择、资源 ownership
与延迟释放权限——并用 `context -> transaction -> provenance` 在它们之间建立
可验证的转换。在上述 FrameVM-managed surface 内，其核心性质是：每个
published allocation 恰好计入一个 VM；每个 physical extent 至多有一个 live
owner，且 release 不单独依赖 ambient context；CPU-local identity 由
`(VM, vCPU)` 决定，不随 Host CPU migration 改变。逐阶段 fault injection、
`Segment` 第 `k` 页构造失败、重复 range adoption、无/错误上下文 drop 与
opaque provider 阻止 image unload，分别检验这些性质在异常路径上仍成立。
FrameVM 的贡献因此不是首先提出 per-domain allocation 或语言安全的资源隔离，
而是在不显式携带 VM identity 的 kernel-shaped 接口背后，把 provider selection、
physical ownership、delayed release 与 vCPU-local identity 组合成同一套
VM-relative protocol。

## 挑战三：使异步设备权限具有可组合的时间边界

设备虚拟化的困难不在于为 Guest 提供几个读写函数，而在于一个逻辑 I/O 的
authority 可能逃逸发起它的调用。异步 backend 可以继续持有 buffer、DMA
mapping 或 completion，Host 也可以在 Guest 没有主动调用时产生 console、
network、socket callback 或 virtual interrupt。与此同时，VM 可以 stop、
reset 或 restart，同一个虚拟 BDF 也可能在下一代运行中被重新使用。于是，
一个内存安全且类型正确的 completion 仍可能属于旧 generation；如果它在新
VM runtime 中触发 callback 或 IRQ，安全语言并不会自动把它识别为越权操作。

完整硬件模拟可以重新建立传统 VM 的隔离边界，但会引入 legacy device state、
trap 和 descriptor translation；把 Host device object 直接交给 Guest 又会
泄露 BAR、DMA 或 interrupt authority。另一个诱人的方案是为所有设备设计
统一的 request ring、resource wrapper 和 completion framework。通用 ring
本身可以支持零拷贝，但它会向隔离层暴露通用 descriptor 或 address，并要求
隔离层重新验证、追踪和回收其 ownership；而 console、RNG、block、network
和 socket 的 ownership direction、buffer lifetime 与错误语义并不相同。
强行统一 payload representation 会把真正需要共享的 generation、admission
和 revocation 语义隐藏在泛化框架之下。

FrameVM 因此提出 **generation-scoped typed I/O capabilities**，并把设备模型
划分为统一的 control plane 与 family-specific data plane。每个 VM 拥有私有
virtual PCI control plane，负责 discovery、BDF、configuration、BAR layout、
MSI-X state 和 route selection；service 在 probe 后获得一个不可随意复制的
`FunctionClaim`。对于 direct call，monotonic claim ID 把 VM、BDF、device
family 和当前 function instance 绑定为一次可检查的权限；对于异步 event，
generation check 进一步阻止旧运行代重新进入。真正的数据操作保持类型化并
由各 family 自己定义：console output 和 RNG 使用有界同步借用，console input
使用有界的 owned state，block 使用方向明确且生命周期受限的 scatter/gather
cursor，network 可以转移 owned receive buffer，Sock 则在需要跨域时显式复制
到 shared exchange carrier，并在 pre-publication failure 上返还原 packet。
PCI 统一的是身份、claim 和中断路由，而不是把所有 payload 强制编码为同一种
descriptor。

这个 claim 同时是时间上的权限。每次调用先进入 function runtime 的
admission gate，并增加 active-call 引用；Host-to-Guest 事件先发布 family-owned
state，再设置 MSI-X pending state 和唤醒对应 interrupt handler。stop 首先
撤销 claim、关闭新调用和新事件的 admission，然后在不持有 spinlock 的情况
下排空 active calls、retained buffers、callbacks 和 interrupt requests，最后
才允许释放 synthetic backend 或卸载 service image。restart 产生新的
generation，所有旧 claim、event 和 completion 在边界检查处失效，即使 BDF
和内存地址恰好被复用也不能重新获得权限。Mediated PCI passthrough 是独立的
data plane：它可以复用原生设备协议，但还必须在同一 owner-and-generation
原则下排空 DMA reference，并完成 configuration、IOMMU 和 IRQ revocation。

这一机制避免把 FrameV 的贡献表述为“又一套 paravirtual device”。它真正
解决的是共享地址空间中的 temporal authority：一个操作不仅必须在类型上
匹配某类设备，还必须证明自己属于正确的 VM、正确的 function 和仍然存活的
generation。其可证伪性质是 foreign 或 stale claim 在接触 family backend
之前被拒绝，任何 Host notification 都满足 publish-before-notify。类型化
family contract 允许各设备选择合适的 borrowing、ownership transfer 或显式
copy，并在真实所有权允许时避免通用 descriptor translation 和不必要复制；
统一的 claim/admission/drain 协议则为异步路径提供可验证的撤销边界。

## 统一原则：owner-scoped admission–drain

这三个挑战分别出现在 execution、ownership 和 lifetime 三个维度，却共享
同一个根因：
传统内核接口把资源归属和生命周期蕴含在唯一内核的运行环境中，而可嵌套
接口只复制了 API shape，没有复制这些隐含语义。FrameVM 将它们统一为一个
owner-scoped admission–drain protocol：资源或操作首先绑定到明确的 owner；
只有当 identity 可能复用且旧工作可能残留时，才额外绑定 epoch。系统只在
owner 的 admission 开放时接纳新工作；停止时先关闭 admission，再排空已经
接纳的 task、reservation、device call、callback 和 interrupt；只有在这些
引用全部消失以后，才释放资源，并在需要时以新 epoch 复用 identity。其抽象
顺序可以概括为：

```text
Bind(owner [, epoch]) -> Admit -> Close -> Drain -> Release
```

这个协议也要求区分两种 quiescence 证明。`Stopped` 证明 service execution
和新 admission 已经终止，但不谎称所有 opaque memory ownership 都已消失；
只有单独的 destroyability check 证明 memory、device、DMA 和 provider
authority 均已排空以后，资源才能归还 Host 或交给另一个 owner。若某个
opaque provider、DMA reference 或旧 generation callback 无法被证明已经关闭，
已经停止的 VM 仍须 retain 或 quarantine 相应资源。这样，资源接口可以保持
稳定、Guest 策略可以继续位于安全语言实现的上层，而隔离所需的 owner、
provenance、epoch 和 drain 逻辑被集中在独立且可审计的中间层中。

## 与已有工作的关系

[Fluke (OSDI '96)](https://www.usenix.org/legacy/publications/library/proceedings/osdi96/hibler.html)
展示了递归虚拟化和由上层重新提供系统抽象的可能性；
[Bascule (EuroSys '13)](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/bascule_eurosys13.pdf)
进一步探索了共享地址空间中的可嵌套系统接口；
[CPU Inheritance Scheduling (OSDI '96)](https://www.usenix.org/legacy/publications/library/proceedings/osdi96/ford.html)
说明了阻塞依赖与调度上下文必须协同传播；
[Alta/K0 (USENIX ATC '00)](https://users.cs.utah.edu/flux/papers/javaos-usenix00.pdf)
说明了安全语言的 memory safety 并不自动提供资源隔离，并在单一 managed
runtime 中探索了 per-domain static state、heap accounting 和 hierarchical
scheduling；
[Xen (SOSP '03)](https://www.cl.cam.ac.uk/research/srg/netos/papers/2003-xensosp.pdf)
则证明了 paravirtualized interface 可以显著降低传统设备虚拟化成本。
FrameVM 不把 nestable interface、安全语言单地址空间隔离、hierarchical
scheduling、per-tenant allocator 或 paravirtual I/O 本身作为首次贡献。它的
增量在于一个更具体的组合问题：当 Asterinas-derived safe-Rust、kernel-shaped
系统层在共享地址空间中消费并重新提供以 physical memory、CPU-local state
和异步 device operation 为基础的资源接口时，如何在不把租户隔离逻辑扩散
到 Guest API 的前提下，使接口背后的 execution context、resource provenance
和 temporal authority 同样可嵌套、可撤销并可验证。

因此，FrameVM 的三个机制不是彼此独立的工程补丁。scheduler-coherent vCPU
groups 使执行上下文可组合，VM-scoped resource-provider domains 使全局资源
状态具有明确归属，generation-scoped typed I/O capabilities 使异步权限具有
时间边界；owner-scoped admission–drain protocol 则把三者收敛为同一个
隔离原则。FrameVM 的核心贡献正是让系统层不仅能够重新提供相同形状的资源
接口，而且能够重新提供这些接口原本依赖却从未显式表达的隔离语义。
