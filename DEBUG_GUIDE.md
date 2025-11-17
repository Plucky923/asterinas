# Asterinas GDB 调试指南

## 在 framevisor::mm::vm_space::VmSpace::new 处打断点

### 方法 1：使用文件名和行号（最简单）

```gdb
# 在 GDB 中执行
hbreak kernel/comps/framevisor/src/mm/vm_space.rs:10
continue
```

### 方法 2：查找函数符号后设置断点

```gdb
# 查找函数符号
info functions framevisor.*VmSpace.*new

# 或者使用正则表达式查找
rbreak framevisor.*VmSpace.*new

# 找到符号后，使用完整路径设置断点
hbreak framevisor::mm::vm_space::VmSpace::new
```

### 方法 3：在调用该函数的地方打断点

```gdb
# 在 init_vm_space 函数处打断点
hbreak framevisor::mm::vm_space::init_vm_space
continue
# 然后单步进入
step
```

## 处理 GDB 卡住的情况

### 1. 立即中断并检查状态

```gdb
# 按 Ctrl+C 中断执行
# 然后执行：
bt                    # 查看调用栈
info registers        # 查看寄存器状态
x/10i $pc            # 查看当前执行的指令
frame                # 查看当前帧信息
list                 # 查看当前代码
```

### 2. 检查是否在等待或死循环

```gdb
# 查看调用栈，检查是否有等待函数
bt

# 如果看到类似这些函数，说明可能在等待：
# - spin loop
# - interrupt wait
# - lock acquire
# - I/O operation

# 查看当前指令是否在循环
x/20i $pc-40         # 查看前后 20 条指令
```

### 3. 使用条件断点避免卡住

```gdb
# 在关键位置设置条件断点，而不是直接 continue
hbreak framevisor::mm::vm_space::VmSpace::new
condition 1 $pc == 0x<address>  # 只在特定地址触发
continue
```

### 4. 单步调试而不是 continue

```gdb
# 不要直接 continue，而是：
step                 # 单步进入函数
next                 # 单步跳过函数
finish              # 执行到函数返回

# 或者设置多个断点
hbreak framevisor::mm::vm_space::VmSpace::new
hbreak ostd::mm::VmSpace::new
continue            # 会停在第一个断点
continue            # 会停在第二个断点
```

### 5. 检查是否有 panic 或异常

```gdb
# 查看是否有 panic 处理
info breakpoints
info signals

# 如果程序真的卡死，可能需要：
# 1. 重启 gdb server (make gdb_server)
# 2. 检查 QEMU 日志 (cat qemu.log)
# 3. 检查是否有内核 panic
```

## 完整的调试流程

### 启动调试会话

```bash
# 终端 1：启动 GDB server
cd /home/plucky/asterinas
make gdb_server

# 终端 2：启动 GDB client
cd /home/plucky/asterinas
make gdb_client
```

### 在 GDB 中设置断点

```gdb
# 连接到远程目标后
(gdb) target remote :1234

# 设置断点（使用硬件断点，因为启用了 KVM）
(gdb) hbreak kernel/comps/framevisor/src/mm/vm_space.rs:10

# 或者使用函数名
(gdb) hbreak framevisor::mm::vm_space::VmSpace::new

# 继续执行到断点
(gdb) continue
```

### 调试技巧

```gdb
# 查看变量
(gdb) print vmspace
(gdb) print self
(gdb) info locals
(gdb) info args

# 查看调用栈
(gdb) bt
(gdb) bt full          # 显示所有局部变量

# 查看源代码
(gdb) list
(gdb) list 10,20       # 查看第 10-20 行

# 单步执行
(gdb) step             # 进入函数
(gdb) next             # 跳过函数
(gdb) finish           # 执行到函数返回

# 查看内存
(gdb) x/10x $rsp       # 查看栈内容
(gdb) x/10i $pc        # 查看当前指令
```

## 常见问题

### Q: GDB 在 continue 后卡住怎么办？

A: 
1. 按 `Ctrl+C` 中断
2. 执行 `bt` 查看调用栈
3. 检查是否在等待中断或锁
4. 使用断点而不是 continue
5. 检查 QEMU 日志：`tail -f qemu.log`

### Q: 断点不生效？

A:
- 确保使用 `hbreak` 而不是 `break`（KVM 环境需要硬件断点）
- 检查符号是否正确：`info functions <function_name>`
- 确保代码已经被加载：`info files`

### Q: 找不到符号？

A:
- 确保使用 debug 模式编译（不要用 `RELEASE=1`）
- 检查符号表：`info variables framevisor`
- 使用正则表达式查找：`rbreak framevisor.*`

### Q: 如何调试 framevm 代码？

A:
- framevm 是动态加载的，需要在内核加载 framevm 后设置断点
- 可以在 `kernel/src/vmm/mod.rs` 的 `load_framevm` 函数处打断点
- 然后在内核加载 framevm 后，再在 framevm 代码中设置断点

## 参考

- [OSDK Debug 文档](book/src/osdk/reference/commands/debug.md)
- Makefile 中的 `gdb_server` 和 `gdb_client` 目标

