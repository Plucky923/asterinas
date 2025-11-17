# 符号文件生成

multiboot2协议，在进入ostd时，elf文件已经由grub加载到内存中了，所以不好在启动后再解析ELF文件了。
需要在bootload将这些文件的信息传递过去，然后在ostd中进行符号的解析



在osdk中修改，将target/osdk/iso_root下的aster-nix-osdk-bin直接拷贝为额外的模块文件.bin并随镜像一起打包，并在GRUB配置中附带`type=kernel-bin`与`name=<文件名>`参数，方便在ostd启动阶段解析模块名称；initramfs模块则带有`type=initramfs`标识。

# 符号表初始化与维护

对于.text .rodata .data .bss都是虚拟地址可以正常维护
对于.tbss .tdata就比较麻烦
对于.cls也一样
这些需要正确的处理


# 符号维护

有些符号没有被使用到
