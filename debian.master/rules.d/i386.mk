human_arch	= 32 bit x86
build_arch	= i386
header_arch	= x86_64
asm_link	= x86
defconfig	= defconfig
flavours        = generic generic-pae virtual
build_image	= bzImage
kernel_file	= arch/$(build_arch)/boot/bzImage
install_file	= vmlinuz
loader		= grub
no_dumpfile	= true
