#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xe09a23a6, "module_layout" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0xf5b859cf, "unregister_ftrace_function" },
	{ 0xc5850110, "printk" },
	{ 0xcaea29b0, "register_ftrace_function" },
	{ 0xa8ea4dd0, "ftrace_set_filter_ip" },
	{ 0xe3fffae9, "__x86_indirect_thunk_rbp" },
	{ 0x7f7b1cfd, "unregister_kprobe" },
	{ 0x9d447e54, "register_kprobe" },
	{ 0xbdfb6dbb, "__fentry__" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "D0DBE5F1DEF179F7B51E27C");
