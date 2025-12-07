#include <linux/module.h>
#include <linux/export-internal.h>
#include <linux/compiler.h>

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



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xec52cd88, "nf_unregister_net_hook" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x96848186, "scnprintf" },
	{ 0xba8fbd64, "_raw_spin_lock" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xb5b54b34, "_raw_spin_unlock" },
	{ 0x619cb7dd, "simple_read_from_buffer" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xbe06a47e, "skb_copy_bits" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xf45c3f31, "proc_create" },
	{ 0x92997ed8, "_printk" },
	{ 0x9ae026d4, "init_net" },
	{ 0xdc67c7d9, "nf_register_net_hook" },
	{ 0x666e61e9, "remove_proc_entry" },
	{ 0xbf1981cb, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "A8D49B7218A7C0924CDF500");
