#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
};

static const struct modversion_info ____versions[]
__attribute_used__
__attribute__((section("__versions"))) = {
	{ 0x89e24b9c, "struct_module" },
	{ 0x2da418b5, "copy_to_user" },
	{ 0x8235805b, "memmove" },
	{ 0xf2a644fb, "copy_from_user" },
	{ 0x79b6ef38, "find_task_by_pid_type" },
	{ 0x72270e35, "do_gettimeofday" },
	{ 0x1d26aa98, "sprintf" },
	{ 0x19070091, "kmem_cache_alloc" },
	{ 0xab978df6, "malloc_sizes" },
	{ 0x37a0cba, "kfree" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0x98e2f2c2, "filp_close" },
	{ 0xa9399fb9, "filp_open" },
	{ 0x25da070, "snprintf" },
	{ 0x1e6d26a8, "strstr" },
	{ 0xe987619e, "proc_net" },
};

static const char __module_depends[]
__attribute_used__
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "15FBB984D721E696BEE9D6C");
