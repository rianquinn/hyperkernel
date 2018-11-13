#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xe8aad16f, "module_layout" },
	{ 0xa043880c, "alloc_pages_current" },
	{ 0xbc5cde86, "kmalloc_caches" },
	{ 0xdf0f75c6, "eventfd_signal" },
	{ 0xa6093a32, "mutex_unlock" },
	{ 0x41598ced, "irq_create_mapping" },
	{ 0x4629334c, "__preempt_count" },
	{ 0x79a77cc5, "handle_edge_irq" },
	{ 0xb44ad4b3, "_copy_to_user" },
	{ 0x47093710, "misc_register" },
	{ 0x955a832f, "___preempt_schedule" },
	{ 0x706c5a65, "preempt_count_sub" },
	{ 0xb18fc00, "current_task" },
	{ 0x9a76f11f, "__mutex_init" },
	{ 0x27e1a049, "printk" },
	{ 0xd67364f7, "eventfd_ctx_fdget" },
	{ 0xc917e655, "debug_smp_processor_id" },
	{ 0x4c9d28b0, "phys_base" },
	{ 0x41aed6e7, "mutex_lock" },
	{ 0x9a7d0cd4, "irq_get_irq_data" },
	{ 0x2072ee9b, "request_threaded_irq" },
	{ 0xf84313f, "cpu_bit_bitmap" },
	{ 0x7cd8d75e, "page_offset_base" },
	{ 0xb2fd5ceb, "__put_user_4" },
	{ 0xdb7305a1, "__stack_chk_fail" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x8c7d81de, "kmem_cache_alloc_trace" },
	{ 0x4302d0eb, "free_pages" },
	{ 0xbbac0a4b, "x86_vector_domain" },
	{ 0x37a0cba, "kfree" },
	{ 0x2c7db649, "irq_dispose_mapping" },
	{ 0x941f2aaa, "eventfd_ctx_put" },
	{ 0xf229424a, "preempt_count_add" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x1c9866e1, "misc_deregister" },
	{ 0xc1514a3b, "free_irq" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "F25D25C048CE989A67D1BE4");
