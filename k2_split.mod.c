#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

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
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0xdc301cbc, "elv_rb_del" },
	{ 0xc001a0a6, "elv_rqhash_del" },
	{ 0xc9e30214, "elv_rb_add" },
	{ 0x874c24ea, "elv_rb_find" },
	{ 0x73fddd94, "elv_bio_merge_ok" },
	{ 0x37a0cba, "kfree" },
	{ 0x8123c88d, "elv_unregister" },
	{ 0x6ca443d2, "elevator_alloc" },
	{ 0x38e9c18a, "kmalloc_caches" },
	{ 0x8d088cd7, "kmalloc_node_trace" },
	{ 0x1c0dd58c, "kobject_put" },
	{ 0xf10cfabd, "blk_mq_run_hw_queues" },
	{ 0x65487097, "__x86_indirect_thunk_rax" },
	{ 0x956408e8, "bio_split_rw" },
	{ 0xb43f9365, "ktime_get" },
	{ 0xce938121, "bio_chain" },
	{ 0x6cb4b05a, "blk_mq_get_new_requests" },
	{ 0x7983155e, "blk_mq_bio_to_request" },
	{ 0xc4926d2a, "elv_rqhash_add" },
	{ 0x3780833b, "__tracepoint_block_rq_insert" },
	{ 0x5a5a2271, "__cpu_online_mask" },
	{ 0x85bfc5f9, "__SCT__tp_func_block_rq_insert" },
	{ 0x688e72e1, "__SCT__preempt_schedule_notrace" },
	{ 0xdb4df9ec, "bio_set_ioprio" },
	{ 0x1e7f4e27, "__SCK__tp_func_block_rq_insert" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x254acf86, "pcpu_hot" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0x3b6c41ea, "kstrtouint" },
	{ 0x34db050b, "_raw_spin_lock_irqsave" },
	{ 0xd35cce70, "_raw_spin_unlock_irqrestore" },
	{ 0x122c3a7e, "_printk" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0xa4a73418, "elv_register" },
	{ 0x248522c0, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "5D22BDE03C902A59D840C2B");
