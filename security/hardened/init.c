#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/percpu.h>
#include <linux/module.h>

int hardened_enable_brute;

/*
DEFINE_SPINLOCK(hardened_alert_lock);
unsigned long hardened_alert_wtime = 0;
unsigned long hardened_alert_fyet = 0;

DEFINE_SPINLOCK(hardened_audit_lock);
*/

DEFINE_RWLOCK(hardened_exec_file_lock);

void __init
hardened_init(void)
{
#ifdef CONFIG_HARDENED_BRUTE
        hardened_enable_brute = 1;
#endif
	return;
}
