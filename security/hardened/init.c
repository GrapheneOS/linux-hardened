#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/percpu.h>
#include <linux/module.h>

int hardened_enable_chroot_findtask;
int hardened_enable_chroot_mount;
int hardened_enable_chroot_shmat;
int hardened_enable_chroot_fchdir;
int hardened_enable_chroot_double;
int hardened_enable_chroot_pivot;
int hardened_enable_chroot_chdir;
int hardened_enable_chroot_chmod;
int hardened_enable_chroot_mknod;
int hardened_enable_chroot_nice;
int hardened_enable_chroot_execlog;
int hardened_enable_chroot_caps;
int hardened_enable_chroot_rename;
int hardened_enable_chroot_sysctl;
int hardened_enable_chroot_unix;

/*
DEFINE_SPINLOCK(hardened_alert_lock);
unsigned long hardened_alert_wtime = 0;
unsigned long hardened_alert_fyet = 0;

DEFINE_SPINLOCK(hardened_audit_lock);

DEFINE_RWLOCK(hardened_exec_file_lock);
*/

void __init
hardened_init(void)
{
#ifdef CONFIG_HARDENED_CHROOT_FINDTASK
	hardened_enable_chroot_findtask = 1;
#endif
#ifdef CONFIG_HARDENED_CHROOT_UNIX
	hardened_enable_chroot_unix = 1;
#endif
#ifdef CONFIG_HARDENED_CHROOT_MOUNT
	hardened_enable_chroot_mount = 1;
#endif
#ifdef CONFIG_HARDENED_CHROOT_FCHDIR
	hardened_enable_chroot_fchdir = 1;
#endif
#ifdef CONFIG_HARDENED_CHROOT_SHMAT
	hardened_enable_chroot_shmat = 1;
#endif
#ifdef CONFIG_HARDENED_AUDIT_PTRACE
	hardened_enable_audit_ptrace = 1;
#endif
#ifdef CONFIG_HARDENED_CHROOT_DOUBLE
	hardened_enable_chroot_double = 1;
#endif
#ifdef CONFIG_HARDENED_CHROOT_PIVOT
	hardened_enable_chroot_pivot = 1;
#endif
#ifdef CONFIG_HARDENED_CHROOT_CHDIR
	hardened_enable_chroot_chdir = 1;
#endif
#ifdef CONFIG_HARDENED_CHROOT_CHMOD
	hardened_enable_chroot_chmod = 1;
#endif
#ifdef CONFIG_HARDENED_CHROOT_MKNOD
	hardened_enable_chroot_mknod = 1;
#endif
#ifdef CONFIG_HARDENED_CHROOT_NICE
	hardened_enable_chroot_nice = 1;
#endif
#ifdef CONFIG_HARDENED_CHROOT_CAPS
	hardened_enable_chroot_caps = 1;
#endif
#ifdef CONFIG_HARDENED_CHROOT_RENAME
	hardened_enable_chroot_rename = 1;
#endif
#ifdef CONFIG_HARDENED_CHROOT_SYSCTL
	hardened_enable_chroot_sysctl = 1;
#endif
	return;
}
