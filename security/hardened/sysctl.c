#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sysctl.h>
#include <linux/hardened.h>
#include <linux/hardened_internal.h>

struct ctl_table hardened_table[] = {
#ifdef CONFIG_HARDENED_CHROOT
#ifdef CONFIG_GRKERNSEC_CHROOT_SHMAT
	{
		.procname	= "chroot_deny_shmat",
		.data		= &grsec_hardened_enable_chroot_shmat,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_UNIX
	{
		.procname	= "chroot_deny_unix",
		.data		= &grsec_hardened_enable_chroot_unix,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_MOUNT
	{
		.procname	= "chroot_deny_mount",
		.data		= &grsec_hardened_enable_chroot_mount,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_FCHDIR
	{
		.procname	= "chroot_deny_fchdir",
		.data		= &grsec_hardened_enable_chroot_fchdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_DOUBLE
	{
		.procname	= "chroot_deny_chroot",
		.data		= &grsec_hardened_enable_chroot_double,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_PIVOT
	{
		.procname	= "chroot_deny_pivot",
		.data		= &grsec_hardened_enable_chroot_pivot,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CHDIR
	{
		.procname	= "chroot_enforce_chdir",
		.data		= &grsec_hardened_enable_chroot_chdir,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CHMOD
	{
		.procname	= "chroot_deny_chmod",
		.data		= &grsec_hardened_enable_chroot_chmod,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_MKNOD
	{
		.procname	= "chroot_deny_mknod",
		.data		= &grsec_hardened_enable_chroot_mknod,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_NICE
	{
		.procname	= "chroot_restrict_nice",
		.data		= &grsec_hardened_enable_chroot_nice,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_CAPS
	{
		.procname	= "chroot_caps",
		.data		= &grsec_hardened_enable_chroot_caps,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_RENAME
	{
		.procname	= "chroot_deny_bad_rename",
		.data		= &grsec_hardened_enable_chroot_rename,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_SYSCTL
	{
		.procname	= "chroot_deny_sysctl",
		.data		= &grsec_hardened_enable_chroot_sysctl,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
#ifdef CONFIG_GRKERNSEC_CHROOT_FINDTASK
	{
		.procname	= "chroot_findtask",
		.data		= &grsec_hardened_enable_chroot_findtask,
		.maxlen		= sizeof(int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_secure,
	},
#endif
	{ }
};
#endif
