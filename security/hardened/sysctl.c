#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sysctl.h>
#include <linux/hardened.h>
#include <linux/hardened_internal.h>

struct ctl_table hardened_table[] = {
#ifdef CONFIG_HARDENED_BRUTE
        {
                .procname       = "deter_bruteforce",
                .data           = &hardened_enable_brute,
                .maxlen         = sizeof(int),
                .mode           = 0600,
                .proc_handler   = &proc_dointvec,
        },
#endif
	{ }
};
