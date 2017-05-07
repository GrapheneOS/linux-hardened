#ifndef HARDENED_H
#define HARDENED_H
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/binfmts.h>
#include <linux/tty.h>

#define BRUTE_DAEMON_MSG "bruteforce prevention initiated for the next 30 minutes or until service restarted, stalling each fork 30 seconds.  Please investigate the crash report for "
#define BRUTE_SUID_MSG "bruteforce prevention initiated due to crash of %.950s against uid %u, banning suid/sgid execs for %u minutes.  Please investigate the crash report for "

void handle_brute_attach(int dumpable);
void handle_brute_check(void);
void handle_kernel_exploit(void);
int handle_signal(const struct task_struct *p, const int sig);


int pid_is_chrooted(struct task_struct *p);
int handle_chroot_fowner(struct pid *pid, enum pid_type type);
int handle_chroot_nice(void);
int handle_chroot_sysctl(const int op);
int handle_chroot_setpriority(struct task_struct *p,
					const int niceval);
int chroot_fchdir(struct dentry *u_dentry, struct vfsmount *u_mnt);
int chroot_pathat(int dfd, struct dentry *u_dentry, struct vfsmount *u_mnt, unsigned flags);
int chroot_fhandle(void);
int handle_chroot_chroot(const struct dentry *dentry,
				   const struct vfsmount *mnt);
void handle_chroot_chdir(const struct path *path);
int handle_chroot_chmod(const struct dentry *dentry,
				  const struct vfsmount *mnt, const int mode);
int handle_chroot_mknod(const struct dentry *dentry,
				  const struct vfsmount *mnt, const int mode);
int handle_chroot_mount(const struct dentry *dentry,
				  const struct vfsmount *mnt,
				  const char *dev_name);
int handle_chroot_pivot(void);
int handle_chroot_unix(const pid_t pid);

void set_chroot_entries(struct task_struct *task, const struct path *path);
void clear_chroot_entries(struct task_struct *task);
int chroot_is_capable(const int cap);
int task_chroot_is_capable(const struct task_struct *task, const struct cred *cred, const int cap);
void inc_chroot_refcnts(struct dentry *dentry, struct vfsmount *mnt);
void dec_chroot_refcnts(struct dentry *dentry, struct vfsmount *mnt);
int bad_chroot_rename(struct dentry *olddentry, struct vfsmount *oldmnt,
			 struct dentry *newdentry, struct vfsmount *newmnt);

#ifdef CONFIG_HARDENED_CHROOT_FINDTASK
extern int hardened_enable_chroot_findtask;
#endif

#endif
