#ifndef __HARDENED_INTERNAL_H
#define __HARDENED_INTERNAL_H

#ifdef CONFIG_HARDENED

#include <linux/fs.h>
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>

void hardened_handle_alertkill(struct task_struct *task);
char *hardened_to_filename(const struct dentry *dentry,
			    const struct vfsmount *mnt);
char *hardened_to_filename1(const struct dentry *dentry,
			    const struct vfsmount *mnt);
char *hardened_to_filename2(const struct dentry *dentry,
			    const struct vfsmount *mnt);
char *hardened_to_filename3(const struct dentry *dentry,
			    const struct vfsmount *mnt);

extern int hardened_enable_brute;

extern rwlock_t hardened_exec_file_lock;

#define hardened_task_fullpath(tsk) ((tsk)->exec_file ? \
			hardened_to_filename2((tsk)->exec_file->f_path.dentry, \
			(tsk)->exec_file->f_path.mnt) : "/")

#define hardened_parent_task_fullpath(tsk) ((tsk)->real_parent->exec_file ? \
			hardened_to_filename3((tsk)->real_parent->exec_file->f_path.dentry, \
			(tsk)->real_parent->exec_file->f_path.mnt) : "/")

#define hardened_task_fullpath0(tsk) ((tsk)->exec_file ? \
			hardened_to_filename((tsk)->exec_file->f_path.dentry, \
			(tsk)->exec_file->f_path.mnt) : "/")

#define hardened_parent_task_fullpath0(tsk) ((tsk)->real_parent->exec_file ? \
			hardened_to_filename1((tsk)->real_parent->exec_file->f_path.dentry, \
			(tsk)->real_parent->exec_file->f_path.mnt) : "/")

#define proc_is_chrooted(tsk_a)  ((tsk_a)->is_chrooted)

#define have_same_root(tsk_a,tsk_b) ((tsk_a)->chroot_dentry == (tsk_b)->chroot_dentry)

static inline bool is_same_file(const struct file *file1, const struct file *file2)
{
	if (file1 && file2) {
		const struct inode *inode1 = file1->f_path.dentry->d_inode;
		const struct inode *inode2 = file2->f_path.dentry->d_inode;
		if (inode1->i_ino == inode2->i_ino && inode1->i_sb->s_dev == inode2->i_sb->s_dev)
			return true;
	}

	return false;
}

#endif

#endif
