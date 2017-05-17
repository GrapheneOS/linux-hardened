/*
 *  linux/fs/tpe.c
 *
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/uidgid.h>
#include <linux/tpe.h>
#include <linux/ratelimit.h>
#include <linux/limits.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/slab.h>

#define TPE_GLOBAL_UID(x) from_kuid_munged(&init_user_ns, (x))
#define TPE_GLOBAL_GID(x) from_kgid_munged(&init_user_ns, (x))
#define tpe_is_global_root(x) uid_eq((x), GLOBAL_ROOT_UID)
#define tpe_is_global_nonroot(x) (!uid_eq((x), GLOBAL_ROOT_UID))
#define tpe_is_global_nonroot_gid(x) (!gid_eq((x), GLOBAL_ROOT_GID))

int security_tpe = IS_ENABLED(CONFIG_SECURITY_TPE);
kgid_t security_tpe_gid = KGIDT_INIT(CONFIG_SECURITY_TPE_GID);
int security_tpe_all = IS_ENABLED(CONFIG_SECURITY_TPE_ALL);
int security_tpe_invert = IS_ENABLED(CONFIG_SECURITY_TPE_INVERT);

int print_tpe_error(const struct file *file, char *reason1, char *reason2)
{
	char *filepath = kmalloc(PATH_MAX+1, GFP_KERNEL);
	char error_msg[90] = {0};

	if (!reason1)
		kfree(filepath);
		return 0;

	if (reason2)
		snprintf(error_msg, sizeof(error_msg), "%s and %s", reason1, reason2);
	else
		strncpy(error_msg, reason1, sizeof(error_msg));
	
	filepath = dentry_path_raw(file->f_path.dentry, filepath, PATH_MAX-1);

	pr_warn_ratelimited("TPE: Denied execution of %s Reason: %s\n",
		(IS_ERR(filepath) ? "failed fetching file path" : filepath),
		error_msg
	);
	kfree(filepath);
	return 1;

}

int tpe_allow(const struct file *file)
{
	struct inode *inode = d_backing_inode(file->f_path.dentry->d_parent);
	struct inode *file_inode = d_backing_inode(file->f_path.dentry);
	const struct cred *cred = current_cred();
	char *reason1 = NULL;
	char *reason2 = NULL;

	//TPE is disabled
	if (!security_tpe)
		return 1;

	// never restrict root
	if (tpe_is_global_root(cred->uid))
		return 1;

	// Check for tpe_all
	if (!security_tpe_all)
		goto general_tpe_check;

	// TPE_ALL: These restrictions are enforced even if the gid is trusted
	if (tpe_is_global_nonroot(inode->i_uid) && !uid_eq(inode->i_uid, cred->uid))
		reason1 = "directory not owned by user";
	else if (inode->i_mode & S_IWOTH)
		reason1 = "file in world-writable directory";
	else if ((inode->i_mode & S_IWGRP) && tpe_is_global_nonroot_gid(inode->i_gid))
		reason1 = "file in group-writable directory";
	else if (file_inode->i_mode & S_IWOTH)
		reason1 = "file is world-writable";

	if (reason1)
		goto end;

general_tpe_check:
	// determine if group is trusted
	if (security_tpe_invert && !in_group_p(security_tpe_gid))
		reason2 = "not in trusted group";
	else if (!security_tpe_invert && in_group_p(security_tpe_gid))
		reason2 = "in untrusted group";
	else
		return 1;

	// main TPE checks
	if (tpe_is_global_nonroot(inode->i_uid))
		reason1 = "file in non-root-owned directory";
	else if (inode->i_mode & S_IWOTH)
		reason1 = "file in world-writable directory";
	else if ((inode->i_mode & S_IWGRP) && tpe_is_global_nonroot_gid(inode->i_gid))
		reason1 = "file in group-writable directory";
	else if (file_inode->i_mode & S_IWOTH)
		reason1 = "file is world-writable";

end:
	if (reason1) {
		print_tpe_error(file, reason1, reason2);
		return 0;
	} else {
		return 1;
	}
}
