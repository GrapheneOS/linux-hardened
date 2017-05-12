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

#define TPE_GLOBAL_UID(x) from_kuid_munged(&init_user_ns, (x))
#define TPE_GLOBAL_GID(x) from_kgid_munged(&init_user_ns, (x))
#define tpe_is_global_root(x) uid_eq((x), GLOBAL_ROOT_UID)
#define tpe_is_global_nonroot(x) (!uid_eq((x), GLOBAL_ROOT_UID))
#define tpe_is_global_nonroot_gid(x) (!gid_eq((x), GLOBAL_ROOT_GID))

int security_tpe = IS_ENABLED(CONFIG_SECURITY_TPE);
kgid_t security_tpe_gid = KGIDT_INIT(CONFIG_SECURITY_TPE_GID);
int security_tpe_all = IS_ENABLED(CONFIG_SECURITY_TPE_ALL);
int security_tpe_invert = IS_ENABLED(CONFIG_SECURITY_TPE_INVERT);

int tpe_allow(const struct file *file)
{
	struct inode *inode = d_backing_inode(file->f_path.dentry->d_parent);
	struct inode *file_inode = d_backing_inode(file->f_path.dentry);
	const struct cred *cred = current_cred();
	char *msg = NULL;
	char *msg2 = NULL;

	// never restrict root
	if (tpe_is_global_root(cred->uid))
		return 1;

	if (security_tpe) {
		if (security_tpe_invert && !in_group_p(security_tpe_gid))
			msg = "not being in trusted group";
		else if (!security_tpe_invert && in_group_p(security_tpe_gid))
			msg = "being in untrusted group";
	}

	// not in any affected group/role
	if (!msg)
		goto next_check;

	if (tpe_is_global_nonroot(inode->i_uid))
		msg2 = "file in non-root-owned directory";
	else if (inode->i_mode & S_IWOTH)
		msg2 = "file in world-writable directory";
	else if ((inode->i_mode & S_IWGRP) && tpe_is_global_nonroot_gid(inode->i_gid))
		msg2 = "file in group-writable directory";
	else if (file_inode->i_mode & S_IWOTH)
		msg2 = "file is world-writable";

	if (msg && msg2) {
		char fullmsg[70] = {0};
		snprintf(fullmsg, sizeof(fullmsg)-1, "%s and %s", msg, msg2);
		pr_warn_ratelimited("TPE: %s\n",fullmsg);
		return 0;
	}
	msg = NULL;
next_check:
	if (!security_tpe || !security_tpe_all)
		return 1;

	if (tpe_is_global_nonroot(inode->i_uid) && !uid_eq(inode->i_uid, cred->uid))
		msg = "directory not owned by user";
	else if (inode->i_mode & S_IWOTH)
		msg = "file in world-writable directory";
	else if ((inode->i_mode & S_IWGRP) && tpe_is_global_nonroot_gid(inode->i_gid))
		msg = "file in group-writable directory";
	else if (file_inode->i_mode & S_IWOTH)
		msg = "file is world-writable";

	if (msg) {
		pr_warn_ratelimited("TPE: %s\n",msg);
		return 0;
	}
	return 1;
}
