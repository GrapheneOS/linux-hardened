#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/coredump.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/hardened.h>
#include <linux/hardened_internal.h>
#include <linux/hardirq.h>
#include <asm/pgtable.h>

char *signames[] = {
	[SIGSEGV] = "Segmentation fault",
	[SIGILL] = "Illegal instruction",
	[SIGABRT] = "Abort",
	[SIGBUS] = "Invalid alignment/Bus error"
};

/* NOTE: replace this with new logging eventually
void
gr_log_signal(const int sig, const void *addr, const struct task_struct *t)
{
#ifdef CONFIG_GRKERNSEC_SIGNAL
	if (grsec_enable_signal && ((sig == SIGSEGV) || (sig == SIGILL) ||
				    (sig == SIGABRT) || (sig == SIGBUS))) {
		if (task_pid_nr(t) == task_pid_nr(current)) {
			gr_log_sig_addr(GR_DONT_AUDIT_GOOD, GR_UNISIGLOG_MSG, signames[sig], addr);
		} else {
			gr_log_sig_task(GR_DONT_AUDIT_GOOD, GR_DUALSIGLOG_MSG, t, sig);
		}
	}
#endif
	return;
}
*/

#ifdef CONFIG_HARDENED
extern int specific_send_sig_info(int sig, struct siginfo *info, struct task_struct *t);

int fake_force_sig(int sig, struct task_struct *t)
{
	unsigned long int flags;
	int ret, blocked, ignored;
	struct k_sigaction *action;

	spin_lock_irqsave(&t->sighand->siglock, flags);
	action = &t->sighand->action[sig-1];
	ignored = action->sa.sa_handler == SIG_IGN;
	blocked = sigismember(&t->blocked, sig);
	if (blocked || ignored) {
		action->sa.sa_handler = SIG_DFL;
		if (blocked) {
			sigdelset(&t->blocked, sig);
			recalc_sigpending_and_wake(t);
		}
	}
	if (action->sa.sa_handler == SIG_DFL)
		t->signal->flags &= ~SIGNAL_UNKILLABLE;
	ret = specific_send_sig_info(sig, SEND_SIG_PRIV, t);

	spin_unlock_irqrestore(&t->sighand->siglock, flags);

	return ret;
}
#endif

#define USER_BAN_TIME (15 * 60)
#define DAEMON_BRUTE_TIME (30 * 60)

void handle_brute_attach(int dumpable)
{
#ifdef CONFIG_HARDENED_BRUTE
	struct task_struct *p = current;
	kuid_t uid = GLOBAL_ROOT_UID;
	int is_priv = 0;
	int daemon = 0;

	if (!hardened_enable_brute)
		return;

	if (is_privileged_binary(p->mm->exe_file->f_path.dentry))
		is_priv = 1;

	rcu_read_lock();
	read_lock(&tasklist_lock);
	read_lock(&hardened_exec_file_lock);
	if (!is_priv && p->real_parent && is_same_file(p->real_parent->exec_file, p->exec_file)) {
		p->real_parent->brute_expires = get_seconds() + DAEMON_BRUTE_TIME;
		p->real_parent->brute = 1;
		daemon = 1;
	} else {
		const struct cred *cred = __task_cred(p), *cred2;
		struct task_struct *tsk, *tsk2;

		if (dumpable != SUID_DUMP_USER && is_global_nonroot(cred->uid)) {
			struct user_struct *user;

			uid = cred->uid;

			/* this is put upon execution past expiration */
			user = find_user(uid);
			if (user == NULL)
				goto unlock;
			user->sugid_banned = 1;
			user->sugid_ban_expires = get_seconds() + USER_BAN_TIME;
			if (user->sugid_ban_expires == ~0UL)
				user->sugid_ban_expires--;

			/* only kill other threads of the same binary, from the same user */
			do_each_thread(tsk2, tsk) {
				cred2 = __task_cred(tsk);
				if (tsk != p && uid_eq(cred2->uid, uid) && is_same_file(tsk->exec_file, p->exec_file))
					fake_force_sig(SIGKILL, tsk);
			} while_each_thread(tsk2, tsk);
		}
	}
unlock:
	read_unlock(&hardened_exec_file_lock);
	read_unlock(&tasklist_lock);
	rcu_read_unlock();

	/* NOTE: replace this logging logic since we didn't extract the grsec logging functions
	if (is_global_nonroot(uid))
		gr_log_fs_int2(GR_DONT_AUDIT, GR_BRUTE_SUID_MSG, p->exec_file->f_path.dentry, p->exec_file->f_path.mnt, GR_GLOBAL_UID(uid), GR_USER_BAN_TIME / 60);
	else if (daemon)
		gr_log_noargs(GR_DONT_AUDIT, GR_BRUTE_DAEMON_MSG);
	*/
#endif
	return;
}

void handle_brute_check(void)
{
#ifdef CONFIG_HARDENED_BRUTE
	struct task_struct *p = current;

	if (unlikely(p->brute)) {
		if (!hardened_enable_brute)
			p->brute = 0;
		else if (time_before(get_seconds(), p->brute_expires))
			msleep(30 * 1000);
	}
#endif
	return;
}

void handle_kernel_exploit(void)
{
#ifdef CONFIG_HARDENED_KERN_LOCKOUT
	static unsigned int num_banned_users __read_only;
	const struct cred *cred;
	struct task_struct *tsk, *tsk2;
	struct user_struct *user;
	kuid_t uid;

	if (in_irq() || in_serving_softirq() || in_nmi())
		panic("brute force detection: halting the system due to suspicious kernel crash caused in interrupt context");

	uid = current_uid();

	if (is_global_root(uid))
		panic("brute force detection: halting the system due to suspicious kernel crash caused by root");
	else {
		//pax_open_kernel();
		num_banned_users++;
		//pax_close_kernel();
		if (num_banned_users > 8)
			panic("brute force detection: halting the system due to suspicious kernel crash caused by a large number of different users");

		/* kill all the processes of this user, hold a reference
		   to their creds struct, and prevent them from creating
		   another process until system reset
		*/

		printk(KERN_ALERT "brute force detection: banning user with uid %u until system restart for suspicious kernel crash\n",
			GR_GLOBAL_UID(uid));
			
		/* we intentionally leak this ref */
		user = get_uid(current->cred->user);
		if (user)
			user->kernel_banned = 1;

		/* kill all processes of this user */
		read_lock(&tasklist_lock);
		do_each_thread(tsk2, tsk) {
			cred = __task_cred(tsk);
			if (uid_eq(cred->uid, uid))
				fake_force_sig(SIGKILL, tsk);
		} while_each_thread(tsk2, tsk);
		read_unlock(&tasklist_lock); 
	}
#endif
}

#ifdef CONFIG_HARDENED_BRUTE
static bool sugid_ban_expired(struct user_struct *user)
{
	if (user->sugid_ban_expires != ~0UL && time_after_eq(get_seconds(), user->sugid_ban_expires)) {
		user->sugid_banned = 0;
		user->sugid_ban_expires = 0;
		free_uid(user);
		return true;
	}

	return false;
}
#endif

int process_kernel_exec_ban(void)
{
#ifdef CONFIG_HARDENED_KERN_LOCKOUT
	if (unlikely(current->cred->user->kernel_banned))
		return -EPERM;
#endif
	return 0;
}

int process_kernel_setuid_ban(struct user_struct *user)
{
#ifdef CONFIG_HARDENED_KERN_LOCKOUT
	if (unlikely(user->kernel_banned))
		fake_force_sig(SIGKILL, current);
#endif
	return 0;
}

int process_sugid_exec_ban(const struct linux_binprm *bprm)
{
#ifdef CONFIG_HARDENED_BRUTE
	struct user_struct *user = current->cred->user;
	if (unlikely(user->sugid_banned)) {
		if (sugid_ban_expired(user))
			return 0;
		/* disallow execution of suid/sgid binaries only */
		else if (is_privileged_binary(bprm->file->f_path.dentry))
			return -EPERM;
	}
#endif
	return 0;
}

int check_user_change(kuid_t real, kuid_t effective, kuid_t fs)
{
#if defined(CONFIG_HARDENED_KERN_LOCKOUT)    
	// NOTE: commenting out unused variables associated with code in skipit: section below
	//unsigned int i;
        //__u16 num;
        //uid_t *uidlist;
        //uid_t curuid;
        //int realok = 0;
        //int effectiveok = 0;
        //int fsok = 0;
        uid_t globalreal;//, globaleffective, globalfs;

        struct user_struct *user;

        if (!uid_valid(real))
                goto skipit;

        /* find user based on global namespace */

        globalreal = GR_GLOBAL_UID(real);

        user = find_user(make_kuid(&init_user_ns, globalreal));
        if (user == NULL)
                goto skipit;

        if (process_kernel_setuid_ban(user)) {
                /* for find_user */
                free_uid(user);
                return 1;
        }

        /* for find_user */
        free_uid(user);

skipit:
#endif
	// if you re-enable some of the below code remove this return
	return 0;
	/* NOTE: below is not part of the BRUTE code so for now commenting out
	if (unlikely(!(gr_status & GR_READY)))
                return 0;

        if (current->acl->mode & (GR_LEARN | GR_INHERITLEARN))
                gr_log_learn_uid_change(real, effective, fs);

        num = current->acl->user_trans_num;
        uidlist = current->acl->user_transitions;

        if (uidlist == NULL)
                return 0;

        if (!uid_valid(real)) {
                realok = 1;
                globalreal = (uid_t)-1;
        } else {
                globalreal = GR_GLOBAL_UID(real);
        }
        if (!uid_valid(effective)) {
                effectiveok = 1;
                globaleffective = (uid_t)-1;
        } else {
                globaleffective = GR_GLOBAL_UID(effective);
        }
        if (!uid_valid(fs)) {
                fsok = 1;
                globalfs = (uid_t)-1;
        } else {
                globalfs = GR_GLOBAL_UID(fs);
        }

        if (current->acl->user_trans_type & GR_ID_ALLOW) {
                for (i = 0; i < num; i++) {
                        curuid = uidlist[i];
                        if (globalreal == curuid)
                                realok = 1;
                        if (globaleffective == curuid)
                                effectiveok = 1;
                        if (globalfs == curuid)
                                fsok = 1;
                }
        } else if (current->acl->user_trans_type & GR_ID_DENY) {
                for (i = 0; i < num; i++) {
                        curuid = uidlist[i];
                        if (globalreal == curuid)
                                break;
                        if (globaleffective == curuid)
                                break;
                        if (globalfs == curuid)
                                break;
                }
                
                if (i == num) {
                        realok = 1;
                        effectiveok = 1;
                        fsok = 1;
                }
        }

        if (realok && effectiveok && fsok)
                return 0;
        else {
                gr_log_int(GR_DONT_AUDIT, GR_USRCHANGE_ACL_MSG, realok ? (effectiveok ? (fsok ? 0 : globalfs) : globaleffective) : globalreal);
                return 1;
        }
	*/
}
