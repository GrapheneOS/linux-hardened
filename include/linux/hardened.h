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
int check_user_change(kuid_t real, kuid_t effective, kuid_t fs);

#endif
