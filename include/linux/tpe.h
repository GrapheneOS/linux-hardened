/*
 *  linux/fs/tpe.h
 *
 */

extern int security_tpe;
extern kgid_t security_tpe_gid;
extern int security_tpe_all;
extern int security_tpe_invert;
extern int tpe_allow(const struct file *file);
