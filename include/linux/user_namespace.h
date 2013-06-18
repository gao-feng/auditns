#ifndef _LINUX_USER_NAMESPACE_H
#define _LINUX_USER_NAMESPACE_H

#include <linux/kref.h>
#include <linux/nsproxy.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <linux/skbuff.h>

#define UID_GID_MAP_MAX_EXTENTS 5

struct uid_gid_map {	/* 64 bytes -- 1 cache line */
	u32 nr_extents;
	struct uid_gid_extent {
		u32 first;
		u32 lower_first;
		u32 count;
	} extent[UID_GID_MAP_MAX_EXTENTS];
};

#ifdef CONFIG_AUDIT
struct audit_ctrl {
	struct sock		*sock;
	int			initialized;
	int			enabled;
	int			pid;
	int			portid;
	struct sk_buff_head	queue;
	struct sk_buff_head	hold_queue;
	struct task_struct	*kauditd_task;
	wait_queue_head_t	kauditd_wait;
	bool			ever_enabled;
};
#endif

struct user_namespace {
	struct uid_gid_map	uid_map;
	struct uid_gid_map	gid_map;
	struct uid_gid_map	projid_map;
	atomic_t		count;
	struct user_namespace	*parent;
	kuid_t			owner;
	kgid_t			group;
	unsigned int		proc_inum;
#ifdef CONFIG_AUDIT
	struct audit_ctrl	audit;
#endif
	bool			may_mount_sysfs;
	bool			may_mount_proc;
};

extern struct user_namespace init_user_ns;

#ifdef CONFIG_USER_NS

static inline struct user_namespace *get_user_ns(struct user_namespace *ns)
{
	if (ns)
		atomic_inc(&ns->count);
	return ns;
}

extern int create_user_ns(struct cred *new);
extern int unshare_userns(unsigned long unshare_flags, struct cred **new_cred);
extern void free_user_ns(struct user_namespace *ns);

static inline void put_user_ns(struct user_namespace *ns)
{
	if (ns) {
		if (atomic_dec_and_test(&ns->count)) {
			free_user_ns(ns);
		} else if (atomic_read(&ns->count) == 1) {
			/* If the last user of this userns is kauditd,
			 * we should wake up the kauditd and let it kill
			 * itself, Then this userns will be destroyed.*/
			if (ns->audit.kauditd_task)
				wake_up_process(ns->audit.kauditd_task);
		}
	}
}

struct seq_operations;
extern struct seq_operations proc_uid_seq_operations;
extern struct seq_operations proc_gid_seq_operations;
extern struct seq_operations proc_projid_seq_operations;
extern ssize_t proc_uid_map_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t proc_gid_map_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t proc_projid_map_write(struct file *, const char __user *, size_t, loff_t *);
#else

static inline struct user_namespace *get_user_ns(struct user_namespace *ns)
{
	return &init_user_ns;
}

static inline int create_user_ns(struct cred *new)
{
	return -EINVAL;
}

static inline int unshare_userns(unsigned long unshare_flags,
				 struct cred **new_cred)
{
	if (unshare_flags & CLONE_NEWUSER)
		return -EINVAL;
	return 0;
}

static inline void put_user_ns(struct user_namespace *ns)
{
}

#endif

void update_mnt_policy(struct user_namespace *userns);

#endif /* _LINUX_USER_H */
