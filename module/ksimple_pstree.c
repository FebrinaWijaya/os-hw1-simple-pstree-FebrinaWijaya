#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include "ksimple_pstree.h"

#define NETLINK_USER 31

struct sock *nl_sk = NULL;
static void getChildren(pid_t pid, int level, char** output)
{
    struct pid *pid_struct;
    struct task_struct *task, *task1;
    char buffer[100], buf_temp[100];
    int len;
    int i;
    struct list_head *list;

    pid_struct = find_get_pid(pid);
    task = pid_task(pid_struct, PIDTYPE_PID);
    if(task == NULL) {
        *output = krealloc(*output, sizeof(char)*2, GFP_USER);
        (*output)[0] = '\n';
        (*output)[1] = '\0';
        return;
    }

    buffer[0] = '\0';
    for(i=1; i<level; i++) {
        snprintf(buf_temp, 100, "%s", buffer);
        snprintf(buffer, i*4+1, "    %s",buf_temp);
    }
    snprintf(buf_temp, 100, "%s", buffer);
    len = snprintf(buffer, 100, "%s%s(%d)\n", buf_temp, task->comm, task->pid);
    printk(KERN_INFO "%s", buffer);

    *output = krealloc(*output, sizeof(char)*((len+strlen(*output))+1), GFP_USER);
    strcat(*output, buffer);

    list = kmalloc(sizeof(struct list_head), GFP_USER);
    list_for_each(list,&(task->children)) {
        task1=list_entry(list,struct task_struct,sibling);
        getChildren(task1->pid, level+1, output);
    }
}

static void getSibling(pid_t pid, int level, char** output)
{
    struct pid *pid_struct;
    struct task_struct *task, *task1;
    char buffer[100];
    int len;
    int count = 0;
    struct list_head *list;

    pid_struct = find_get_pid(pid);
    task = pid_task(pid_struct, PIDTYPE_PID);
    if(task == NULL) {
        *output = krealloc(*output, sizeof(char)*2, GFP_USER);
        (*output)[0] = '\n';
        (*output)[1] = '\0';
        return;
    }

    list = kmalloc(sizeof(struct list_head), GFP_USER);
    list_for_each(list,&(task->sibling)) {
        task1=list_entry(list,struct task_struct,sibling);
        if(task1->pid!=0) {
            ++count;
            buffer[0] = '\0';
            len = snprintf(buffer, 100, "%s(%d)\n", task1->comm, task1->pid);
            printk(KERN_INFO "%s", buffer);

            *output = krealloc(*output, sizeof(char)*((len+strlen(*output))+1), GFP_USER);

            strcat(*output, buffer);
        }
    }
    if(count == 0) {
        *output = krealloc(*output, sizeof(char)*2, GFP_USER);
        (*output)[0] = '\n';
        (*output)[1] = '\0';
    }
}

static void getParent(pid_t pid, int *level, char** output)
{
    struct pid *pid_struct;
    struct task_struct *task;
    char buffer[100], buf_temp[100];
    int len;
    int i;

    pid_struct = find_get_pid(pid);
    task = pid_task(pid_struct, PIDTYPE_PID);
    if(task == NULL) {
        *output = krealloc(*output, sizeof(char)*2, GFP_USER);
        (*output)[0] = '\n';
        (*output)[1] = '\0';
        return;
    }

    if (task->parent->pid != 0) {
        //printk(KERN_INFO "has parent\n");
        getParent(task->parent->pid, level, output);
        //printk(KERN_INFO "%s %d\n", task->parent->comm, task->parent->pid);
    }

    for(i=1; i<*level; i++) {
        snprintf(buf_temp, 100, "%s", buffer);
        snprintf(buffer, i*4+1, "    %s",buf_temp);
    }
    ++(*level);
    snprintf(buf_temp, 100, "%s", buffer);
    len = snprintf(buffer, 100, "%s%s(%d)\n", buf_temp, task->comm, task->pid);
    printk(KERN_INFO "%s", buffer);
    *output = krealloc(*output, sizeof(char)*((len+strlen(*output))+1), GFP_USER);
    strcat(*output, buffer);
}

static void nl_recv_msg(struct sk_buff *skb)
{

    struct nlmsghdr *nlh;
    int pid_sending;
    struct sk_buff *skb_out;
    int msg_size;
    int res;
    //start of declaration written by me
    char *msg_rcvd;
    char *mode_str;
    char *pid_str;
    long temp;
    pid_t pid;
    char *output;
    int init_lvl = 1;
    //end of declaration written by me

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    nlh = (struct nlmsghdr *)skb->data;
    printk(KERN_INFO "Netlink received msg payload:%s\n", (char *)nlmsg_data(nlh));
    pid_sending = nlh->nlmsg_pid; /*pid of sending process */

    //start of code written by me
    msg_rcvd = (char *)nlmsg_data(nlh);
    mode_str = strsep(&msg_rcvd, " ");
    //printk(KERN_INFO "%s\n", mode_str);
    pid_str = strsep(&msg_rcvd, " ");
    //printk(KERN_INFO "%s\n", pid_str);

    kstrtol(pid_str, 10, &temp);
    pid = temp;

    output = kmalloc(sizeof(char), GFP_USER);
    output[0] = '\0';
    //printk(KERN_INFO "%s", output);

    if(mode_str[0] == 's')
        getSibling(pid, init_lvl, &output);
    else if(mode_str[0] == 'p')
        getParent(pid, &init_lvl, &output);
    else
        getChildren(pid, init_lvl, &output);

    msg_size = strlen(output);
    //end of code written by me
    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(nlh), output, msg_size);

    res = nlmsg_unicast(nl_sk, skb_out, pid_sending);
    if (res < 0)
        printk(KERN_INFO "Error while sending back to user\n");
}

static int __init hello_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
    };
    printk("Entering: %s\n", __FUNCTION__);
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    return 0;
}

static void __exit hello_exit(void)
{

    printk(KERN_INFO "exiting hello module\n");
    netlink_kernel_release(nl_sk);
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");