#ifndef KSIMPLE_PSTREE_H
#define KSIMPLE_PSTREE_H

static void nl_recv_msg(struct sk_buff *skb);
static int __init hello_init(void);
static void __exit hello_exit(void);
static void getChildren(pid_t pid, int level, char** output);
static void getSibling(pid_t pid, int level, char** output);
static void getParent(pid_t pid, int *level, char** output);

#endif