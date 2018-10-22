#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <unistd.h>
#include "simple_pstree.h"
#define NETLINK_USER 31

#define MAX_PAYLOAD 4096 /* maximum payload size*/

#define DEBUG 0
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

int main(int argc, char *argv[])
{

    char* msg_to_send;
    if(argc > 1) {
        int length = strlen(argv[1]);
        if(length>2) {
            msg_to_send = malloc(sizeof(char)*length);
            strcpy(msg_to_send, argv[1]);
            msg_to_send[0] = msg_to_send[1];
            msg_to_send[1] = ' ';
        } else if(argv[1][1] == 'c') {
            msg_to_send = "c 1";
        } else {
            int pid = getpid();
            if(DEBUG) printf("pid = %d\n",pid);
            char temp[20];
            sprintf(temp,"%d",pid);
            msg_to_send = malloc(sizeof(char)*(1+strlen(temp)+1));
            argv[1][0] = argv[1][1];
            argv[1][1] = ' ';
            msg_to_send[0] = '\0';
            strcat(msg_to_send,argv[1]);
            strcat(msg_to_send,temp);
        }
    } else {
        msg_to_send = "c 1";
    }
    if(DEBUG)
        printf("message to send: %s\n", msg_to_send);

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0)
        return -1;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    strcpy(NLMSG_DATA(nlh), msg_to_send);

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if(DEBUG) printf("Sending message to kernel\n");
    sendmsg(sock_fd, &msg, 0);
    if(DEBUG) printf("Waiting for message from kernel\n");

    /* Read message from kernel */
    recvmsg(sock_fd, &msg, 0);
    if(DEBUG) printf("Received message payload: \n");
    printf("%s", (char *)NLMSG_DATA(nlh));
    close(sock_fd);
}