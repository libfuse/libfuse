#include <stdio.h>                 /* fprintf */
#include <errno.h>                 /* errno */
#include <string.h>                /* strerror */
#include <unistd.h>                /* read,write,close */
#include <stdlib.h>                /* getenv,strtol */
#include <sys/select.h>            /* select */
#include <sys/socket.h>            /* send, recv */
#include <sys/un.h>                /* struct sockaddr_un */
#define BUFSIZE (2<<16)
#undef IOSLAVE_DEBUG
char *scratch;

/* return values:
 * 0  => success
 * -1 => error condition
 */
int send_fd(int sock_fd, int send_fd) {
    int retval;
    struct msghdr msg;
    struct cmsghdr *p_cmsg;
    struct iovec vec;
    char cmsgbuf[CMSG_SPACE(sizeof(send_fd))];
    int *p_fds;
    char sendchar = 0;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);
    p_cmsg = CMSG_FIRSTHDR(&msg);
    p_cmsg->cmsg_level = SOL_SOCKET;
    p_cmsg->cmsg_type = SCM_RIGHTS;
    p_cmsg->cmsg_len = CMSG_LEN(sizeof(send_fd));
    p_fds = (int *) CMSG_DATA(p_cmsg);
    *p_fds = send_fd;
    msg.msg_controllen = p_cmsg->cmsg_len;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    /* "To pass file descriptors or credentials you need to send/read at
     * least one byte" (man 7 unix)
     */
    vec.iov_base = &sendchar;
    vec.iov_len = sizeof(sendchar);
    while((retval = sendmsg(sock_fd, &msg, 0)) == -1 && errno == EINTR);
    if (retval != 1) {
        perror("sendmsg");
        return -1;
    }
    return 0;
}

int main() {
    char *env = getenv("_FUSE_IOSLAVE_FD");
    int fd;
    if (!env)
        exit(fprintf(stderr, "fuse_ioslave: do not run me directly\n"));
    fd = strtol(env, NULL, 0);
    if(send_fd(fd, 0) == -1)
    	fprintf(stderr,"failed to send fd\n");
    return 0;
}
