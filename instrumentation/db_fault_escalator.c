

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#define __USE_GNU
#include <dlfcn.h>

static int viper_recv_fd = -1;
static int viper_recv_disabled = 0;

static void viper_recv_resolve_path(char *buf, size_t bufsz)
{
    const char *p = getenv("VIPER_RECV_LOG");
    if (p && *p) {
        snprintf(buf, bufsz, "%s", p);
    } else {
        snprintf(buf, bufsz, "/tmp/viper_recv_%d.bin", (int)getpid());
    }
}

static void viper_recv_open(void)
{
    if (viper_recv_disabled || viper_recv_fd >= 0) return;
    char path[256];
    viper_recv_resolve_path(path, sizeof(path));


    viper_recv_fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0666);
    if (viper_recv_fd < 0) {
        viper_recv_disabled = 1;
    }
}

static ssize_t (*real_recv)(int sockfd, void *buf, size_t len, int flags) = NULL;

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    if (!real_recv) {
        real_recv = dlsym(RTLD_NEXT, "recv");
    }
    ssize_t n = real_recv(sockfd, buf, len, flags);
    if (n > 0 && !viper_recv_disabled) {
        viper_recv_open();
        if (viper_recv_fd >= 0) {


            (void) write(viper_recv_fd, buf, (size_t)n);
        }
    }
    return n;
}
