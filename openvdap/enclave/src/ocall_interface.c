#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdarg.h> // for variable arguments functions
#include <fcntl.h>
#include <stdlib.h>

#define DO_NOT_REDEFINE_FOR_OCALL

#include "openvdap_t.h"

// For open64 need to define this
//#define O_TMPFILE (O_TMPFILE | O_DIRECTORY)

long int sysconf(int name){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
    return 0;
}

int open64(const char *filename, int flags, ...){
    mode_t mode = 0; // file permission bitmask

    // Get the mode_t from arguments
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list valist;
        va_start(valist, flags);
        mode = va_arg(valist, mode_t);
        va_end(valist);
    }

    int ret;
    int status = ocall_openvdap_open64(&ret, filename, flags, mode);
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return ret;
}

off_t lseek64(int fd, off_t offset, int whence){
    off_t ret;
    int status = ocall_openvdap_lseek64(&ret, fd, offset, whence);
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return ret;
}

//int gettimeofday(struct timeval *tv, struct timezone *tz){
//    char error_msg[256];
//    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
//    ocall_openvdap_print_error(error_msg);
//    return 0;
//}

unsigned int sleep(unsigned int seconds){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
    return 0;
}

void *dlopen(const char *filename, int flag){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
}

char *dlerror(void){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
    return 0;
}

void *dlsym(void *handle, const char *symbol){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);

}

int dlclose(void *handle){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
    return 0;
}

int utimes(const char *filename, const struct timeval times[2]){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
    return 0;
}

struct tm *localtime(const time_t *timep){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
    return 0;
}

pid_t getpid(void){
    int ret;
    int status = ocall_openvdap_getpid(&ret);
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return ret;
}

int fsync(int fd){
    int ret;
    int status = ocall_openvdap_fsync(&ret, fd);
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return ret;
}

time_t time(time_t *t){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
    return 0;
}

int close(int fd){
    int ret;
    int status = ocall_openvdap_close(&ret, fd);
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return ret;
}

int access(const char *pathname, int mode){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
    return 0;
}

char *getcwd(char *buf, size_t size){
    char* ret;
    int status = ocall_openvdap_getcwd(&ret, buf, size);
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return ret;
}

int sgx_lstat(const char *path, struct oe_stat_t *buf){
    int ret;
    int status = ocall_openvdap_lstat(&ret, path, buf, sizeof(struct stat));
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return ret;
}

int sgx_stat(const char *path, struct oe_stat_t *buf){
    int ret;
    int status = ocall_openvdap_stat(&ret, path, buf, sizeof(struct stat));
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return ret;
}

int sgx_fstat(int fd, struct oe_stat_t *buf){
    int ret;
    int status = ocall_openvdap_fstat(&ret, fd, buf, sizeof(struct stat));
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return ret;
}

int sgx_ftruncate(int fd, off_t length){
    int ret;
    int status = ocall_openvdap_ftruncate(&ret, fd, length);
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return ret;
}

int fcntl(int fd, int cmd, ... /* arg */ ){
    // Read one argument
    va_list valist;
    va_start(valist, cmd);
    void* arg = va_arg(valist, void*);
    va_end(valist);

    int ret;
    int status = ocall_openvdap_fcntl(&ret, fd, cmd, arg, sizeof(void*));
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return ret;
}

ssize_t read(int fd, void *buf, size_t count){
    int ret;
    int status = ocall_openvdap_read(&ret, fd, buf, count);
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return (ssize_t)ret;
}

ssize_t write(int fd, const void *buf, size_t count){
    int ret;
    int status = ocall_openvdap_write(&ret, fd, buf, count);
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return (ssize_t)ret;
}

int fchmod(int fd, mode_t mode){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
    return 0;
}

int unlink(const char *pathname){
    int ret;
    int status = ocall_openvdap_unlink(&ret, pathname);
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return ret;
}

int mkdir(const char *pathname, mode_t mode) {
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
    return 0;
}

int rmdir(const char *pathname){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
    return 0;
}

int fchown(int fd, uid_t owner, gid_t group){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
    return 0;
}

uid_t geteuid(void){
    int ret;
    int status = ocall_openvdap_getuid(&ret);
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return (uid_t)ret;
}

char* getenv(const char *name){
    char* ret = NULL;
    int status = ocall_openvdap_getenv(&ret, name);
    if (status != 0) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: when calling ocall_openvdap_", __func__);
        ocall_openvdap_print_error(error_msg);
    }
    return ret;
}

void *mmap64(void *addr, size_t len, int prot, int flags, int fildes, off_t off){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
}

//int munmap(void *addr, size_t length){
//    char error_msg[256];
//    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
//    ocall_openvdap_print_error(error_msg);
//    return 0;
//}

void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
}

ssize_t readlink(const char *path, char *buf, size_t bufsiz){
    char error_msg[256];
    snprintf(error_msg, sizeof(error_msg), "%s%s", "Error: no ocall implementation for ", __func__);
    ocall_openvdap_print_error(error_msg);
    return 0;
}
