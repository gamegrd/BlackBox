//
// Created by harold on 17/5/22.
//
#include <unistd.h>
#include <stdlib.h>
#include <sys/ptrace.h>

#include <sys/stat.h>
#include <syscall.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <algorithm>
#include <asm/mman.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <linux/in6.h>
#include <netdb.h>
#include <asm/unistd.h>
#include <errno.h>
#include "IoHook.h"
#include "dobby.h"
#include <stdlib.h>
#include <stdio.h>
#include <string>

static inline void
hook_function(void *handle, const char *symbol, void *new_func, void **old_func) {
    void *addr = dlsym(handle, symbol);
    if (addr == NULL) {
        ALOGE("IoHook: Not found symbol : %s", symbol);
        return;
    }
    ALOGE("IoHook: DobbyHook : %s    %x", symbol,addr);
    DobbyHook(addr, new_func, old_func);
}

void str_replace(char * str1, char * str2, char * str3){
    int i, j, k, done, count = 0, gap = 0;
    char temp[PATH_MAX];
    memset(temp,0,sizeof(temp));
    for(i = 0; i < strlen(str1); i += gap){
        if(str1[i] == str2[0]){
            done = 0;
            for(j = i, k = 0; k < strlen(str2); j++, k++){
                if(str1[j] != str2[k]){
                    done = 1;
                    gap = k;
                    break;
                }
            }
            if(done == 0){ // 已找到待替换字符串并替换
                for(j = i + strlen(str2), k = 0; j < strlen(str1); j++, k++){ // 保存原字符串中剩余的字符
                    temp[k] = str1[j];
                }
                temp[k] = '\0'; // 将字符数组变成字符串
                for(j = i, k = 0; k < strlen(str3); j++, k++){ // 字符串替换
                    str1[j] = str3[k];
                    count++;
                }
                for(k = 0; k < strlen(temp); j++, k++){ // 剩余字符串回接
                    str1[j] = temp[k];
                }
                str1[j] = '\0'; // 将字符数组变成字符串
                str1[j+1] = '\0'; // 将字符数组变成字符串
                gap = strlen(str2);
            }
        }else{
            gap = 1;
        }
    }

    return;
}

const char *relocate_path(const char *path, char * buffer, const size_t size) {
    if ( strlen(path) > size ){
        ALOGE("IoHook: ERROR PATH TOO LONG");
        return path;
    }
    memset(buffer,0,size);
    strcpy(buffer,path);
    if ( buffer == strstr(buffer,"/data/data/app.gmb.vm/databases")){
        str_replace(buffer,"/data/data/app.gmb.vm/databases","/data/data/top.niunaijun.blackboxa32/blackbox/data/user/0/app.gmb.vm/databases");
    }
    str_replace(buffer,"/data/user/0/top.niunaijun.blackboxa32","/data/data/top.niunaijun.blackboxa32");

    ALOGE("IoHook: relocate_path: %s   >>    %s" ,path , buffer );
    return buffer;
}


__BEGIN_DECLS


// int faccessat(int dirfd, const char *pathname, int mode, int flags);
HOOK_DEF(int, faccessat, int dirfd, const char *pathname, int mode, int flags) {
    char temp[PATH_MAX];
    const char *redirect_path = relocate_path(pathname, temp, sizeof(temp));
    ALOGE("IoHook: faccessat : %s", redirect_path);
    return orig_faccessat(dirfd,redirect_path,mode,flags);
}

// int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
HOOK_DEF(int, fchmodat, int dirfd, const char *pathname, mode_t mode, int flags) {
    char temp[PATH_MAX];
    ALOGE("IoHook: fchmodat : %s", pathname);
    return orig_fchmodat(dirfd,pathname,mode,flags);
}

// int fstatat64(int dirfd, const char *pathname, struct stat *buf, int flags);
HOOK_DEF(int, fstatat64, int dirfd, const char *pathname, struct stat *buf, int flags) {
    char temp[PATH_MAX];
    ALOGE("IoHook: fstatat64 : %s", pathname);
    return orig_fstatat64(dirfd,pathname,buf,flags);
}

// int kill(pid_t pid, int sig);
HOOK_DEF(int, kill, pid_t pid, int sig) {
    ALOGE("IoHook:kill >>> pid : %d, sig : %d", pid, sig);
    return orig_kill(pid,sig);
}

// int __statfs64(const char *path, size_t size, struct statfs *stat);
HOOK_DEF(int, __statfs64, const char *pathname, size_t size, struct statfs *stat) {
    char temp[PATH_MAX];
    ALOGE("IoHook: __statfs64 : %s", pathname);
    const char *redirect_path = relocate_path(pathname, temp, sizeof(temp));
    return orig___statfs64(redirect_path,size,stat);
}

// int lstat(const char *path, struct stat *buf);
HOOK_DEF(int, lstat, const char *pathname, struct stat *buf) {
    char temp[PATH_MAX];
    const char *redirect_path = relocate_path(pathname, temp, sizeof(temp));
    auto  rt =  orig_lstat(redirect_path,buf);
    ALOGE("IoHook: %s  open >>  %d ",redirect_path,rt);
    return rt;
}

// int stat(const char *path, struct stat *buf);
HOOK_DEF(int, stat, const char *pathname, struct stat *buf) {
    char temp[PATH_MAX];
    const char *redirect_path = relocate_path(pathname, temp, sizeof(temp));
    auto rt = orig_stat(redirect_path,buf);
    ALOGE("IoHook: stat : %s   rt: %d"  , redirect_path,rt);
    return rt;
}

// int fchmod(const char *pathname, mode_t mode);
HOOK_DEF(int, fchmod, const char *pathname, mode_t mode) {
    char temp[PATH_MAX];
    ALOGE("IoHook: fchmod : %s", pathname);
    return orig_fchmod(pathname,mode);
}


// int fstatat(int dirfd, const char *pathname, struct stat *buf, int flags);
HOOK_DEF(int, fstatat, int dirfd, const char *pathname, struct stat *buf, int flags) {
    char temp[PATH_MAX];
    ALOGE("IoHook: fstatat : %s", pathname);
    const char *redirect_path = relocate_path(pathname, temp, sizeof(temp));
    return orig_fstatat(dirfd,redirect_path,buf,flags);
}

HOOK_DEF(int, fstat, int fd, struct stat *buf)
{
    auto ret = orig_fstat(fd, buf);
    return ret;
}

// int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);
HOOK_DEF(int, mknodat, int dirfd, const char *pathname, mode_t mode, dev_t dev) {
    char temp[PATH_MAX];
    ALOGE("IoHook: dirfd : %s", pathname);
    return orig_mknodat(dirfd,pathname,mode,dev);
}

// int utimensat(int dirfd, const char *pathname, const struct timespec times[2], int flags);
HOOK_DEF(int, utimensat, int dirfd, const char *pathname, const struct timespec times[2],
         int flags) {

    ALOGE("IoHook: utimensat : %s", pathname);
    return orig_utimensat(dirfd,pathname,times,flags);
}

// int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
HOOK_DEF(int, fchownat, int dirfd, const char *pathname, uid_t owner, gid_t group, int flags) {
    ALOGE("IoHook: chroot %s",pathname);
    return orig_fchownat(dirfd,pathname,owner,group,flags);
}

// int chroot(const char *pathname);
HOOK_DEF(int, chroot, const char *pathname) {
    char temp[PATH_MAX];
    ALOGE("IoHook: chroot %s",pathname);
    return orig_chroot(pathname);
}

// int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
HOOK_DEF(int, renameat, int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
    ALOGE("IoHook: renameat %s  > %s" ,oldpath,newpath);
    return orig_renameat(olddirfd,oldpath,newdirfd,newpath);
}

// int statfs64(const char *__path, struct statfs64 *__buf) __INTRODUCED_IN(21);
HOOK_DEF(int, statfs64, const char *filename, struct statfs64 *buf) {
    char temp[PATH_MAX];
    return orig_statfs64(filename,buf);
}

// int unlinkat(int dirfd, const char *pathname, int flags);
HOOK_DEF(int, unlinkat, int dirfd, const char *pathname, int flags) {
    char temp[PATH_MAX];
    ALOGE("IoHook: unlinkat %s " ,pathname);
    return orig_unlinkat(dirfd,pathname,flags);
}

// int symlinkat(const char *oldpath, int newdirfd, const char *newpath);
HOOK_DEF(int, symlinkat, const char *oldpath, int newdirfd, const char *newpath) {
    char temp[PATH_MAX];
    return orig_symlinkat(oldpath,newdirfd,newpath);
}

// int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags);
HOOK_DEF(int, linkat, int olddirfd, const char *oldpath, int newdirfd, const char *newpath,
         int flags) {
    char temp[PATH_MAX];
    return orig_linkat(olddirfd,newpath,newdirfd,newpath,flags);
}

// int mkdirat(int dirfd, const char *pathname, mode_t mode);
HOOK_DEF(int, mkdirat, int dirfd, const char *pathname, mode_t mode) {
    ALOGE("IoHook: LINE: %d : %s", __LINE__ ,pathname);
    return orig_mkdirat(dirfd,pathname,mode);
}

// int readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz);
HOOK_DEF(int, readlinkat, int dirfd, const char *pathname, char *buf, size_t bufsiz) {
    ALOGE("IoHook: LINE: %d : %s", __LINE__ ,pathname);
    return orig_readlinkat(dirfd,pathname,buf,bufsiz);
}


// int truncate(const char *path, off_t length);
HOOK_DEF(int, truncate, const char *pathname, off_t length) {
    ALOGE("IoHook: chdir %s",pathname);
    return orig_truncate(pathname,length);
}

// int chdir(const char *path);
HOOK_DEF(int, chdir, const char *pathname) {
    char temp[PATH_MAX];
    ALOGE("IoHook: chdir %s",pathname);
    return orig_chdir(pathname);
}

// int truncate64(const char *pathname, off_t length);
HOOK_DEF(int, truncate64, const char *pathname, off_t length) {
    ALOGE("IoHook: truncate64 %s",pathname);
    return orig_truncate64(pathname,length);
}


// int __getcwd(char *buf, size_t size);
HOOK_DEF(int, getcwd, char *buf, size_t size) {
    return orig_getcwd(buf,size);
}

// int __openat(int fd, const char *pathname, int flags, int mode);
HOOK_DEF(int, openat, int fd, const char *pathname, int flags, int mode) {
    ALOGE("IoHook: openat %s",pathname);
    return orig_openat(fd,pathname,flags,mode);
}

HOOK_DEF(int, close, int __fd) {
   return orig_close(__fd);
}


// int __statfs (__const char *__file, struct statfs *__buf);
HOOK_DEF(int, __statfs, __const char *__file, struct statfs *__buf) {
    char temp[PATH_MAX];
    ALOGE("IoHook: LINE: %d : %s", __LINE__ ,__file);
    return orig___statfs(__file,__buf);
}

HOOK_DEF(int, statfs, __const char *__file, struct statfs *__buf) {
    char temp[PATH_MAX];
    ALOGE("IoHook: LINE: %d : %s", __LINE__ ,__file);
    return orig_statfs(__file,__buf);
}

// int (*origin_execve)(const char *pathname, char *const argv[], char *const envp[]);
HOOK_DEF(int, execve, const char *pathname, char *argv[], char *const envp[]) {
    return orig_execve(pathname,argv,envp);
}

HOOK_DEF(void *, dlopen_CI, const char *filename, int flag) {
    char temp[PATH_MAX];
    const char *redirect_path = relocate_path(filename, temp, sizeof(temp));
    void *ret = orig_dlopen_CI(redirect_path, flag);
    //onSoLoaded(filename, ret);
    return ret;
}

HOOK_DEF(void*, do_dlopen_CIV, const char *filename, int flag, const void *extinfo) {
    char temp[PATH_MAX];
    ALOGE("IoHook: LINE: %d : %s", __LINE__ ,filename);
    const char *redirect_path = relocate_path(filename, temp, sizeof(temp));
    void *ret = orig_do_dlopen_CIV(redirect_path, flag, extinfo);
    //onSoLoaded(filename, ret);
    return ret;
}

HOOK_DEF(void*, do_dlopen_CIVV, const char *name, int flags, const void *extinfo,
         void *caller_addr) {
    char temp[PATH_MAX];
    ALOGE("IoHook: LINE: %d : %s", __LINE__ ,name);
    const char *redirect_path = relocate_path(name, temp, sizeof(temp));
    void *ret = orig_do_dlopen_CIVV(redirect_path, flags, extinfo, caller_addr);
    //onSoLoaded(name, ret);
    return ret;
}

//void *dlsym(void *handle, const char *symbol)
HOOK_DEF(void*, dlsym, void *handle, char *symbol) {
    return orig_dlsym(handle, symbol);
}

HOOK_DEF(pid_t, vfork) {
    return fork();
}

HOOK_DEF(ssize_t, pread64, int fd, void* buf, size_t count, off64_t offset) {
    ssize_t ret = 0;

        ret = orig_pread64(fd, buf, count, offset);

    return ret;
}

HOOK_DEF(ssize_t, pwrite64, int fd, const void *buf, size_t count, off64_t offset) {
    ssize_t ret = 0;
    bool flag = false;
    if(!flag)
        ret = orig_pwrite64(fd, buf, count, offset);
    return ret;
}

HOOK_DEF(ssize_t, read, int fd, void *buf, size_t count) {
    ssize_t ret = 0;
    bool flag = false;
    ret = orig_read(fd,buf,count);
    return ret;
}

HOOK_DEF(ssize_t, write, int fd, const void* buf, size_t count) {
    ssize_t ret = 0;
    ret = orig_write(fd,buf,count);
    return ret;
}

HOOK_DEF(int, munmap, void *addr, size_t length) {
    int ret = -1;
    ret = orig_munmap(addr,length);
    return ret;
}

HOOK_DEF(int, msync, void *addr, size_t size, int flags) {
    int ret = -1;
    ret = orig_msync( addr, size, flags);

    return ret;
}

HOOK_DEF(void *, mmap, void *addr, size_t length, int prot,int flags, int fd, size_t pgoffset) {
    return orig_mmap(addr,length,prot,flags,fd,pgoffset);
}

HOOK_DEF(off_t, lseek, int fd, off_t offset, int whence)
{
    off_t ret;

        ret = orig_lseek(fd, offset, whence);

    return ret;
}

HOOK_DEF(int, __llseek, unsigned int fd, unsigned long offset_high,
         unsigned long offset_low, off64_t *result,
         unsigned int whence)
{

   auto  ret = orig___llseek(fd, offset_high, offset_low, result, whence);

    return ret;
}

//int ftruncate64(int, off_t)
HOOK_DEF(int, ftruncate64, int fd, off64_t length)
{
    int ret;
    ret = orig_ftruncate64(fd, length);

    return ret;
}

//ssize_t sendfile(int out_fd, int in_fd, off_t* offset, size_t count)
HOOK_DEF(ssize_t, sendfile, int out_fd, int in_fd, off_t* offset, size_t count)
{
    return orig_sendfile(out_fd,in_fd,offset,count);
}

//ssize_t sendfile64(int out_fd, int in_fd, off64_t* offset, size_t count)
HOOK_DEF(ssize_t, sendfile64, int out_fd, int in_fd, off64_t* offset, size_t count)
{
    return orig_sendfile64(out_fd,in_fd,offset,count);
}

//int dup(int oldfd);
HOOK_DEF(int, dup, int oldfd)
{
    return orig_dup(oldfd);
}

//int dup3(int oldfd, int newfd, int flags);
HOOK_DEF(int, dup3, int oldfd, int newfd, int flags)
{
    return orig_dup3(oldfd, newfd, flags);
}

HOOK_DEF(int, fcntl, int fd, int cmd, ...) {
    va_list arg;
    int ret = -1;
    va_start (arg, cmd);
    switch (cmd) {
        default:
            void * target = va_arg(arg, void*);
            ret = orig_fcntl(fd, cmd, target);
            va_end(arg);
            break;
    }
    return ret;
}

HOOK_DEF(int, getaddrinfo,const char *__node, const char *__service, const struct addrinfo *__hints,
         struct addrinfo **__result) {
    return orig_getaddrinfo(__node,__service,__hints,__result);
}

HOOK_DEF(ssize_t, sendto, int fd, const void *buf, size_t n, int flags, struct sockaddr *dst_addr,
         socklen_t dst_addr_length) {
    return orig_sendto(fd,buf,n,flags,dst_addr,dst_addr_length);
}

HOOK_DEF(int, connect, int sd, struct sockaddr *addr, socklen_t socklen) {
    return orig_connect(sd,addr,socklen);
}

HOOK_DEF(void, xlogger_Write, void* _info, const char* _log)
{
    ALOGE("IoHook: xlogger_Write %s",_log);
    orig_xlogger_Write(_info, _log);
}

// int __openat(int fd, const char *pathname, int flags, int mode);
HOOK_DEF(int, __openat, int fd, const char *pathname, int flags, int mode) {
    char temp[PATH_MAX];
    const char *redirect_path = relocate_path(pathname, temp, sizeof(temp));
    auto rt =  orig___openat(fd,redirect_path,flags,mode);
    ALOGE("IoHook: __openat : %s    >> %d ", redirect_path,rt);
    return rt;
}


// int __open(const char *pathname, int flags, int mode);
HOOK_DEF(int, __open, const char *pathname, int flags, int mode) {
    char temp[PATH_MAX];
    const char *redirect_path = relocate_path(pathname, temp, sizeof(temp));
    auto rt = orig___open(redirect_path,flags,mode);
    ALOGE("IoHook: __open : %s  ==> %d ", redirect_path,rt);
    return rt;
}

// int access(const char *pathname, int mode);
HOOK_DEF(int, access, const char *pathname, int mode) {
    char temp[PATH_MAX];
    const char *redirect_path = relocate_path(pathname, temp, sizeof(temp));
    auto rt = orig_access(redirect_path,mode);
    ALOGE("IoHook: access : %s  == > %d", redirect_path,rt );
    return rt;
}
// int rename(const char *oldpath, const char *newpath);
HOOK_DEF(int, rename, const char *oldpath, const char *newpath) {
    char temp_old[PATH_MAX], temp_new[PATH_MAX];
    const char *relocated_path_old = relocate_path(oldpath, temp_old, sizeof(temp_old));
    const char *relocated_path_new = relocate_path(newpath, temp_new, sizeof(temp_new));
    if (relocated_path_old && relocated_path_new) {
        ALOGE("IoHook: rename : %s  == > %s ", relocated_path_old,relocated_path_new );
        return orig_rename(relocated_path_old, relocated_path_new);
    }
}



__END_DECLS
// end IO DEF



IoHook* IoHook::get_instance(){
    IoHook* ctx = nullptr;
    if (!ctx){
        ctx =  new IoHook();
        void *handle = dlopen("libc.so", RTLD_NOW);
        //void *__loader_dlopen = DobbySymbolResolver(NULL, "__loader_dlopen");
        if (handle) {
            /*
            // x32
            HOOK_SYMBOL(handle, __openat);
            HOOK_SYMBOL(handle, access);
            HOOK_SYMBOL(handle, __open);
            HOOK_SYMBOL(handle, rename);
            // x64

            HOOK_SYMBOL(handle, fchownat);
            HOOK_SYMBOL(handle, renameat);
            HOOK_SYMBOL(handle, mkdirat);
            HOOK_SYMBOL(handle, mknodat);
            HOOK_SYMBOL(handle, truncate);
            HOOK_SYMBOL(handle, linkat);
            HOOK_SYMBOL(handle, readlinkat);
            HOOK_SYMBOL(handle, unlinkat);
            HOOK_SYMBOL(handle, symlinkat);
            HOOK_SYMBOL(handle, utimensat);
            HOOK_SYMBOL(handle, chdir);
            HOOK_SYMBOL(handle, execve);
            HOOK_SYMBOL(handle, statfs64);
            HOOK_SYMBOL(handle, kill);
            HOOK_SYMBOL(handle, vfork);
            HOOK_SYMBOL(handle, faccessat);
            HOOK_SYMBOL(handle, openat);
            HOOK_SYMBOL(handle, fchmodat);
            HOOK_SYMBOL(handle, fstatat64);

            //fstatat64 BUS CRASH
            //HOOK_SYMBOL(handle, statfs); // crash 100%

            HOOK_SYMBOL(handle, __statfs);
            HOOK_SYMBOL(handle, __statfs64);
            HOOK_SYMBOL(handle, getcwd);
            HOOK_SYMBOL(handle, stat);
            HOOK_SYMBOL(handle, lstat);
            HOOK_SYMBOL(handle, fstatat);
            HOOK_SYMBOL(handle, close);
            HOOK_SYMBOL(handle, read);
            HOOK_SYMBOL(handle, write);
            HOOK_SYMBOL(handle, mmap);
            HOOK_SYMBOL(handle, munmap);
            HOOK_SYMBOL(handle, pread64);
            HOOK_SYMBOL(handle, pwrite64);
            HOOK_SYMBOL(handle, fstat);
            HOOK_SYMBOL(handle, __llseek);
            HOOK_SYMBOL(handle, lseek);
            HOOK_SYMBOL(handle, ftruncate64);
            HOOK_SYMBOL(handle, sendfile);
            HOOK_SYMBOL(handle, sendfile64);
            HOOK_SYMBOL(handle, dup);
            HOOK_SYMBOL(handle, dup3);
            HOOK_SYMBOL(handle, fcntl);
            HOOK_SYMBOL(handle, getaddrinfo);
            HOOK_SYMBOL(handle, sendto);
            HOOK_SYMBOL(handle, connect);
            HOOK_SYMBOL(handle, msync);
        */

            dlclose(handle);
        }


        /*
        void *addr = dlsym(handle, "open");
        if (addr){
            ALOGE( "IoHook: -------------------------OPEN----4-------------");
            hook_function(handle,"open", (void *)new_open,(void **)orig_open);
            ALOGE( "IoHook: -------------------------OPEN----done-------------");
        }else{
            ALOGE( "IoHook: ------------------------NO-OPEN-----------------");
        }
        */
    ALOGD("IoHook: =========IoHook===========");
    }
    return ctx;
}