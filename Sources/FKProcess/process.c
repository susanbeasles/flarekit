#define _GNU_SOURCE
#include "FKProcess.h"
#include <spawn.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>

int fk_run(const char *exe, const char *const *argv, const char *const *env, const char *cwd,
           const unsigned char *input, size_t size, const char *out, unsigned timeout) {
    int pipes[2]; if (pipe(pipes)) return -1;
    int output = open(out, O_WRONLY|O_CREAT|O_TRUNC, 0600), discard = open("/dev/null",O_WRONLY);
    if (output < 0 || discard < 0) { close(pipes[0]);close(pipes[1]);if(output>=0)close(output);if(discard>=0)close(discard);return -1; }
    // Every descriptor is explicitly closed in the child. No shell or inherited credential env.
    posix_spawn_file_actions_t actions; posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions,pipes[0],STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions,output,STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions,discard,STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions,pipes[0]); posix_spawn_file_actions_addclose(&actions,pipes[1]);
    posix_spawn_file_actions_addclose(&actions,output); posix_spawn_file_actions_addclose(&actions,discard);
    if (cwd) posix_spawn_file_actions_addchdir_np(&actions,cwd);
    posix_spawnattr_t attributes;posix_spawnattr_init(&attributes);
    posix_spawnattr_setflags(&attributes,POSIX_SPAWN_SETPGROUP);posix_spawnattr_setpgroup(&attributes,0);
    pid_t pid; int error=posix_spawn(&pid,exe,&actions,&attributes,(char *const *)argv,(char *const *)env);
    posix_spawnattr_destroy(&attributes);
    posix_spawn_file_actions_destroy(&actions); close(pipes[0]);close(output);close(discard);
    if (error) {close(pipes[1]);return -1;}
    // Avoid termination if a rejected child closes stdin. Bounded inputs are <=2 MiB.
    sigset_t blocked,old;sigemptyset(&blocked);sigaddset(&blocked,SIGPIPE);pthread_sigmask(SIG_BLOCK,&blocked,&old);
    fcntl(pipes[1],F_SETFL,fcntl(pipes[1],F_GETFL)|O_NONBLOCK);
    time_t deadline=time(NULL)+timeout;int status=0;
    size_t written=0;while(written<size&&time(NULL)<deadline){
        ssize_t n=write(pipes[1],input+written,size-written);
        if(n>0)written+=n;
        else if(errno==EAGAIN||errno==EINTR)usleep(10000);
        else break;
    }
    close(pipes[1]);
    sigset_t pending;sigpending(&pending);
    if(sigismember(&pending,SIGPIPE)&&!sigismember(&old,SIGPIPE)){int signal_number;sigwait(&blocked,&signal_number);}
    pthread_sigmask(SIG_SETMASK,&old,NULL);
    while(waitpid(pid,&status,WNOHANG)==0) {
        if(time(NULL)>=deadline){kill(-pid,SIGKILL);while(waitpid(pid,&status,0)<0&&errno==EINTR){};return 124;}
        usleep(10000);
    }
    return WIFEXITED(status)?WEXITSTATUS(status):128+(WIFSIGNALED(status)?WTERMSIG(status):0);
}
