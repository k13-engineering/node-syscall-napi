#include <sys/syscall.h>

#include <stdio.h>

#define PRINT_SYS_CONSTANT(name) printf("  %s: %in,\n", #name, name)

int main(int argc, char* argv[]) {
  printf("{\n");
  PRINT_SYS_CONSTANT(__NR_io_setup);
  PRINT_SYS_CONSTANT(__NR_io_destroy);
  PRINT_SYS_CONSTANT(__NR_io_submit);
  PRINT_SYS_CONSTANT(__NR_io_cancel);
  PRINT_SYS_CONSTANT(__NR_io_getevents);
  PRINT_SYS_CONSTANT(__NR_setxattr);
  PRINT_SYS_CONSTANT(__NR_lsetxattr);
  PRINT_SYS_CONSTANT(__NR_fsetxattr);
  PRINT_SYS_CONSTANT(__NR_getxattr);
  PRINT_SYS_CONSTANT(__NR_lgetxattr);
  PRINT_SYS_CONSTANT(__NR_fgetxattr);
  PRINT_SYS_CONSTANT(__NR_listxattr);
  PRINT_SYS_CONSTANT(__NR_llistxattr);
  PRINT_SYS_CONSTANT(__NR_flistxattr);
  PRINT_SYS_CONSTANT(__NR_removexattr);
  PRINT_SYS_CONSTANT(__NR_lremovexattr);
  PRINT_SYS_CONSTANT(__NR_fremovexattr);
  PRINT_SYS_CONSTANT(__NR_getcwd);
  PRINT_SYS_CONSTANT(__NR_lookup_dcookie);
  PRINT_SYS_CONSTANT(__NR_eventfd2);
  PRINT_SYS_CONSTANT(__NR_epoll_create1);
  PRINT_SYS_CONSTANT(__NR_epoll_ctl);
  PRINT_SYS_CONSTANT(__NR_epoll_pwait);
  PRINT_SYS_CONSTANT(__NR_dup);
  PRINT_SYS_CONSTANT(__NR_dup3);
  PRINT_SYS_CONSTANT(__NR_inotify_init1);
  PRINT_SYS_CONSTANT(__NR_inotify_add_watch);
  PRINT_SYS_CONSTANT(__NR_inotify_rm_watch);
  PRINT_SYS_CONSTANT(__NR_ioctl);
  PRINT_SYS_CONSTANT(__NR_ioprio_set);
  PRINT_SYS_CONSTANT(__NR_ioprio_get);
  PRINT_SYS_CONSTANT(__NR_flock);
  PRINT_SYS_CONSTANT(__NR_mknodat);
  PRINT_SYS_CONSTANT(__NR_mkdirat);
  PRINT_SYS_CONSTANT(__NR_unlinkat);
  PRINT_SYS_CONSTANT(__NR_symlinkat);
  PRINT_SYS_CONSTANT(__NR_linkat);
  PRINT_SYS_CONSTANT(__NR_renameat);
  PRINT_SYS_CONSTANT(__NR_umount2);
  PRINT_SYS_CONSTANT(__NR_mount);
  PRINT_SYS_CONSTANT(__NR_pivot_root);
  PRINT_SYS_CONSTANT(__NR_nfsservctl);
  PRINT_SYS_CONSTANT(__NR_fallocate);
  PRINT_SYS_CONSTANT(__NR_faccessat);
  PRINT_SYS_CONSTANT(__NR_chdir);
  PRINT_SYS_CONSTANT(__NR_fchdir);
  PRINT_SYS_CONSTANT(__NR_chroot);
  PRINT_SYS_CONSTANT(__NR_fchmod);
  PRINT_SYS_CONSTANT(__NR_fchmodat);
  PRINT_SYS_CONSTANT(__NR_fchownat);
  PRINT_SYS_CONSTANT(__NR_fchown);
  PRINT_SYS_CONSTANT(__NR_openat);
  PRINT_SYS_CONSTANT(__NR_close);
  PRINT_SYS_CONSTANT(__NR_vhangup);
  PRINT_SYS_CONSTANT(__NR_pipe2);
  PRINT_SYS_CONSTANT(__NR_quotactl);
  PRINT_SYS_CONSTANT(__NR_getdents64);
  PRINT_SYS_CONSTANT(__NR_read);
  PRINT_SYS_CONSTANT(__NR_write);
  PRINT_SYS_CONSTANT(__NR_readv);
  PRINT_SYS_CONSTANT(__NR_writev);
  PRINT_SYS_CONSTANT(__NR_pread64);
  PRINT_SYS_CONSTANT(__NR_pwrite64);
  PRINT_SYS_CONSTANT(__NR_preadv);
  PRINT_SYS_CONSTANT(__NR_pwritev);
  PRINT_SYS_CONSTANT(__NR_pselect6);
  PRINT_SYS_CONSTANT(__NR_ppoll);
  PRINT_SYS_CONSTANT(__NR_signalfd4);
  PRINT_SYS_CONSTANT(__NR_vmsplice);
  PRINT_SYS_CONSTANT(__NR_splice);
  PRINT_SYS_CONSTANT(__NR_tee);
  PRINT_SYS_CONSTANT(__NR_readlinkat);
  PRINT_SYS_CONSTANT(__NR_sync);
  PRINT_SYS_CONSTANT(__NR_fsync);
  PRINT_SYS_CONSTANT(__NR_fdatasync);
#ifdef __NR_sync_file_range
  PRINT_SYS_CONSTANT(__NR_sync_file_range);
#endif
  PRINT_SYS_CONSTANT(__NR_timerfd_create);
  PRINT_SYS_CONSTANT(__NR_timerfd_settime);
  PRINT_SYS_CONSTANT(__NR_timerfd_gettime);
  PRINT_SYS_CONSTANT(__NR_utimensat);
  PRINT_SYS_CONSTANT(__NR_acct);
  PRINT_SYS_CONSTANT(__NR_capget);
  PRINT_SYS_CONSTANT(__NR_capset);
  PRINT_SYS_CONSTANT(__NR_personality);
  PRINT_SYS_CONSTANT(__NR_exit);
  PRINT_SYS_CONSTANT(__NR_exit_group);
  PRINT_SYS_CONSTANT(__NR_waitid);
  PRINT_SYS_CONSTANT(__NR_set_tid_address);
  PRINT_SYS_CONSTANT(__NR_unshare);
  PRINT_SYS_CONSTANT(__NR_futex);
  PRINT_SYS_CONSTANT(__NR_set_robust_list);
  PRINT_SYS_CONSTANT(__NR_get_robust_list);
  PRINT_SYS_CONSTANT(__NR_nanosleep);
  PRINT_SYS_CONSTANT(__NR_getitimer);
  PRINT_SYS_CONSTANT(__NR_setitimer);
  PRINT_SYS_CONSTANT(__NR_kexec_load);
  PRINT_SYS_CONSTANT(__NR_init_module);
  PRINT_SYS_CONSTANT(__NR_delete_module);
  PRINT_SYS_CONSTANT(__NR_timer_create);
  PRINT_SYS_CONSTANT(__NR_timer_gettime);
  PRINT_SYS_CONSTANT(__NR_timer_getoverrun);
  PRINT_SYS_CONSTANT(__NR_timer_settime);
  PRINT_SYS_CONSTANT(__NR_timer_delete);
  PRINT_SYS_CONSTANT(__NR_clock_settime);
  PRINT_SYS_CONSTANT(__NR_clock_gettime);
  PRINT_SYS_CONSTANT(__NR_clock_getres);
  PRINT_SYS_CONSTANT(__NR_clock_nanosleep);
  PRINT_SYS_CONSTANT(__NR_syslog);
  PRINT_SYS_CONSTANT(__NR_ptrace);
  PRINT_SYS_CONSTANT(__NR_sched_setparam);
  PRINT_SYS_CONSTANT(__NR_sched_setscheduler);
  PRINT_SYS_CONSTANT(__NR_sched_getscheduler);
  PRINT_SYS_CONSTANT(__NR_sched_getparam);
  PRINT_SYS_CONSTANT(__NR_sched_setaffinity);
  PRINT_SYS_CONSTANT(__NR_sched_getaffinity);
  PRINT_SYS_CONSTANT(__NR_sched_yield);
  PRINT_SYS_CONSTANT(__NR_sched_get_priority_max);
  PRINT_SYS_CONSTANT(__NR_sched_get_priority_min);
  PRINT_SYS_CONSTANT(__NR_sched_rr_get_interval);
  PRINT_SYS_CONSTANT(__NR_restart_syscall);
  PRINT_SYS_CONSTANT(__NR_kill);
  PRINT_SYS_CONSTANT(__NR_tkill);
  PRINT_SYS_CONSTANT(__NR_tgkill);
  PRINT_SYS_CONSTANT(__NR_sigaltstack);
  PRINT_SYS_CONSTANT(__NR_rt_sigsuspend);
  PRINT_SYS_CONSTANT(__NR_rt_sigaction);
  PRINT_SYS_CONSTANT(__NR_rt_sigprocmask);
  PRINT_SYS_CONSTANT(__NR_rt_sigpending);
  PRINT_SYS_CONSTANT(__NR_rt_sigtimedwait);
  PRINT_SYS_CONSTANT(__NR_rt_sigqueueinfo);
  PRINT_SYS_CONSTANT(__NR_rt_sigreturn);
  PRINT_SYS_CONSTANT(__NR_setpriority);
  PRINT_SYS_CONSTANT(__NR_getpriority);
  PRINT_SYS_CONSTANT(__NR_reboot);
  PRINT_SYS_CONSTANT(__NR_setregid);
  PRINT_SYS_CONSTANT(__NR_setgid);
  PRINT_SYS_CONSTANT(__NR_setreuid);
  PRINT_SYS_CONSTANT(__NR_setuid);
  PRINT_SYS_CONSTANT(__NR_setresuid);
  PRINT_SYS_CONSTANT(__NR_getresuid);
  PRINT_SYS_CONSTANT(__NR_setresgid);
  PRINT_SYS_CONSTANT(__NR_getresgid);
  PRINT_SYS_CONSTANT(__NR_setfsuid);
  PRINT_SYS_CONSTANT(__NR_setfsgid);
  PRINT_SYS_CONSTANT(__NR_times);
  PRINT_SYS_CONSTANT(__NR_setpgid);
  PRINT_SYS_CONSTANT(__NR_getpgid);
  PRINT_SYS_CONSTANT(__NR_getsid);
  PRINT_SYS_CONSTANT(__NR_setsid);
  PRINT_SYS_CONSTANT(__NR_getgroups);
  PRINT_SYS_CONSTANT(__NR_setgroups);
  PRINT_SYS_CONSTANT(__NR_uname);
  PRINT_SYS_CONSTANT(__NR_sethostname);
  PRINT_SYS_CONSTANT(__NR_setdomainname);
#ifdef __NR_getrlimit
  PRINT_SYS_CONSTANT(__NR_getrlimit);
#endif
  PRINT_SYS_CONSTANT(__NR_setrlimit);
  PRINT_SYS_CONSTANT(__NR_getrusage);
  PRINT_SYS_CONSTANT(__NR_umask);
  PRINT_SYS_CONSTANT(__NR_prctl);
  PRINT_SYS_CONSTANT(__NR_getcpu);
  PRINT_SYS_CONSTANT(__NR_gettimeofday);
  PRINT_SYS_CONSTANT(__NR_settimeofday);
  PRINT_SYS_CONSTANT(__NR_adjtimex);
  PRINT_SYS_CONSTANT(__NR_getpid);
  PRINT_SYS_CONSTANT(__NR_getppid);
  PRINT_SYS_CONSTANT(__NR_getuid);
  PRINT_SYS_CONSTANT(__NR_geteuid);
  PRINT_SYS_CONSTANT(__NR_getgid);
  PRINT_SYS_CONSTANT(__NR_getegid);
  PRINT_SYS_CONSTANT(__NR_gettid);
  PRINT_SYS_CONSTANT(__NR_sysinfo);
  PRINT_SYS_CONSTANT(__NR_mq_open);
  PRINT_SYS_CONSTANT(__NR_mq_unlink);
  PRINT_SYS_CONSTANT(__NR_mq_timedsend);
  PRINT_SYS_CONSTANT(__NR_mq_timedreceive);
  PRINT_SYS_CONSTANT(__NR_mq_notify);
  PRINT_SYS_CONSTANT(__NR_mq_getsetattr);
  PRINT_SYS_CONSTANT(__NR_msgget);
  PRINT_SYS_CONSTANT(__NR_msgctl);
  PRINT_SYS_CONSTANT(__NR_msgrcv);
  PRINT_SYS_CONSTANT(__NR_msgsnd);
  PRINT_SYS_CONSTANT(__NR_semget);
  PRINT_SYS_CONSTANT(__NR_semctl);
  PRINT_SYS_CONSTANT(__NR_semtimedop);
  PRINT_SYS_CONSTANT(__NR_semop);
  PRINT_SYS_CONSTANT(__NR_shmget);
  PRINT_SYS_CONSTANT(__NR_shmctl);
  PRINT_SYS_CONSTANT(__NR_shmat);
  PRINT_SYS_CONSTANT(__NR_shmdt);
  PRINT_SYS_CONSTANT(__NR_socket);
  PRINT_SYS_CONSTANT(__NR_socketpair);
  PRINT_SYS_CONSTANT(__NR_bind);
  PRINT_SYS_CONSTANT(__NR_listen);
  PRINT_SYS_CONSTANT(__NR_accept);
  PRINT_SYS_CONSTANT(__NR_connect);
  PRINT_SYS_CONSTANT(__NR_getsockname);
  PRINT_SYS_CONSTANT(__NR_getpeername);
  PRINT_SYS_CONSTANT(__NR_sendto);
  PRINT_SYS_CONSTANT(__NR_recvfrom);
  PRINT_SYS_CONSTANT(__NR_setsockopt);
  PRINT_SYS_CONSTANT(__NR_getsockopt);
  PRINT_SYS_CONSTANT(__NR_shutdown);
  PRINT_SYS_CONSTANT(__NR_sendmsg);
  PRINT_SYS_CONSTANT(__NR_recvmsg);
  PRINT_SYS_CONSTANT(__NR_readahead);
  PRINT_SYS_CONSTANT(__NR_brk);
  PRINT_SYS_CONSTANT(__NR_munmap);
  PRINT_SYS_CONSTANT(__NR_mremap);
  PRINT_SYS_CONSTANT(__NR_add_key);
  PRINT_SYS_CONSTANT(__NR_request_key);
  PRINT_SYS_CONSTANT(__NR_keyctl);
  PRINT_SYS_CONSTANT(__NR_clone);
  PRINT_SYS_CONSTANT(__NR_execve);
  PRINT_SYS_CONSTANT(__NR_swapon);
  PRINT_SYS_CONSTANT(__NR_swapoff);
  PRINT_SYS_CONSTANT(__NR_mprotect);
  PRINT_SYS_CONSTANT(__NR_msync);
  PRINT_SYS_CONSTANT(__NR_mlock);
  PRINT_SYS_CONSTANT(__NR_munlock);
  PRINT_SYS_CONSTANT(__NR_mlockall);
  PRINT_SYS_CONSTANT(__NR_munlockall);
  PRINT_SYS_CONSTANT(__NR_mincore);
  PRINT_SYS_CONSTANT(__NR_madvise);
  PRINT_SYS_CONSTANT(__NR_remap_file_pages);
  PRINT_SYS_CONSTANT(__NR_mbind);
  PRINT_SYS_CONSTANT(__NR_get_mempolicy);
  PRINT_SYS_CONSTANT(__NR_set_mempolicy);
#ifdef __NR_migrate_pages
  PRINT_SYS_CONSTANT(__NR_migrate_pages);
#endif
  PRINT_SYS_CONSTANT(__NR_move_pages);
  PRINT_SYS_CONSTANT(__NR_rt_tgsigqueueinfo);
  PRINT_SYS_CONSTANT(__NR_perf_event_open);
  PRINT_SYS_CONSTANT(__NR_accept4);
  PRINT_SYS_CONSTANT(__NR_recvmmsg);
  PRINT_SYS_CONSTANT(__NR_wait4);
  PRINT_SYS_CONSTANT(__NR_prlimit64);
  PRINT_SYS_CONSTANT(__NR_fanotify_init);
  PRINT_SYS_CONSTANT(__NR_fanotify_mark);
  PRINT_SYS_CONSTANT(__NR_name_to_handle_at);
  PRINT_SYS_CONSTANT(__NR_open_by_handle_at);
  PRINT_SYS_CONSTANT(__NR_clock_adjtime);
  PRINT_SYS_CONSTANT(__NR_syncfs);
  PRINT_SYS_CONSTANT(__NR_setns);
  PRINT_SYS_CONSTANT(__NR_sendmmsg);
  PRINT_SYS_CONSTANT(__NR_process_vm_readv);
  PRINT_SYS_CONSTANT(__NR_process_vm_writev);
  PRINT_SYS_CONSTANT(__NR_kcmp);
  PRINT_SYS_CONSTANT(__NR_finit_module);
  PRINT_SYS_CONSTANT(__NR_sched_setattr);
  PRINT_SYS_CONSTANT(__NR_sched_getattr);
  PRINT_SYS_CONSTANT(__NR_renameat2);
  PRINT_SYS_CONSTANT(__NR_seccomp);
  PRINT_SYS_CONSTANT(__NR_getrandom);
  PRINT_SYS_CONSTANT(__NR_memfd_create);
  PRINT_SYS_CONSTANT(__NR_bpf);
  PRINT_SYS_CONSTANT(__NR_execveat);
  PRINT_SYS_CONSTANT(__NR_userfaultfd);
  PRINT_SYS_CONSTANT(__NR_membarrier);
  PRINT_SYS_CONSTANT(__NR_mlock2);
  PRINT_SYS_CONSTANT(__NR_copy_file_range);
  PRINT_SYS_CONSTANT(__NR_preadv2);
  PRINT_SYS_CONSTANT(__NR_pwritev2);
  PRINT_SYS_CONSTANT(__NR_pkey_mprotect);
  PRINT_SYS_CONSTANT(__NR_pkey_alloc);
  PRINT_SYS_CONSTANT(__NR_pkey_free);
#ifdef __NR_statx
  PRINT_SYS_CONSTANT(__NR_statx);
#endif
  printf("}\n");

  return 0;
}
