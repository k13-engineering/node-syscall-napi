#include <node_api.h>
#include "napilib.h"

#include <unistd.h>
#include <sys/syscall.h>

#include <stdio.h>
#include <errno.h>

struct syscall_ctx {
  long num;
  long native_args[7];
  long res;
  long error_code;
  napi_ref arg_refs[7];
};

static void syscall_work(void* opaque) {
  struct syscall_ctx* ctx = (struct syscall_ctx*) opaque;

  ctx->res = syscall(ctx->num,
                     ctx->native_args[0],
                     ctx->native_args[1],
                     ctx->native_args[2],
                     ctx->native_args[3],
                     ctx->native_args[4],
                     ctx->native_args[5],
                     ctx->native_args[6]);
  if(ctx->res < 0) {
    ctx->error_code = errno;
  } else {
    ctx->error_code = 0;
  }
}

static napi_status syscall_done(napi_env env, void* opaque, napi_deferred deferred) {
  struct syscall_ctx* ctx = (struct syscall_ctx*) opaque;
  long res = ctx->res;
  long error_code = ctx->error_code;
  unsigned int i;

  for(i = 0; i < sizeof(ctx->arg_refs) / sizeof(ctx->arg_refs[0]); i += 1) {
    if(ctx->arg_refs[i] != NULL) {
      // do not check error here as we could not handle it anyway
      napi_delete_reference(env, ctx->arg_refs[i]);
    }
  }

  free(ctx);

  if(res < 0) {
    napi_value error;

    NAPILIB_CHECK(napilib_create_error_by_errno(env, error_code, &error));
    NAPILIB_CHECK(napi_reject_deferred(env, deferred, error));
  } else {
    napi_value result;

    NAPILIB_CHECK(napi_create_bigint_int64(env, res, &result));
    NAPILIB_CHECK(napi_resolve_deferred(env, deferred, result));
  }

  return napi_ok;
}

static napi_status syscall_entry(napi_env env, napi_value* args, int arg_count, napi_value* result) {
  int i;
  struct syscall_ctx* ctx = (struct syscall_ctx*) malloc(sizeof(*ctx));
  memset(ctx, 0, sizeof(*ctx));

  if(arg_count < 1) {
    return napi_throw_error(env, NULL, "minimum required argument count for syscall() is 1");
  }

  if(arg_count > 8) {
    return napi_throw_error(env, NULL, "maximum supported argument count for syscall() is 8");
  }

  NAPILIB_CHECK(napilib_require_bigint_int64(env, args[0], &ctx->num));

  for(i = 1; i < arg_count; i += 1) {
    int arg_idx = i - 1;
    bool is_buffer = 0;

    NAPILIB_CHECK(napi_is_buffer(env, args[i], &is_buffer));
    if(is_buffer) {
      void* data;
      size_t length;

      NAPILIB_CHECK(napi_get_buffer_info(env, args[i], &data, &length));
      ctx->native_args[arg_idx] = (long) data;
      NAPILIB_CHECK(napi_create_reference(env, args[i], 1, &ctx->arg_refs[arg_idx]));
    } else {
      NAPILIB_CHECK(napilib_require_bigint_int64(env, args[i], &ctx->native_args[arg_idx]));
    }
  }

  NAPILIB_CHECK(napilib_execute_async(
    env,
    "syscall",
    syscall_work,
    syscall_done,
    ctx,
    result
  ));

  return napi_ok;
}

#define DEF_SYS_CONSTANT(env, obj, name) NAPILIB_CHECK(napilib_set_named_bigint_int64_property(env, obj, #name, name))

static napi_status add_syscall_constants_to(napi_env env, napi_value target) {
  DEF_SYS_CONSTANT(env, target, __NR_io_setup);
  DEF_SYS_CONSTANT(env, target, __NR_io_destroy);
  DEF_SYS_CONSTANT(env, target, __NR_io_submit);
  DEF_SYS_CONSTANT(env, target, __NR_io_cancel);
  DEF_SYS_CONSTANT(env, target, __NR_io_getevents);
  DEF_SYS_CONSTANT(env, target, __NR_setxattr);
  DEF_SYS_CONSTANT(env, target, __NR_lsetxattr);
  DEF_SYS_CONSTANT(env, target, __NR_fsetxattr);
  DEF_SYS_CONSTANT(env, target, __NR_getxattr);
  DEF_SYS_CONSTANT(env, target, __NR_lgetxattr);
  DEF_SYS_CONSTANT(env, target, __NR_fgetxattr);
  DEF_SYS_CONSTANT(env, target, __NR_listxattr);
  DEF_SYS_CONSTANT(env, target, __NR_llistxattr);
  DEF_SYS_CONSTANT(env, target, __NR_flistxattr);
  DEF_SYS_CONSTANT(env, target, __NR_removexattr);
  DEF_SYS_CONSTANT(env, target, __NR_lremovexattr);
  DEF_SYS_CONSTANT(env, target, __NR_fremovexattr);
  DEF_SYS_CONSTANT(env, target, __NR_getcwd);
  DEF_SYS_CONSTANT(env, target, __NR_lookup_dcookie);
  DEF_SYS_CONSTANT(env, target, __NR_eventfd2);
  DEF_SYS_CONSTANT(env, target, __NR_epoll_create1);
  DEF_SYS_CONSTANT(env, target, __NR_epoll_ctl);
  DEF_SYS_CONSTANT(env, target, __NR_epoll_pwait);
  DEF_SYS_CONSTANT(env, target, __NR_dup);
  DEF_SYS_CONSTANT(env, target, __NR_dup3);
  DEF_SYS_CONSTANT(env, target, __NR_inotify_init1);
  DEF_SYS_CONSTANT(env, target, __NR_inotify_add_watch);
  DEF_SYS_CONSTANT(env, target, __NR_inotify_rm_watch);
  DEF_SYS_CONSTANT(env, target, __NR_ioctl);
  DEF_SYS_CONSTANT(env, target, __NR_ioprio_set);
  DEF_SYS_CONSTANT(env, target, __NR_ioprio_get);
  DEF_SYS_CONSTANT(env, target, __NR_flock);
  DEF_SYS_CONSTANT(env, target, __NR_mknodat);
  DEF_SYS_CONSTANT(env, target, __NR_mkdirat);
  DEF_SYS_CONSTANT(env, target, __NR_unlinkat);
  DEF_SYS_CONSTANT(env, target, __NR_symlinkat);
  DEF_SYS_CONSTANT(env, target, __NR_linkat);
  DEF_SYS_CONSTANT(env, target, __NR_renameat);
  DEF_SYS_CONSTANT(env, target, __NR_umount2);
  DEF_SYS_CONSTANT(env, target, __NR_mount);
  DEF_SYS_CONSTANT(env, target, __NR_pivot_root);
  DEF_SYS_CONSTANT(env, target, __NR_nfsservctl);
  DEF_SYS_CONSTANT(env, target, __NR_fallocate);
  DEF_SYS_CONSTANT(env, target, __NR_faccessat);
  DEF_SYS_CONSTANT(env, target, __NR_chdir);
  DEF_SYS_CONSTANT(env, target, __NR_fchdir);
  DEF_SYS_CONSTANT(env, target, __NR_chroot);
  DEF_SYS_CONSTANT(env, target, __NR_fchmod);
  DEF_SYS_CONSTANT(env, target, __NR_fchmodat);
  DEF_SYS_CONSTANT(env, target, __NR_fchownat);
  DEF_SYS_CONSTANT(env, target, __NR_fchown);
  DEF_SYS_CONSTANT(env, target, __NR_openat);
  DEF_SYS_CONSTANT(env, target, __NR_close);
  DEF_SYS_CONSTANT(env, target, __NR_vhangup);
  DEF_SYS_CONSTANT(env, target, __NR_pipe2);
  DEF_SYS_CONSTANT(env, target, __NR_quotactl);
  DEF_SYS_CONSTANT(env, target, __NR_getdents64);
  DEF_SYS_CONSTANT(env, target, __NR_read);
  DEF_SYS_CONSTANT(env, target, __NR_write);
  DEF_SYS_CONSTANT(env, target, __NR_readv);
  DEF_SYS_CONSTANT(env, target, __NR_writev);
  DEF_SYS_CONSTANT(env, target, __NR_pread64);
  DEF_SYS_CONSTANT(env, target, __NR_pwrite64);
  DEF_SYS_CONSTANT(env, target, __NR_preadv);
  DEF_SYS_CONSTANT(env, target, __NR_pwritev);
  DEF_SYS_CONSTANT(env, target, __NR_pselect6);
  DEF_SYS_CONSTANT(env, target, __NR_ppoll);
  DEF_SYS_CONSTANT(env, target, __NR_signalfd4);
  DEF_SYS_CONSTANT(env, target, __NR_vmsplice);
  DEF_SYS_CONSTANT(env, target, __NR_splice);
  DEF_SYS_CONSTANT(env, target, __NR_tee);
  DEF_SYS_CONSTANT(env, target, __NR_readlinkat);
  DEF_SYS_CONSTANT(env, target, __NR_sync);
  DEF_SYS_CONSTANT(env, target, __NR_fsync);
  DEF_SYS_CONSTANT(env, target, __NR_fdatasync);
  // DEF_SYS_CONSTANT(env, target, __NR_sync_file_range);
  DEF_SYS_CONSTANT(env, target, __NR_timerfd_create);
  DEF_SYS_CONSTANT(env, target, __NR_timerfd_settime);
  DEF_SYS_CONSTANT(env, target, __NR_timerfd_gettime);
  DEF_SYS_CONSTANT(env, target, __NR_utimensat);
  DEF_SYS_CONSTANT(env, target, __NR_acct);
  DEF_SYS_CONSTANT(env, target, __NR_capget);
  DEF_SYS_CONSTANT(env, target, __NR_capset);
  DEF_SYS_CONSTANT(env, target, __NR_personality);
  DEF_SYS_CONSTANT(env, target, __NR_exit);
  DEF_SYS_CONSTANT(env, target, __NR_exit_group);
  DEF_SYS_CONSTANT(env, target, __NR_waitid);
  DEF_SYS_CONSTANT(env, target, __NR_set_tid_address);
  DEF_SYS_CONSTANT(env, target, __NR_unshare);
  DEF_SYS_CONSTANT(env, target, __NR_futex);
  DEF_SYS_CONSTANT(env, target, __NR_set_robust_list);
  DEF_SYS_CONSTANT(env, target, __NR_get_robust_list);
  DEF_SYS_CONSTANT(env, target, __NR_nanosleep);
  DEF_SYS_CONSTANT(env, target, __NR_getitimer);
  DEF_SYS_CONSTANT(env, target, __NR_setitimer);
  DEF_SYS_CONSTANT(env, target, __NR_kexec_load);
  DEF_SYS_CONSTANT(env, target, __NR_init_module);
  DEF_SYS_CONSTANT(env, target, __NR_delete_module);
  DEF_SYS_CONSTANT(env, target, __NR_timer_create);
  DEF_SYS_CONSTANT(env, target, __NR_timer_gettime);
  DEF_SYS_CONSTANT(env, target, __NR_timer_getoverrun);
  DEF_SYS_CONSTANT(env, target, __NR_timer_settime);
  DEF_SYS_CONSTANT(env, target, __NR_timer_delete);
  DEF_SYS_CONSTANT(env, target, __NR_clock_settime);
  DEF_SYS_CONSTANT(env, target, __NR_clock_gettime);
  DEF_SYS_CONSTANT(env, target, __NR_clock_getres);
  DEF_SYS_CONSTANT(env, target, __NR_clock_nanosleep);
  DEF_SYS_CONSTANT(env, target, __NR_syslog);
  DEF_SYS_CONSTANT(env, target, __NR_ptrace);
  DEF_SYS_CONSTANT(env, target, __NR_sched_setparam);
  DEF_SYS_CONSTANT(env, target, __NR_sched_setscheduler);
  DEF_SYS_CONSTANT(env, target, __NR_sched_getscheduler);
  DEF_SYS_CONSTANT(env, target, __NR_sched_getparam);
  DEF_SYS_CONSTANT(env, target, __NR_sched_setaffinity);
  DEF_SYS_CONSTANT(env, target, __NR_sched_getaffinity);
  DEF_SYS_CONSTANT(env, target, __NR_sched_yield);
  DEF_SYS_CONSTANT(env, target, __NR_sched_get_priority_max);
  DEF_SYS_CONSTANT(env, target, __NR_sched_get_priority_min);
  DEF_SYS_CONSTANT(env, target, __NR_sched_rr_get_interval);
  DEF_SYS_CONSTANT(env, target, __NR_restart_syscall);
  DEF_SYS_CONSTANT(env, target, __NR_kill);
  DEF_SYS_CONSTANT(env, target, __NR_tkill);
  DEF_SYS_CONSTANT(env, target, __NR_tgkill);
  DEF_SYS_CONSTANT(env, target, __NR_sigaltstack);
  DEF_SYS_CONSTANT(env, target, __NR_rt_sigsuspend);
  DEF_SYS_CONSTANT(env, target, __NR_rt_sigaction);
  DEF_SYS_CONSTANT(env, target, __NR_rt_sigprocmask);
  DEF_SYS_CONSTANT(env, target, __NR_rt_sigpending);
  DEF_SYS_CONSTANT(env, target, __NR_rt_sigtimedwait);
  DEF_SYS_CONSTANT(env, target, __NR_rt_sigqueueinfo);
  DEF_SYS_CONSTANT(env, target, __NR_rt_sigreturn);
  DEF_SYS_CONSTANT(env, target, __NR_setpriority);
  DEF_SYS_CONSTANT(env, target, __NR_getpriority);
  DEF_SYS_CONSTANT(env, target, __NR_reboot);
  DEF_SYS_CONSTANT(env, target, __NR_setregid);
  DEF_SYS_CONSTANT(env, target, __NR_setgid);
  DEF_SYS_CONSTANT(env, target, __NR_setreuid);
  DEF_SYS_CONSTANT(env, target, __NR_setuid);
  DEF_SYS_CONSTANT(env, target, __NR_setresuid);
  DEF_SYS_CONSTANT(env, target, __NR_getresuid);
  DEF_SYS_CONSTANT(env, target, __NR_setresgid);
  DEF_SYS_CONSTANT(env, target, __NR_getresgid);
  DEF_SYS_CONSTANT(env, target, __NR_setfsuid);
  DEF_SYS_CONSTANT(env, target, __NR_setfsgid);
  DEF_SYS_CONSTANT(env, target, __NR_times);
  DEF_SYS_CONSTANT(env, target, __NR_setpgid);
  DEF_SYS_CONSTANT(env, target, __NR_getpgid);
  DEF_SYS_CONSTANT(env, target, __NR_getsid);
  DEF_SYS_CONSTANT(env, target, __NR_setsid);
  DEF_SYS_CONSTANT(env, target, __NR_getgroups);
  DEF_SYS_CONSTANT(env, target, __NR_setgroups);
  DEF_SYS_CONSTANT(env, target, __NR_uname);
  DEF_SYS_CONSTANT(env, target, __NR_sethostname);
  DEF_SYS_CONSTANT(env, target, __NR_setdomainname);
  // DEF_SYS_CONSTANT(env, target, __NR_getrlimit);
  DEF_SYS_CONSTANT(env, target, __NR_setrlimit);
  DEF_SYS_CONSTANT(env, target, __NR_getrusage);
  DEF_SYS_CONSTANT(env, target, __NR_umask);
  DEF_SYS_CONSTANT(env, target, __NR_prctl);
  DEF_SYS_CONSTANT(env, target, __NR_getcpu);
  DEF_SYS_CONSTANT(env, target, __NR_gettimeofday);
  DEF_SYS_CONSTANT(env, target, __NR_settimeofday);
  DEF_SYS_CONSTANT(env, target, __NR_adjtimex);
  DEF_SYS_CONSTANT(env, target, __NR_getpid);
  DEF_SYS_CONSTANT(env, target, __NR_getppid);
  DEF_SYS_CONSTANT(env, target, __NR_getuid);
  DEF_SYS_CONSTANT(env, target, __NR_geteuid);
  DEF_SYS_CONSTANT(env, target, __NR_getgid);
  DEF_SYS_CONSTANT(env, target, __NR_getegid);
  DEF_SYS_CONSTANT(env, target, __NR_gettid);
  DEF_SYS_CONSTANT(env, target, __NR_sysinfo);
  DEF_SYS_CONSTANT(env, target, __NR_mq_open);
  DEF_SYS_CONSTANT(env, target, __NR_mq_unlink);
  DEF_SYS_CONSTANT(env, target, __NR_mq_timedsend);
  DEF_SYS_CONSTANT(env, target, __NR_mq_timedreceive);
  DEF_SYS_CONSTANT(env, target, __NR_mq_notify);
  DEF_SYS_CONSTANT(env, target, __NR_mq_getsetattr);
  DEF_SYS_CONSTANT(env, target, __NR_msgget);
  DEF_SYS_CONSTANT(env, target, __NR_msgctl);
  DEF_SYS_CONSTANT(env, target, __NR_msgrcv);
  DEF_SYS_CONSTANT(env, target, __NR_msgsnd);
  DEF_SYS_CONSTANT(env, target, __NR_semget);
  DEF_SYS_CONSTANT(env, target, __NR_semctl);
  DEF_SYS_CONSTANT(env, target, __NR_semtimedop);
  DEF_SYS_CONSTANT(env, target, __NR_semop);
  DEF_SYS_CONSTANT(env, target, __NR_shmget);
  DEF_SYS_CONSTANT(env, target, __NR_shmctl);
  DEF_SYS_CONSTANT(env, target, __NR_shmat);
  DEF_SYS_CONSTANT(env, target, __NR_shmdt);
  DEF_SYS_CONSTANT(env, target, __NR_socket);
  DEF_SYS_CONSTANT(env, target, __NR_socketpair);
  DEF_SYS_CONSTANT(env, target, __NR_bind);
  DEF_SYS_CONSTANT(env, target, __NR_listen);
  DEF_SYS_CONSTANT(env, target, __NR_accept);
  DEF_SYS_CONSTANT(env, target, __NR_connect);
  DEF_SYS_CONSTANT(env, target, __NR_getsockname);
  DEF_SYS_CONSTANT(env, target, __NR_getpeername);
  DEF_SYS_CONSTANT(env, target, __NR_sendto);
  DEF_SYS_CONSTANT(env, target, __NR_recvfrom);
  DEF_SYS_CONSTANT(env, target, __NR_setsockopt);
  DEF_SYS_CONSTANT(env, target, __NR_getsockopt);
  DEF_SYS_CONSTANT(env, target, __NR_shutdown);
  DEF_SYS_CONSTANT(env, target, __NR_sendmsg);
  DEF_SYS_CONSTANT(env, target, __NR_recvmsg);
  DEF_SYS_CONSTANT(env, target, __NR_readahead);
  DEF_SYS_CONSTANT(env, target, __NR_brk);
  DEF_SYS_CONSTANT(env, target, __NR_munmap);
  DEF_SYS_CONSTANT(env, target, __NR_mremap);
  DEF_SYS_CONSTANT(env, target, __NR_add_key);
  DEF_SYS_CONSTANT(env, target, __NR_request_key);
  DEF_SYS_CONSTANT(env, target, __NR_keyctl);
  DEF_SYS_CONSTANT(env, target, __NR_clone);
  DEF_SYS_CONSTANT(env, target, __NR_execve);
  DEF_SYS_CONSTANT(env, target, __NR_swapon);
  DEF_SYS_CONSTANT(env, target, __NR_swapoff);
  DEF_SYS_CONSTANT(env, target, __NR_mprotect);
  DEF_SYS_CONSTANT(env, target, __NR_msync);
  DEF_SYS_CONSTANT(env, target, __NR_mlock);
  DEF_SYS_CONSTANT(env, target, __NR_munlock);
  DEF_SYS_CONSTANT(env, target, __NR_mlockall);
  DEF_SYS_CONSTANT(env, target, __NR_munlockall);
  DEF_SYS_CONSTANT(env, target, __NR_mincore);
  DEF_SYS_CONSTANT(env, target, __NR_madvise);
  DEF_SYS_CONSTANT(env, target, __NR_remap_file_pages);
  DEF_SYS_CONSTANT(env, target, __NR_mbind);
  DEF_SYS_CONSTANT(env, target, __NR_get_mempolicy);
  DEF_SYS_CONSTANT(env, target, __NR_set_mempolicy);
  // DEF_SYS_CONSTANT(env, target, __NR_migrate_pages);
  DEF_SYS_CONSTANT(env, target, __NR_move_pages);
  DEF_SYS_CONSTANT(env, target, __NR_rt_tgsigqueueinfo);
  DEF_SYS_CONSTANT(env, target, __NR_perf_event_open);
  DEF_SYS_CONSTANT(env, target, __NR_accept4);
  DEF_SYS_CONSTANT(env, target, __NR_recvmmsg);
  DEF_SYS_CONSTANT(env, target, __NR_wait4);
  DEF_SYS_CONSTANT(env, target, __NR_prlimit64);
  DEF_SYS_CONSTANT(env, target, __NR_fanotify_init);
  DEF_SYS_CONSTANT(env, target, __NR_fanotify_mark);
  DEF_SYS_CONSTANT(env, target, __NR_name_to_handle_at);
  DEF_SYS_CONSTANT(env, target, __NR_open_by_handle_at);
  DEF_SYS_CONSTANT(env, target, __NR_clock_adjtime);
  DEF_SYS_CONSTANT(env, target, __NR_syncfs);
  DEF_SYS_CONSTANT(env, target, __NR_setns);
  DEF_SYS_CONSTANT(env, target, __NR_sendmmsg);
  DEF_SYS_CONSTANT(env, target, __NR_process_vm_readv);
  DEF_SYS_CONSTANT(env, target, __NR_process_vm_writev);
  DEF_SYS_CONSTANT(env, target, __NR_kcmp);
  DEF_SYS_CONSTANT(env, target, __NR_finit_module);
  DEF_SYS_CONSTANT(env, target, __NR_sched_setattr);
  DEF_SYS_CONSTANT(env, target, __NR_sched_getattr);
  DEF_SYS_CONSTANT(env, target, __NR_renameat2);
  DEF_SYS_CONSTANT(env, target, __NR_seccomp);
  DEF_SYS_CONSTANT(env, target, __NR_getrandom);
  DEF_SYS_CONSTANT(env, target, __NR_memfd_create);
  DEF_SYS_CONSTANT(env, target, __NR_bpf);
  DEF_SYS_CONSTANT(env, target, __NR_execveat);
  DEF_SYS_CONSTANT(env, target, __NR_userfaultfd);
  DEF_SYS_CONSTANT(env, target, __NR_membarrier);
  DEF_SYS_CONSTANT(env, target, __NR_mlock2);
  DEF_SYS_CONSTANT(env, target, __NR_copy_file_range);
  DEF_SYS_CONSTANT(env, target, __NR_preadv2);
  DEF_SYS_CONSTANT(env, target, __NR_pwritev2);
  DEF_SYS_CONSTANT(env, target, __NR_pkey_mprotect);
  DEF_SYS_CONSTANT(env, target, __NR_pkey_alloc);
  DEF_SYS_CONSTANT(env, target, __NR_pkey_free);
  DEF_SYS_CONSTANT(env, target, __NR_statx);

  return napi_ok;
}

static napi_status create_module_instance(napi_env env, napi_value* res) {
  napi_value exports;

  NAPILIB_CHECK(napi_create_object(env, &exports));

  NAPILIB_CHECK(add_syscall_constants_to(env, exports));
  NAPILIB_CHECK(napilib_set_named_simple_function_property(env, exports, "syscall", syscall_entry));

  *res = exports;

  return napi_ok;
}

napi_value init(napi_env env, napi_value exports) {
  napi_status status;
  napi_value module_exports;

  status = create_module_instance(env, &module_exports);
  if(status != napi_ok) {
    return NULL;
  }

  return module_exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
