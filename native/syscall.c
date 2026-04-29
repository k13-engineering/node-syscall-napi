#include <node_api.h>

#if defined(__x86_64__) || defined(_M_X64)
#define ARCH_X86_64 1
#elif defined(__aarch64__) || defined(_M_ARM64)
#define ARCH_AARCH64 1
#else
#error "Unsupported architecture: only x86_64 and aarch64 are supported"
#endif

#define NAPI_CHECK(expr) do { \
  napi_status _s = (expr); \
  if (_s != napi_ok) { \
    return _s; \
  } \
} while(0)

static long raw_syscall(long num, long a0, long a1, long a2, long a3, long a4, long a5) {
#if ARCH_X86_64
  long ret;
  register long r10 __asm__("r10") = a3;
  register long r8  __asm__("r8")  = a4;
  register long r9  __asm__("r9")  = a5;
  __asm__ volatile (
    "syscall"
    : "=a"(ret)
    : "a"(num), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9)
    : "rcx", "r11", "memory"
  );
  return ret;
#elif ARCH_AARCH64
  register long x8 __asm__("x8") = num;
  register long x0 __asm__("x0") = a0;
  register long x1 __asm__("x1") = a1;
  register long x2 __asm__("x2") = a2;
  register long x3 __asm__("x3") = a3;
  register long x4 __asm__("x4") = a4;
  register long x5 __asm__("x5") = a5;
  __asm__ volatile (
    "svc #0"
    : "=r"(x0)
    : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
    : "memory"
  );
  return x0;
#endif
}

static napi_status require_bigint_int64(napi_env env, napi_value value, long *result) {
  int64_t tmp;
  bool lossless = 0;
  napi_status status;

  status = napi_get_value_bigint_int64(env, value, &tmp, &lossless);
  if (status == napi_bigint_expected) {
    napi_throw_type_error(env, NULL, "bigint required");
    return napi_pending_exception;
  }
  NAPI_CHECK(status);

  if (!lossless) {
    napi_throw_error(env, NULL, "bigint value does not fit into int64_t");
    return napi_pending_exception;
  }

  *result = (long)tmp;
  return napi_ok;
}

static napi_value syscall_sync_fn(napi_env env, napi_callback_info info) {
  napi_value argv[8];
  size_t argc = 8;
  napi_value this_arg;
  napi_value result;
  napi_value js_errno;
  napi_value js_ret;
  napi_value undefined;
  long num;
  long native_args[7] = {0, 0, 0, 0, 0, 0, 0};
  long res;
  int i;

  napi_get_undefined(env, &undefined);

  if (napi_get_cb_info(env, info, &argc, argv, &this_arg, NULL) != napi_ok) {
    return undefined;
  }

  if (argc < 1) {
    napi_throw_error(env, NULL, "minimum required argument count for syscall() is 1");
    return undefined;
  }

  if (argc > 8) {
    napi_throw_error(env, NULL, "maximum supported argument count for syscall() is 8");
    return undefined;
  }

  if (require_bigint_int64(env, argv[0], &num) != napi_ok) {
    return undefined;
  }

  for (i = 1; i < (int)argc; i += 1) {
    int arg_idx = i - 1;
    bool is_buffer = 0;

    if (napi_is_buffer(env, argv[i], &is_buffer) != napi_ok) {
      return undefined;
    }

    if (is_buffer) {
      void *data;
      size_t length;

      if (napi_get_buffer_info(env, argv[i], &data, &length) != napi_ok) {
        return undefined;
      }

      native_args[arg_idx] = (long)data;
    } else {
      if (require_bigint_int64(env, argv[i], &native_args[arg_idx]) != napi_ok) {
        return undefined;
      }
    }
  }

  res = raw_syscall(num,
                    native_args[0],
                    native_args[1],
                    native_args[2],
                    native_args[3],
                    native_args[4],
                    native_args[5]);

  if (napi_create_object(env, &result) != napi_ok) {
    return undefined;
  }

  if (res < 0 && res >= -4095) {
    if (napi_create_int32(env, (int32_t)(-res), &js_errno) != napi_ok) {
      return undefined;
    }
    if (napi_set_named_property(env, result, "errno", js_errno) != napi_ok) {
      return undefined;
    }
  } else {
    if (napi_create_int32(env, 0, &js_errno) != napi_ok) {
      return undefined;
    }
    if (napi_set_named_property(env, result, "errno", js_errno) != napi_ok) {
      return undefined;
    }

    if (napi_create_bigint_int64(env, (int64_t)res, &js_ret) != napi_ok) {
      return undefined;
    }
    if (napi_set_named_property(env, result, "ret", js_ret) != napi_ok) {
      return undefined;
    }
  }

  return result;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_value module;
  napi_value fn;

  if (napi_create_object(env, &module) != napi_ok) {
    return NULL;
  }

  if (napi_create_function(env, NULL, 0, syscall_sync_fn, NULL, &fn) != napi_ok) {
    return NULL;
  }

  if (napi_set_named_property(env, module, "syscall_sync", fn) != napi_ok) {
    return NULL;
  }

  return module;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
