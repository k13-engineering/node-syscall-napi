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
}

static napi_status syscall_done(napi_env env, void* opaque, napi_deferred deferred) {
  struct syscall_ctx* ctx = (struct syscall_ctx*) opaque;
  long res = ctx->res;
  unsigned int i;

  for(i = 0; i < sizeof(ctx->arg_refs) / sizeof(ctx->arg_refs[0]); i += 1) {
    if(ctx->arg_refs[i] != NULL) {
      // do not check error here as we could not handle it anyway
      napi_delete_reference(env, ctx->arg_refs[i]);
    }
  }

  free(ctx);

  napi_value result;

  NAPILIB_CHECK(napi_create_bigint_int64(env, res, &result));
  NAPILIB_CHECK(napi_resolve_deferred(env, deferred, result));

  return napi_ok;
}

static napi_status syscall_async_entry(napi_env env, napi_value* args, int arg_count, napi_value* result) {
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

static napi_status syscall_sync_entry(napi_env env, napi_value* args, int arg_count, napi_value* result) {
  int i;
  struct syscall_ctx ctx;
  memset(&ctx, 0, sizeof(ctx));

  if(arg_count < 1) {
    return napi_throw_error(env, NULL, "minimum required argument count for syscall() is 1");
  }

  if(arg_count > 8) {
    return napi_throw_error(env, NULL, "maximum supported argument count for syscall() is 8");
  }

  NAPILIB_CHECK(napilib_require_bigint_int64(env, args[0], &ctx.num));

  for(i = 1; i < arg_count; i += 1) {
    int arg_idx = i - 1;
    bool is_buffer = 0;

    NAPILIB_CHECK(napi_is_buffer(env, args[i], &is_buffer));
    if(is_buffer) {
      void* data;
      size_t length;

      NAPILIB_CHECK(napi_get_buffer_info(env, args[i], &data, &length));
      ctx.native_args[arg_idx] = (long) data;
    } else {
      NAPILIB_CHECK(napilib_require_bigint_int64(env, args[i], &ctx.native_args[arg_idx]));
    }
  }

  ctx.res = syscall(ctx.num,
                    ctx.native_args[0],
                    ctx.native_args[1],
                    ctx.native_args[2],
                    ctx.native_args[3],
                    ctx.native_args[4],
                    ctx.native_args[5],
                    ctx.native_args[6]);

  NAPILIB_CHECK(napi_create_bigint_int64(env, ctx.res, result));  
  
  return napi_ok;
}

static napi_status create_module_instance(napi_env env, napi_value* res) {
  napi_value exports;

  NAPILIB_CHECK(napi_create_object(env, &exports));

  NAPILIB_CHECK(napilib_set_named_simple_function_property(env, exports, "syscall_async", syscall_async_entry));
  NAPILIB_CHECK(napilib_set_named_simple_function_property(env, exports, "syscall_sync", syscall_sync_entry));

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
