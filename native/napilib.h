#pragma once

#include <node_api.h>

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

static napi_status napilib_throw_error_by_status(napi_env env, napi_status status) {
  napi_status st;
  st = napi_throw_error(env, "", "errorneous napi_status");
  if(st != napi_ok) {
    return st;
  }
  return napi_pending_exception;
}

static napi_status napilib_maybe_throw_by_status(napi_env env, napi_status status) {
  if(status == napi_ok) {
    return status;
  } else if(status == napi_pending_exception) {
    return status;
  }

  return napilib_throw_error_by_status(env, status);
}

#define NAPILIB_CHECK(x) do { napi_status ret = x; if(ret != napi_ok) { return napilib_maybe_throw_by_status(env, ret); } } while(0)
#define NAPILIB_CHECK_GOTO_FAIL(x) if((x) != napi_ok) { goto fail; }

static napi_status napilib_throw_error_by_errno(napi_env env, int err) {
  NAPILIB_CHECK(napi_throw_error(env, "", strerror(err)));
  return napi_pending_exception;
}

typedef void (*napilib_work_t)(void* opaque);
typedef napi_status (*napilib_work_done_t)(napi_env env, void* opaque, napi_deferred deferred);

struct napilib_async_work_context {
  napilib_work_t work;
  napilib_work_done_t work_done;

  napi_deferred deferred;
  napi_async_work async_work;
  void* opaque;
};

typedef void (*napilib_free_t)(void* mem);

static void _napilib_async_work_wrapper(napi_env env, void* ctx_opaque) {
  struct napilib_async_work_context* ctx = (struct napilib_async_work_context*) ctx_opaque;

  ctx->work(ctx->opaque);
}

static void _napilib_async_work_done_wrapper(napi_env env, napi_status status, void* ctx_opaque) {
  struct napilib_async_work_context* ctx = (struct napilib_async_work_context*) ctx_opaque;

  status = ctx->work_done(env, ctx->opaque, ctx->deferred);
  if(status != napi_ok) {
    // TODO: fail deferred
  }

  napi_delete_async_work(env, ctx->async_work);
  free(ctx_opaque);
}

static napi_status napilib_execute_async(napi_env env,
                                         const char* work_name,
                                         napilib_work_t work,
                                         napilib_work_done_t work_done,
                                         void* opaque,
                                         napi_value* promise) {
  struct napilib_async_work_context* ctx = (struct napilib_async_work_context*) malloc(sizeof(*ctx));
  napi_value resource_name;

  ctx->opaque = opaque;
  ctx->work = work;
  ctx->work_done = work_done;

  NAPILIB_CHECK_GOTO_FAIL(napi_create_promise(env, &ctx->deferred, promise));
  NAPILIB_CHECK_GOTO_FAIL(napi_create_string_utf8(env, work_name, -1, &resource_name));

  NAPILIB_CHECK_GOTO_FAIL(napi_create_async_work(env, NULL, resource_name, _napilib_async_work_wrapper, _napilib_async_work_done_wrapper, ctx, &ctx->async_work));
  NAPILIB_CHECK_GOTO_FAIL(napi_queue_async_work(env, ctx->async_work));

  return napi_ok;

fail:
  free(ctx);
  return napi_generic_failure;
}

typedef napi_status (*napilib_simple_callback)(napi_env env, napi_value* args, int arg_count, napi_value* result);

static napi_status _napilib_simple_callback_wrapper2(napi_env env, napi_callback_info info, napi_value* result) {
  // TOOD: dynamic sizes
  int max_args = 32;
  napi_value* argv;
  size_t argc = max_args;
  napi_value this_arg;
  void* opaque;
  napilib_simple_callback simple_cb;
  napi_status status;

  argv = malloc(sizeof(napi_value) * max_args);
  if(argv == NULL) {
    return napilib_throw_error_by_errno(env, errno);
  }

  NAPILIB_CHECK_GOTO_FAIL(napi_get_cb_info(env, info, &argc, argv, &this_arg, &opaque));
  NAPILIB_CHECK_GOTO_FAIL(napi_get_undefined(env, result));

  simple_cb = (napilib_simple_callback) opaque;
  status = simple_cb(env, argv, argc, result);
  free(argv);

  return status;

fail:
  free(argv);
  return napi_generic_failure;
}

static napi_value _napilib_simple_callback_wrapper(napi_env env, napi_callback_info info) {
  napi_status status;
  napi_value result;

  status = _napilib_simple_callback_wrapper2(env, info, &result);
  if(status != napi_ok) {
    napi_value undefined;
    napi_get_undefined(env, &undefined);
    return undefined;
  }

  return result;
}

static napi_status napilib_create_simple_function(napi_env env, napilib_simple_callback simple_cb, napi_value* result) {
  NAPILIB_CHECK(napi_create_function(env, NULL, 0, _napilib_simple_callback_wrapper, simple_cb, result));
  return napi_ok;
}

static napi_status napilib_set_named_simple_function_property(napi_env env, napi_value obj, const char* property_name, napilib_simple_callback simple_cb) {
  napi_value func;

  NAPILIB_CHECK(napilib_create_simple_function(env, simple_cb, &func));
  NAPILIB_CHECK(napi_set_named_property(env, obj, property_name, func));

  return napi_ok;
}

static napi_status napilib_require_bigint_int64(napi_env env, napi_value value, int64_t* result) {
  napi_status status;
  bool lossless = 0;

  status = napi_get_value_bigint_int64(env, value, result, &lossless);
  if(status == napi_bigint_expected) {
    return napi_throw_type_error(env, "", "bigint required");
  } else if(status != napi_ok) {
    return napilib_throw_error_by_status(env, status);
  }

  if(!lossless) {
    return napi_throw_error(env, "", "bigint value does not fit into int64_t");
  }

  return napi_ok;
}
